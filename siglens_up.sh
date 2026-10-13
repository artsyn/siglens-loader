#!/usr/bin/env bash
# Поднимает SigLens в Docker.
#   ./siglens_up.sh          запустить (данные сохраняются между запусками)
#   ./siglens_up.sh reset    удалить контейнер и все данные, запустить с нуля
#   ./siglens_up.sh down     остановить и удалить контейнер, данные оставить
set -euo pipefail

IMAGE="${SIGLENS_IMAGE:-siglens/siglens:1.0.57}"
NAME="${SIGLENS_NAME:-siglens}"
VOLUME="${SIGLENS_VOLUME:-siglens-data}"
# По умолчанию порты открыты только на этой машине: в SigLens нет авторизации,
# а в логе лежат пароли.
BIND="${SIGLENS_BIND:-127.0.0.1}"
INGEST_PORT="${SIGLENS_INGEST_PORT:-8081}"
UI_PORT="${SIGLENS_UI_PORT:-5122}"
# Конфиг лежит рядом со скриптом
CONFIG="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/server.yaml"

if [ ! -f "$CONFIG" ]; then
    echo "[!] Не найден $CONFIG" >&2
    exit 1
fi

# docker может требовать sudo
if docker info >/dev/null 2>&1; then
    DOCKER=(docker)
else
    DOCKER=(sudo docker)
fi

remove_container() {
    "${DOCKER[@]}" rm -f "$NAME" >/dev/null 2>&1 || true
}

case "${1:-up}" in
    down)
        remove_container
        echo "[+] Контейнер $NAME удалён, данные в томе $VOLUME сохранены"
        exit 0
        ;;
    reset)
        remove_container
        "${DOCKER[@]}" volume rm "$VOLUME" >/dev/null 2>&1 || true
        echo "[+] Старые данные удалены"
        ;;
    up) ;;
    *)
        echo "Использование: $0 [up|reset|down]" >&2
        exit 1
        ;;
esac

if "${DOCKER[@]}" ps --format '{{.Names}}' | grep -qx "$NAME"; then
    echo "[=] $NAME уже запущен"
else
    remove_container
    # SigLens в контейнере работает под uid 1000, а новый том принадлежит root
    "${DOCKER[@]}" run --rm --user 0 --entrypoint chown \
        -v "$VOLUME:/siglens/data" "$IMAGE" 1000:1000 /siglens/data
    "${DOCKER[@]}" run -d --name "$NAME" \
        -p "$BIND:$INGEST_PORT:8081" \
        -p "$BIND:$UI_PORT:5122" \
        -v "$VOLUME:/siglens/data" \
        -v "$CONFIG:/siglens/server.yaml:ro" \
        "$IMAGE" >/dev/null
fi

echo -n "[+] Жду запуска"
for _ in $(seq 1 60); do
    if curl -fs -m 2 "http://127.0.0.1:$INGEST_PORT/api/health" >/dev/null 2>&1; then
        echo
        echo "[+] SigLens работает"
        echo "    UI:    http://localhost:$UI_PORT"
        echo "    Приём: http://localhost:$INGEST_PORT"
        exit 0
    fi
    echo -n "."
    sleep 1
done
echo
echo "[!] SigLens не ответил за 60 секунд, смотри: ${DOCKER[*]} logs $NAME" >&2
exit 1
