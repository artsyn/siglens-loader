#!/usr/bin/env python3
"""
Отправка CSV-лога в SigLens.

Каждая строка CSV становится плоским событием: поля лежат в корне,
время события берётся из колонки TimeStamp, числовые колонки уходят числами.
После отправки скрипт сверяет количество событий в SigLens с количеством строк.

Использование:
  python3 send_to_siglens.py mail_log.csv
  python3 send_to_siglens.py mail_log.csv --index mail_logs_v2 --utc
  python3 send_to_siglens.py other.csv --index other --time-column ts \
      --time-format "%d.%m.%Y %H:%M:%S" --int-columns status,bytes
"""
import argparse
import csv
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DEFAULT_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
DEFAULT_INT_COLUMNS = "Status,ClientPort,FrontendPort"
# SigLens берёт время события из поля timestamp (мс), а индекс из поля index
RESERVED = ("timestamp", "index")


def to_epoch_ms(text, time_format, utc):
    dt = datetime.strptime(text.strip(), time_format)
    if utc:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def build_event(row, index, time_column, time_format, int_columns, utc):
    event = {k: v for k, v in row.items() if v not in (None, "") and k not in RESERVED}
    for column in int_columns:
        try:
            event[column] = int(event[column])
        except (KeyError, ValueError):
            pass
    event["timestamp"] = to_epoch_ms(row[time_column], time_format, utc)
    event["index"] = index
    return event


def post_json(url, body, timeout=60):
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def send_batch(ingest_url, events, retries=3):
    # Несколько событий в одном запросе разделяются переводом строки
    body = "\n".join(json.dumps(e, ensure_ascii=False) for e in events).encode("utf-8")
    error = None
    for attempt in range(retries):
        try:
            answer = post_json(ingest_url + "/services/collector/event", body)
            if answer.get("status") == "Success":
                return
            error = answer
        except urllib.error.HTTPError as e:
            error = f"HTTP {e.code}: {e.read()[:300]!r}"
        except (urllib.error.URLError, OSError, ValueError) as e:
            error = f"{type(e).__name__}: {e}"
        time.sleep(1 + attempt)
    sys.exit(f"[!] SigLens не принял пачку: {error}")


def count_events(query_url, index, start_ms, end_ms):
    """Сколько событий лежит в индексе за интервал. None, если спросить не удалось."""
    query = {"searchText": "* | stats count", "indexName": index, "queryLanguage": "Splunk QL",
             "startEpoch": start_ms, "endEpoch": end_ms}
    try:
        answer = post_json(query_url + "/api/search", json.dumps(query).encode("utf-8"))
        return int(answer["measure"][0]["MeasureVal"]["count(*)"])
    except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError, TypeError):
        return None


def main():
    parser = argparse.ArgumentParser(description="Отправка CSV в SigLens плоскими событиями")
    parser.add_argument("csv_path")
    parser.add_argument("--index", default="mail_logs")
    parser.add_argument("--ingest-url", default="http://localhost:8081")
    parser.add_argument("--query-url", default="http://localhost:5122")
    parser.add_argument("--time-column", default="TimeStamp")
    parser.add_argument("--time-format", default=DEFAULT_TIME_FORMAT,
                        help="формат времени в CSV, как в datetime.strptime")
    parser.add_argument("--int-columns", default=DEFAULT_INT_COLUMNS,
                        help="колонки через запятую, которые отправлять числами")
    parser.add_argument("--utc", action="store_true",
                        help="считать время в логе как UTC (по умолчанию как местное время этой машины)")
    parser.add_argument("--batch", type=int, default=500)
    parser.add_argument("--force", action="store_true", help="отправлять, даже если в индексе уже есть события")
    args = parser.parse_args()

    with open(args.csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        sys.exit("[!] В CSV нет строк")
    if args.time_column not in rows[0]:
        sys.exit(f"[!] В CSV нет колонки {args.time_column}")

    int_columns = [c.strip() for c in args.int_columns.split(",") if c.strip()]
    events = []
    for number, row in enumerate(rows, start=2):
        try:
            events.append(build_event(row, args.index, args.time_column, args.time_format,
                                      int_columns, args.utc))
        except ValueError:
            sys.exit(f"[!] Строка {number}: не разобрал время {row[args.time_column]!r}")

    total = len(events)
    first = min(events, key=lambda e: e["timestamp"])
    last = max(events, key=lambda e: e["timestamp"])
    start_ms = first["timestamp"]
    end_ms = last["timestamp"] + 1000
    print(f"[+] Строк: {total}")
    print(f"    Время событий: {first[args.time_column]} .. {last[args.time_column]}")

    existing = count_events(args.query_url, args.index, start_ms, end_ms)
    if existing and not args.force:
        sys.exit(f"[!] В индексе {args.index} уже есть {existing} событий за этот период.\n"
                 f"    Чтобы не задвоить данные, укажи другой --index или сделай ./siglens_up.sh reset")

    started = time.time()
    for i in range(0, total, args.batch):
        send_batch(args.ingest_url, events[i:i + args.batch])
        done = min(i + args.batch, total)
        if done % 5000 < args.batch or done == total:
            print(f"    {done}/{total}")
    print(f"[+] Отправлено за {time.time() - started:.1f} сек, жду пока SigLens всё проиндексирует")

    expected = total + (existing or 0)
    stored = None
    for _ in range(40):
        stored = count_events(args.query_url, args.index, start_ms, end_ms)
        if stored == expected:
            break
        time.sleep(3)

    if stored == expected:
        print(f"[+] В индексе {args.index} событий: {stored}, сходится")
    else:
        print(f"[!] В индексе {args.index} событий: {stored}, ожидалось {expected}")
        sys.exit(1)
    print(f"    UI: {args.query_url}, индекс {args.index}, диапазон времени выбрать вручную")


if __name__ == "__main__":
    main()
