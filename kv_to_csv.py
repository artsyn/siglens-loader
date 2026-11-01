#!/usr/bin/env python3
"""
Парсер лога key=value через табуляцию -> CSV.

Сделан под выгрузку из SIEM, где вперемешку лежат два источника:
  DNS-сервер Windows: syslog-заголовок, дальше AgentDevice=WindowsDNS ...
  Cisco FirePower (eStreamer): DeviceType=Estreamer ... flowStatistics.* ...

Исходные поля сохраняются, имена приводятся к виду без пробелов и точек:
"Question Name" -> QuestionName, flowStatistics.responderPort -> ResponderPort.
Для поиска по обоим источникам сразу добавляются общие колонки:
  EventTime  время события в UTC
  SourceType dns / firepower
  SrcIp, SrcPort, DstIp, DstPort, Protocol, Domain

Время в UTC, поэтому отправлять в SigLens с ключом --utc.

Использование:
  python3 kv_to_csv.py logs.txt
  python3 kv_to_csv.py logs.txt -o out/caldera.csv --tz +05:00
"""
import argparse
import csv
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

TIME_FMT = "%Y-%m-%d %H:%M:%S"
COMMON = ["EventTime", "SourceType", "SrcIp", "SrcPort", "DstIp", "DstPort", "Protocol", "Domain"]
SYSLOG = ["SyslogPri", "SyslogTime", "SyslogHost"]
SYSLOG_HEADER = re.compile(r"^<(\d+)>(\w{3} [ \d]\d \d\d:\d\d:\d\d) (\S+) (.*)$")
PROTOCOLS = {"6": "TCP", "17": "UDP", "1": "ICMP"}
# Эти имена SigLens забирает себе, в событие они бы не попали
RESERVED = ("timestamp", "index")


def column_name(key):
    """'Question Name' -> QuestionName, flowStatistics.bytesSent -> BytesSent."""
    key = key.removeprefix("flowStatistics.")
    name = "".join(p[0].upper() + p[1:] for p in re.split(r"[^0-9A-Za-z]+", key) if p)
    # Служебные имена SigLens и совпадения с общими колонками: исходное поле с префиксом Orig
    if name.lower() in RESERVED or name in COMMON:
        name = "Orig" + name
    return name


def parse_line(line):
    """Строка лога -> словарь {колонка: значение}. Пустая строка -> None."""
    line = line.strip()
    if not line:
        return None
    fields = {}
    match = SYSLOG_HEADER.match(line)
    if match:
        fields.update(zip(SYSLOG, match.groups()[:3]))
        line = match.group(4)
    for token in line.split("\t"):
        key, sep, value = token.partition("=")
        if sep and key.strip():
            fields[column_name(key.strip())] = value.strip()
    return fields


def to_utc(text, time_format, tz):
    dt = datetime.strptime(text, time_format).replace(tzinfo=tz)
    return dt.astimezone(timezone.utc).strftime(TIME_FMT)


def add_dns(f, tz):
    f["SourceType"] = "dns"
    # Время на DNS-сервере, местное
    f["EventTime"] = to_utc(f"{f['Date']} {f['Time']}", "%d.%m.%Y %H:%M:%S", tz)
    # Remote IP это всегда вторая сторона: клиент для Rcv, адресат для Snd
    side = "SrcIp" if f.get("SendReceiveIndicator") == "Rcv" else "DstIp"
    f[side] = f.get("RemoteIP", "")
    f["Protocol"] = f.get("UDPTCPIndicator", "")
    # В сыром dns_debug.log имена пишутся как (3)www(4)bing(3)com(0)
    name = re.sub(r"\(\d+\)", ".", f.get("QuestionName", "")).strip(".")
    f["Domain"] = name.lower()


def add_firepower(f, tz):
    f["SourceType"] = "firepower"
    # Начало соединения, unix-время. Если его нет, время записи (местное)
    first = f.get("FirstPacketTimestamp", "0")
    if first not in ("", "0"):
        dt = datetime.fromtimestamp(int(first), timezone.utc)
        f["EventTime"] = dt.strftime(TIME_FMT)
    else:
        f["EventTime"] = to_utc(f["OrigTimestamp"], "%d %b %Y %H:%M:%S", tz)
    f["SrcIp"] = f.get("InitiatorIPAddress", "")
    f["SrcPort"] = f.get("InitiatorPort", "")
    f["DstIp"] = f.get("ResponderIPAddress", "")
    f["DstPort"] = f.get("ResponderPort", "")
    f["Protocol"] = PROTOCOLS.get(f.get("OrigProtocol", ""), f.get("OrigProtocol", ""))
    url = f.get("ClientAppURL", "")
    f["Domain"] = (urlsplit(url).hostname or "") if url else ""


def tz_drift(f, tz):
    """На сколько секунд местное время записи FirePower расходится с CurrentTime при этом поясе."""
    try:
        local = datetime.strptime(f["OrigTimestamp"], "%d %b %Y %H:%M:%S").replace(tzinfo=tz)
        return abs(local.timestamp() - int(f["CurrentTime"]) / 1000)
    except (KeyError, ValueError):
        return None


def main():
    parser = argparse.ArgumentParser(description="Лог key=value (DNS Windows, FirePower) -> CSV")
    parser.add_argument("log", type=Path)
    parser.add_argument("-o", "--out", type=Path, help="куда писать CSV (по умолчанию рядом с логом)")
    parser.add_argument("--tz", default="+03:00",
                        help="часовой пояс, в котором записано местное время в логе (по умолчанию +03:00)")
    args = parser.parse_args()

    if not args.log.exists():
        sys.exit(f"[!] Файл не найден: {args.log}")
    try:
        tz = datetime.strptime(args.tz, "%z").tzinfo
    except ValueError:
        sys.exit(f"[!] Не понял пояс {args.tz!r}, нужно вида +03:00")

    out_path = args.out or args.log.with_suffix(".csv")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Первый проход: собрать все колонки, у DNS и FirePower они разные
    columns = dict.fromkeys(COMMON + SYSLOG)
    with open(args.log, encoding="utf-8", errors="replace") as f:
        for line in f:
            fields = parse_line(line)
            if fields:
                columns.update(dict.fromkeys(fields))

    counts = {}
    drift_warned = False
    with open(args.log, encoding="utf-8", errors="replace") as src, \
            open(out_path, "w", newline="", encoding="utf-8") as dst:
        writer = csv.DictWriter(dst, fieldnames=list(columns))
        writer.writeheader()
        for number, line in enumerate(src, start=1):
            fields = parse_line(line)
            if not fields:
                continue
            try:
                if fields.get("AgentDevice") == "WindowsDNS":
                    add_dns(fields, tz)
                elif fields.get("DeviceType") == "Estreamer":
                    add_firepower(fields, tz)
                    drift = tz_drift(fields, tz)
                    if drift is not None and drift > 300 and not drift_warned:
                        print(f"[!] Строка {number}: время FirePower с поясом {args.tz} расходится "
                              f"с CurrentTime на {drift / 3600:.1f} ч, проверь --tz")
                        drift_warned = True
                else:
                    sys.exit(f"[!] Строка {number}: неизвестный источник, нет AgentDevice=WindowsDNS "
                             f"или DeviceType=Estreamer")
            except (KeyError, ValueError) as e:
                sys.exit(f"[!] Строка {number}: не разобрал время ({type(e).__name__}: {e})")
            writer.writerow(fields)
            counts[fields["SourceType"]] = counts.get(fields["SourceType"], 0) + 1

    total = sum(counts.values())
    by_source = ", ".join(f"{k} {v}" for k, v in counts.items())
    print(f"[+] {args.log.name}: {total} строк ({by_source}) -> {out_path}")
    print(f"    Отправка: python3 send_to_siglens.py {out_path} --index <индекс> "
          f"--time-column EventTime --utc --int-columns SrcPort,DstPort,BytesSent,BytesReceived,"
          f"PacketsSent,PacketsReceived")


if __name__ == "__main__":
    main()
