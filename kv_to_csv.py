#!/usr/bin/env python3
"""
Парсер лога key=value через табуляцию -> CSV.

Сделан под выгрузку из SIEM, где вперемешку лежат два источника:
  DNS-сервер Windows: syslog-заголовок, дальше AgentDevice=WindowsDNS ...
  Cisco FirePower (eStreamer): DeviceType=Estreamer ... flowStatistics.* ...

По умолчанию в CSV попадают только полезные поля под общими именами,
чтобы DNS и соединения искались одним запросом (см. COLUMNS).
С ключом --all-fields к ним добавляются все исходные поля.

EventTime пишется как в логе, с поясом: 2021-09-07 11:23:53+0300.

Использование:
  python3 kv_to_csv.py logs.txt
  python3 kv_to_csv.py logs.txt -o out/caldera.csv --tz +05:00 --all-fields
"""
import argparse
import csv
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

TIME_FMT = "%Y-%m-%d %H:%M:%S%z"
COLUMNS = [
    # общие
    "EventTime", "SourceType", "Device", "SrcIp", "SrcPort", "DstIp", "DstPort", "Protocol", "Domain",
    # DNS
    "DnsQueryType", "DnsResponseCode", "DnsMessage", "DnsId",
    # FirePower
    "RuleAction", "RuleReason", "PacketsSent", "PacketsReceived", "BytesSent", "BytesReceived",
    "Url", "SecurityIntelligence",
]
INT_COLUMNS = "SrcPort,DstPort,PacketsSent,PacketsReceived,BytesSent,BytesReceived"
SYSLOG = ["SyslogPri", "SyslogTime", "SyslogHost"]
SYSLOG_HEADER = re.compile(r"^<(\d+)>(\w{3} [ \d]\d \d\d:\d\d:\d\d) (\S+) (.*)$")
PROTOCOLS = {"6": "TCP", "17": "UDP", "1": "ICMP"}
FP = "flowStatistics."
# Эти имена SigLens забирает себе, в событие они бы не попали
RESERVED = ("timestamp", "index")


def parse_line(line):
    """Строка лога -> словарь исходных полей. Пустая строка -> None."""
    line = line.strip()
    if not line:
        return None
    raw = {}
    match = SYSLOG_HEADER.match(line)
    if match:
        raw.update(zip(SYSLOG, match.groups()[:3]))
        line = match.group(4)
    for token in line.split("\t"):
        key, sep, value = token.partition("=")
        if sep and key.strip():
            raw[key.strip()] = value.strip()
    return raw


def from_dns(raw, tz):
    # Время на самом DNS-сервере, местное. Syslog-заголовок пишется при пересылке
    dt = datetime.strptime(f"{raw['Date']} {raw['Time']}", "%d.%m.%Y %H:%M:%S").replace(tzinfo=tz)
    # В сыром dns_debug.log имена пишутся как (3)www(4)bing(3)com(0)
    name = re.sub(r"\(\d+\)", ".", raw.get("Question Name", "")).strip(".").lower()
    qr = raw.get("Query/Response", "")
    row = {
        "EventTime": dt.strftime(TIME_FMT),
        "SourceType": "dns",
        "Device": raw.get("SyslogHost", ""),
        "Protocol": raw.get("UDP/TCP indicator", ""),
        "Domain": name,
        "DnsQueryType": raw.get("Question Type", ""),
        "DnsResponseCode": raw.get("ResponseCode", ""),
        "DnsMessage": {"Q": "query", "R": "response"}.get(qr, qr),
        "DnsId": raw.get("Xid (hex)", ""),
    }
    # Remote IP это всегда вторая сторона: клиент для Rcv, адресат для Snd
    side = "SrcIp" if raw.get("Send/Receive indicator") == "Rcv" else "DstIp"
    row[side] = raw.get("Remote IP", "")
    return row


def from_firepower(raw, tz):
    # Начало соединения, unix-время. Если его нет, время записи (местное)
    first = raw.get(FP + "firstPacketTimestamp", "0")
    if first not in ("", "0"):
        dt = datetime.fromtimestamp(int(first), tz)
    else:
        dt = datetime.strptime(raw["timestamp"], "%d %b %Y %H:%M:%S").replace(tzinfo=tz)
    url = raw.get(FP + "clientAppURL", "")
    proto = raw.get(FP + "protocol", "")
    lists = [v for k, v in raw.items()
             if k.startswith(FP + "securityIntelligenceList") and k.endswith(".securityIntelligenceListName")]
    return {
        "EventTime": dt.strftime(TIME_FMT),
        "SourceType": "firepower",
        "Device": raw.get("DeviceAddress", ""),
        "SrcIp": raw.get(FP + "initiatorIPAddress", ""),
        "SrcPort": raw.get(FP + "initiatorPort", ""),
        "DstIp": raw.get(FP + "responderIPAddress", ""),
        "DstPort": raw.get(FP + "responderPort", ""),
        "Protocol": PROTOCOLS.get(proto, proto),
        "Domain": (urlsplit(url).hostname or "") if url else "",
        "RuleAction": raw.get(FP + "ruleAction", ""),
        "RuleReason": raw.get(FP + "ruleReason", ""),
        "PacketsSent": raw.get(FP + "packetsSent", ""),
        "PacketsReceived": raw.get(FP + "packetsReceived", ""),
        "BytesSent": raw.get(FP + "bytesSent", ""),
        "BytesReceived": raw.get(FP + "bytesReceived", ""),
        "Url": url,
        "SecurityIntelligence": ",".join(lists),
    }


def column_name(key):
    """Имя исходного поля для --all-fields: 'Question Name' -> QuestionName, flowStatistics.bytesSent -> OrigBytesSent."""
    key = key.removeprefix(FP)
    name = "".join(p[0].upper() + p[1:] for p in re.split(r"[^0-9A-Za-z]+", key) if p)
    if name.lower() in RESERVED or name in COLUMNS:
        name = "Orig" + name
    return name


def tz_drift(raw, tz):
    """На сколько секунд местное время записи FirePower расходится с CurrentTime при этом поясе."""
    try:
        local = datetime.strptime(raw["timestamp"], "%d %b %Y %H:%M:%S").replace(tzinfo=tz)
        return abs(local.timestamp() - int(raw["CurrentTime"]) / 1000)
    except (KeyError, ValueError):
        return None


def main():
    parser = argparse.ArgumentParser(description="Лог key=value (DNS Windows, FirePower) -> CSV")
    parser.add_argument("log", type=Path)
    parser.add_argument("-o", "--out", type=Path, help="куда писать CSV (по умолчанию рядом с логом)")
    parser.add_argument("--tz", default="+03:00",
                        help="часовой пояс, в котором записано местное время в логе (по умолчанию +03:00)")
    parser.add_argument("--all-fields", action="store_true", help="добавить в CSV все исходные поля")
    args = parser.parse_args()

    if not args.log.exists():
        sys.exit(f"[!] Файл не найден: {args.log}")
    try:
        tz = datetime.strptime(args.tz, "%z").tzinfo
    except ValueError:
        sys.exit(f"[!] Не понял пояс {args.tz!r}, нужно вида +03:00")

    out_path = args.out or args.log.with_suffix(".csv")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    columns = dict.fromkeys(COLUMNS)
    if args.all_fields:
        # Первый проход: собрать имена исходных полей, у DNS и FirePower они разные
        with open(args.log, encoding="utf-8", errors="replace") as f:
            for line in f:
                raw = parse_line(line)
                if raw:
                    columns.update(dict.fromkeys(column_name(k) for k in raw))

    counts = {}
    drift_warned = False
    with open(args.log, encoding="utf-8", errors="replace") as src, \
            open(out_path, "w", newline="", encoding="utf-8") as dst:
        writer = csv.DictWriter(dst, fieldnames=list(columns))
        writer.writeheader()
        for number, line in enumerate(src, start=1):
            raw = parse_line(line)
            if not raw:
                continue
            try:
                if raw.get("AgentDevice") == "WindowsDNS":
                    row = from_dns(raw, tz)
                elif raw.get("DeviceType") == "Estreamer":
                    row = from_firepower(raw, tz)
                    drift = tz_drift(raw, tz)
                    if drift is not None and drift > 300 and not drift_warned:
                        print(f"[!] Строка {number}: время FirePower с поясом {args.tz} расходится "
                              f"с CurrentTime на {drift / 3600:.1f} ч, проверь --tz")
                        drift_warned = True
                else:
                    sys.exit(f"[!] Строка {number}: неизвестный источник, нет AgentDevice=WindowsDNS "
                             f"или DeviceType=Estreamer")
            except (KeyError, ValueError) as e:
                sys.exit(f"[!] Строка {number}: не разобрал время ({type(e).__name__}: {e})")
            if args.all_fields:
                row.update((column_name(k), v) for k, v in raw.items())
            writer.writerow(row)
            counts[row["SourceType"]] = counts.get(row["SourceType"], 0) + 1

    total = sum(counts.values())
    by_source = ", ".join(f"{k} {v}" for k, v in counts.items())
    print(f"[+] {args.log.name}: {total} строк ({by_source}), колонок {len(columns)} -> {out_path}")
    print(f"    Отправка: python3 send_to_siglens.py {out_path} --index <индекс> --time-column EventTime "
          f"--time-format '%Y-%m-%d %H:%M:%S%z' --int-columns {INT_COLUMNS}")


if __name__ == "__main__":
    main()
