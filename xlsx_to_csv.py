#!/usr/bin/env python3
"""
Парсер почтового лога: XLSX -> CSV.

Кроме конвертации раскодирует RequestHeaderAuthorization (Basic base64)
и добавляет две колонки:
  AuthUser - логин в нижнем регистре без домена
  AuthPass - пароль, который был отправлен

Использование:
  python3 xlsx_to_csv.py mail_log.xlsx
  python3 xlsx_to_csv.py mail_log.xlsx -o out/mail_log.csv --sheet Лист1
"""
import argparse
import base64
import csv
import sys
from datetime import datetime
from pathlib import Path

AUTH_COLUMN = "RequestHeaderAuthorization"
TIME_FMT = "%Y-%m-%d %H:%M:%S"


def decode_basic(value):
    """'Basic <base64>' -> (логин, пароль). Для всего остального ('', '')."""
    if not isinstance(value, str) or not value.startswith("Basic "):
        return "", ""
    try:
        raw = base64.b64decode(value[6:]).decode("utf-8", "replace")
    except ValueError:
        return "", ""
    user, _, password = raw.partition(":")
    # Логины встречаются как name, DOMAIN\name и name@domain
    user = user.lower().split("\\")[-1].split("@")[0]
    return user, password


def cell_to_text(value):
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.strftime(TIME_FMT)
    return str(value)


def main():
    parser = argparse.ArgumentParser(description="XLSX -> CSV с раскодированным Basic auth")
    parser.add_argument("xlsx", type=Path)
    parser.add_argument("-o", "--out", type=Path, help="куда писать CSV (по умолчанию рядом с XLSX)")
    parser.add_argument("--sheet", help="имя листа (по умолчанию первый)")
    args = parser.parse_args()

    try:
        import openpyxl
    except ImportError:
        sys.exit("[!] Нужен openpyxl: pip install openpyxl")

    if not args.xlsx.exists():
        sys.exit(f"[!] Файл не найден: {args.xlsx}")

    out_path = args.out or args.xlsx.with_suffix(".csv")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    wb = openpyxl.load_workbook(args.xlsx, read_only=True, data_only=True)
    ws = wb[args.sheet] if args.sheet else wb.worksheets[0]

    header = None
    auth_idx = None
    count = with_auth = 0
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for row in ws.iter_rows(values_only=True):
            if not any(v is not None for v in row):
                continue
            if header is None:
                header = [cell_to_text(v) for v in row]
                if AUTH_COLUMN in header:
                    auth_idx = header.index(AUTH_COLUMN)
                    writer.writerow(header + ["AuthUser", "AuthPass"])
                else:
                    writer.writerow(header)
                continue
            line = [cell_to_text(v) for v in row]
            if auth_idx is not None:
                user, password = decode_basic(row[auth_idx])
                line += [user, password]
                with_auth += bool(user)
            writer.writerow(line)
            count += 1

    print(f"[+] {ws.title}: {count} строк -> {out_path}")
    if auth_idx is not None:
        print(f"    из них с логином и паролем: {with_auth}")


if __name__ == "__main__":
    main()
