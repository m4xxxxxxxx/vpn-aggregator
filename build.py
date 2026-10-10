import urllib.request
import base64
import re
import gzip
import io
import socket
from urllib.parse import unquote, urlparse

import geoip2.database

PROTOCOLS = ("vless://", "vmess://", "ss://", "trojan://")

BLOCKED = [
    "RU", "Russia", "РФ", "CN", "China", "HK", "Hong Kong", "IR", "Iran",
    "SY", "Syria", "CU", "Cuba", "BY", "Belarus", "VE", "Venezuela",
    "MM", "Myanmar", "PK", "Pakistan", "KZ", "Kazakhstan", "EG", "Egypt",
    "IN", "India", "IQ", "Iraq", "SA", "Saudi Arabia", "AE", "United Arab Emirates",
    "VN", "Vietnam", "AZ", "Azerbaijan", "TR", "Turkey", "AF", "Afghanistan",
    "AR", "Argentina",
]

BLOCKED_CODES = {
    "RU", "CN", "HK", "IR", "SY", "CU", "BY", "VE", "MM", "PK", "KZ", "EG",
    "IN", "IQ", "SA", "AE", "VN", "AZ", "TR", "AF", "AR",
}

GEO_URL = "https://download.db-ip.com/free/dbip-country-lite-2026-10.mmdb.gz"
GEO_FILE = "dbip.mmdb"

# Скачиваем базу GeoIP (DB-IP Lite), если её ещё нет
try:
    with urllib.request.urlopen(GEO_URL, timeout=60) as r:
        data = gzip.decompress(r.read())
    open(GEO_FILE, "wb").write(data)
    geo = geoip2.database.Reader(GEO_FILE)
except Exception as e:
    print("Не удалось загрузить базу GeoIP:", e)
    geo = None

def is_blocked_by_name(link):
    name = unquote(link.split("#", 1)[1]) if "#" in link else ""
    for tag in BLOCKED:
        if re.search(r"(?<![A-Za-zА-Яа-я])" + re.escape(tag) + r"(?![A-Za-zА-Яа-я])", name, re.IGNORECASE):
            return True
    return False

def get_host(link):
    # Для vmess ключ закодирован в base64 JSON, поэтому берём только явные ссылки
    try:
        netloc = urlparse(link).hostname
        return netloc
    except Exception:
        return None

def is_blocked_by_ip(link):
    if geo is None:
        return False
    host = get_host(link)
    if not host:
        return False
    try:
        ip = socket.gethostbyname(host)
        code = geo.country(ip).country.iso_code
        return code in BLOCKED_CODES
    except Exception:
        # Не удалось определить страну, сервер пропускаем
        return False

sources = [line.strip() for line in open("sources.txt", encoding="utf-8") if line.strip()]
servers = set()

for url in sources:
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            text = r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print("Ошибка:", url, e)
        continue

    # Некоторые списки закодированы в base64 целиком
    if not any(p in text for p in PROTOCOLS):
        try:
            text = base64.b64decode(text.strip() + "==").decode("utf-8", errors="ignore")
        except Exception:
            continue

    for line in text.splitlines():
        line = line.strip()
        if line.startswith(PROTOCOLS) and not is_blocked_by_name(line) and not is_blocked_by_ip(line):
            servers.add(line)

result = "\n".join(sorted(servers))
open("list.txt", "w", encoding="utf-8").write(result)
print("Серверов:", len(servers))