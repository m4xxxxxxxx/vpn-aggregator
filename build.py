import base64
import bisect
import csv
import io
import json
import re
import socket
import sys
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address
from urllib.parse import unquote, urlparse

socket.setdefaulttimeout(5)

PROTOCOLS = ("vless://", "vmess://", "ss://", "trojan://")

# Страны, которые исключаем (ISO-коды)
BLOCKED_CODES = {
    "RU", "BY", "CN", "HK", "IR", "SY", "CU", "VE", "MM", "PK", "KZ", "EG",
    "IN", "IQ", "SA", "AE", "VN", "AZ", "TR", "AF", "AR",
}

BLOCKED_NAME_WORDS = [
    "Russia", "Russian", "РФ", "Россия", "China", "Hong Kong", "Iran", "Syria",
    "Cuba", "Belarus", "Venezuela", "Myanmar", "Pakistan", "Kazakhstan", "Egypt",
    "India", "Iraq", "Saudi Arabia", "United Arab Emirates", "Vietnam",
    "Azerbaijan", "Turkey", "Afghanistan", "Argentina",
    "Timeweb", "Selectel", "Beget", "Yandex", "VK",
]

# CSV: start_ip, end_ip, country_code (IPv4)
GEO_CSV_URL = "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-country/geolite2-country-ipv4.csv"


def _word_re(words, flags=0):
    alt = "|".join(re.escape(w) for w in words)
    return re.compile(rf"(?<!\w)(?:{alt})(?!\w)", flags)


NAME_CODES_RE = _word_re(BLOCKED_CODES)
NAME_WORDS_RE = _word_re(BLOCKED_NAME_WORDS, re.IGNORECASE)


def load_geo():
    """Загружает таблицу диапазонов IPv4 -> код страны. При ошибке останавливает сборку."""
    try:
        req = urllib.request.Request(GEO_CSV_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        sys.exit(f"FATAL: GeoIP не загружен ({e}), list.txt не обновлён")

    starts, ends, codes = [], [], []
    for row in csv.reader(io.StringIO(raw)):
        if len(row) < 3:
            continue
        try:
            starts.append(int(IPv4Address(row[0])))
            ends.append(int(IPv4Address(row[1])))
            codes.append(row[2].strip().upper())
        except ValueError:
            continue

    if not starts:
        sys.exit("FATAL: GeoIP пустой, list.txt не обновлён")

    print(f"GeoIP загружен: {len(starts)} диапазонов")
    return starts, ends, codes


geo_starts, geo_ends, geo_codes = [], [], []


def country_of(ip):
    n = int(IPv4Address(ip))
    i = bisect.bisect_right(geo_starts, n) - 1
    if i >= 0 and geo_starts[i] <= n <= geo_ends[i]:
        return geo_codes[i]
    return None


def decode_base64(text):
    text = "".join(text.split())
    text += "=" * (-len(text) % 4)
    return base64.b64decode(text).decode("utf-8", errors="ignore")


def fetch_lines(url):
    with urllib.request.urlopen(url, timeout=20) as r:
        text = r.read().decode("utf-8", errors="ignore")
    if not any(p in text for p in PROTOCOLS):
        text = decode_base64(text)
    return [l.strip() for l in text.splitlines() if l.strip().startswith(PROTOCOLS)]


def name_of(link):
    return unquote(link.split("#", 1)[1]) if "#" in link else ""


def blocked_by_name(link):
    name = name_of(link)
    return bool(NAME_CODES_RE.search(name) or NAME_WORDS_RE.search(name))


def host_port(link):
    try:
        if link.startswith("vmess://"):
            j = json.loads(decode_base64(link[len("vmess://"):]))
            return j["add"], int(j.get("port", 443))
        u = urlparse(link)
        return u.hostname, (u.port or 443)
    except Exception:
        return None, None


def evaluate(link):
    host, port = host_port(link)
    if not host:
        return "bad_format", link
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET)[0][4][0]
    except Exception:
        return "dns_fail", link
    code = country_of(ip)
    if code is None:
        return "geo_unknown", link
    if code in BLOCKED_CODES:
        return "blocked_ip", link
    try:
        with socket.create_connection((ip, port), timeout=3):
            pass
    except Exception:
        return "dead", link
    return "ok", link


def main():
    global geo_starts, geo_ends, geo_codes
    geo_starts, geo_ends, geo_codes = load_geo()

    with open("sources.txt", encoding="utf-8") as f:
        sources = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    candidates = set()
    for url in sources:
        try:
            lines = fetch_lines(url)
            print(f"{len(lines):6d}  {url}")
            candidates.update(lines)
        except Exception as e:
            print("Ошибка источника:", url, e)

    stats = Counter()
    to_check = []
    for link in candidates:
        if blocked_by_name(link):
            stats["blocked_name"] += 1
        else:
            to_check.append(link)

    good = []
    with ThreadPoolExecutor(max_workers=30) as ex:
        for status, link in ex.map(evaluate, to_check):
            stats[status] += 1
            if status == "ok":
                good.append(link)

    print("Всего уникальных:", len(candidates))
    for k, v in stats.most_common():
        print(f"{k}: {v}")

    if not good:
        sys.exit("FATAL: ни один сервер не прошёл фильтр, list.txt не обновлён")

    good.sort()
    with open("list.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(good) + "\n")
    print("Серверов в list.txt:", len(good))


if __name__ == "__main__":
    main()