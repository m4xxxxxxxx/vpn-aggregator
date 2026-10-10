import bisect
import csv
import io
import re
import socket
import sys
import time
import base64
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address
from urllib.parse import parse_qs, unquote, urlparse

socket.setdefaulttimeout(5)

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

PROTOCOL = "vless://"

# Сколько лучших серверов (по задержке) записывать в list.txt
MAX_SERVERS = 300

# Белый список стран (ISO-коды)
ALLOWED_CODES = {
    "US", "CA", "GB", "DE", "FR", "NL", "SE", "FI", "NO", "DK", "CH", "IE",
    "AT", "BE", "IT", "ES", "PT", "PL", "CZ", "JP", "SG", "AU",
}

BLOCKED_NAME_WORDS = [
    "Russia", "Russian", "РФ", "Россия", "Timeweb", "Selectel", "Beget",
    "Yandex", "VK", "Belarus", "China", "Hong Kong", "Iran",
]

GEO_CSV_URL = "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-country/geolite2-country-ipv4.csv"

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _word_re(words, flags=0):
    alt = "|".join(re.escape(w) for w in words)
    return re.compile(rf"(?<!\w)(?:{alt})(?!\w)", flags)


NAME_WORDS_RE = _word_re(BLOCKED_NAME_WORDS, re.IGNORECASE)


def http_get(url, timeout):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")


def load_geo():
    try:
        raw = http_get(GEO_CSV_URL, 60)
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
    text = http_get(url, 20)
    if PROTOCOL not in text:
        text = decode_base64(text)
    return [l.strip() for l in text.splitlines() if l.strip().startswith(PROTOCOL)]


def name_of(link):
    return unquote(link.split("#", 1)[1]) if "#" in link else ""


def blocked_by_name(link):
    return bool(NAME_WORDS_RE.search(name_of(link)))


def parse_vless(link):
    """Возвращает (host, port, uuid), если строка выглядит корректно, иначе None."""
    try:
        u = urlparse(link)
        uuid = u.username or ""
        host = u.hostname
        port = u.port
        params = parse_qs(u.query)
    except ValueError:
        return None

    if not UUID_RE.match(uuid) or not host or not port:
        return None

    security = params.get("security", [""])[0]
    if security not in ("reality", "tls"):
        return None
    if security == "reality" and not params.get("pbk"):
        return None

    return host, port, uuid


def evaluate(item):
    link, host, port = item
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET)[0][4][0]
    except Exception:
        return "dns_fail", link, None

    code = country_of(ip)
    if code is None:
        return "geo_unknown", link, None
    if code not in ALLOWED_CODES:
        return "country_not_allowed", link, None

    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=3):
            pass
    except Exception:
        return "dead", link, None
    return "ok", link, time.monotonic() - t0


def load_sources():
    with open("sources.txt", encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    good = []
    for l in lines:
        if not l.startswith(("http://", "https://")):
            print("Пропущена некорректная строка:", l)
            continue
        if not l.isascii():
            print("Пропущена ссылка с не-ASCII символами:", l)
            continue
        good.append(l)
    return good


def main():
    global geo_starts, geo_ends, geo_codes
    geo_starts, geo_ends, geo_codes = load_geo()

    stats = Counter()
    unique = {}
    raw_total = 0

    for url in load_sources():
        try:
            lines = fetch_lines(url)
        except Exception as e:
            print("Ошибка источника:", url, e)
            continue
        print(f"{len(lines):6d}  {url}")
        raw_total += len(lines)

        for link in lines:
            if blocked_by_name(link):
                stats["blocked_name"] += 1
                continue
            parsed = parse_vless(link)
            if parsed is None:
                stats["bad_format"] += 1
                continue
            host, port, uuid = parsed
            key = (host, port, uuid)
            if key in unique:
                stats["duplicate"] += 1
                continue
            unique[key] = (link, host, port)

    print("Всего строк:", raw_total)
    print("Уникальных после разбора:", len(unique))

    good = []
    with ThreadPoolExecutor(max_workers=30) as ex:
        for status, link, latency in ex.map(evaluate, unique.values()):
            stats[status] += 1
            if status == "ok":
                good.append((latency, link))

    for k, v in stats.most_common():
        print(f"{k}: {v}")

    if not good:
        sys.exit("FATAL: ни один сервер не прошёл фильтр, list.txt не обновлён")

    good.sort(key=lambda x: x[0])
    selected = [link for _, link in good[:MAX_SERVERS]]

    with open("list.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(selected) + "\n")
    print(f"Серверов в list.txt: {len(selected)} (из {len(good)} прошедших проверку)")


if __name__ == "__main__":
    main()