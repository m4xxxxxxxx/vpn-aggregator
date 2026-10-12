import base64
import bisect
import csv
import io
import re
import socket
import sys
import time
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address
from urllib.parse import parse_qs, quote, unquote, urlparse

socket.setdefaulttimeout(5)

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
PROTOCOL = "vless://"
LIST_FILE = "list.txt"
SUB_FILE = "sub.txt"
SOURCES_FILE = "sources.txt"

MAX_TOTAL = 1000            # общий лимит строк
MAX_RU_SHARE = 600          # российских не больше этого, остальное зарубежные
MIN_TOTAL = 5               # если серверов меньше, файлы не перезаписываются
MAX_LATENCY_RU = 2.5        # TCP-задержка с GitHub Actions, секунды
MAX_LATENCY_FOREIGN = 1.0
WORKERS = 40
GEO_CSV_URL = "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-country/geolite2-country-ipv4.csv"

RU = "RU"
FOREIGN_CODES = {
    "US", "CA", "GB", "DE", "FR", "NL", "SE", "FI", "NO", "DK", "CH", "IE",
    "AT", "BE", "IT", "ES", "PT", "PL", "CZ", "JP", "SG", "AU",
}

FOREIGN_BLOCK_RE = re.compile(
    r"(?<!\w)(Russia|Russian|РФ|Россия|Timeweb|Selectel|Beget|Yandex|VK|Belarus|China|Hong Kong|Iran)(?!\w)",
    re.IGNORECASE,
)

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")
PBK_RE = re.compile(r"^[A-Za-z0-9_\-]{43}$")
SID_RE = re.compile(r"^(?:[0-9a-fA-F]{2}){0,8}$")
ALLOWED_FP = {"chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"}

geo_starts, geo_ends, geo_codes = [], [], []


def flag(code):
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def http_get(url, timeout):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")


def load_geo():
    try:
        raw = http_get(GEO_CSV_URL, 60)
    except Exception as e:
        sys.exit(f"FATAL: GeoIP не загружен ({e}), файлы не обновлены")
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
        sys.exit("FATAL: GeoIP пустой, файлы не обновлены")
    print(f"GeoIP загружен: {len(starts)} диапазонов")
    return starts, ends, codes


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


def parse_vless(link):
    try:
        u = urlparse(link)
        params = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        uuid, host, port = u.username or "", u.hostname or "", u.port
    except ValueError:
        return None

    if not UUID_RE.match(uuid) or not HOST_RE.match(host) or not port:
        return None
    if params.get("encryption", "none") != "none":
        return None

    security = params.get("security", "")
    if security not in ("reality", "tls"):
        return None

    net = params.get("type", "tcp")
    if net not in ("tcp", "ws", "grpc"):
        return None

    flow = params.get("flow", "")
    if flow and (flow != "xtls-rprx-vision" or security != "reality" or net != "tcp"):
        return None

    if params.get("fp") and params["fp"] not in ALLOWED_FP:
        return None

    if security == "reality":
        if not PBK_RE.match(params.get("pbk", "")):
            return None
        if not SID_RE.match(params.get("sid", "")):
            return None

    return {"host": host, "port": port, "uuid": uuid, "security": security,
            "params": params, "link": link}


def mobile_rank(parsed, latency):
    """Меньше = лучше: reality, затем порт 443, затем TCP, затем задержка."""
    return (
        0 if parsed["security"] == "reality" else 1,
        0 if parsed["port"] == 443 else 1,
        0 if parsed["params"].get("type", "tcp") == "tcp" else 1,
        latency,
    )


def evaluate(item):
    key, host, port = item
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET)[0][4][0]
    except Exception:
        return "dns_fail", key, None, None
    code = country_of(ip)
    if code is None:
        return "geo_unknown", key, None, None
    if code != RU and code not in FOREIGN_CODES:
        return "country_not_allowed", key, None, None
    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=3):
            pass
    except Exception:
        return "dead", key, None, None
    return "ok", key, time.monotonic() - t0, code


def load_sources():
    with open(SOURCES_FILE, encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    return [l for l in lines if l.startswith(("http://", "https://")) and l.isascii()]


def pick(ru_ok, fo_ok):
    ru_take = min(len(ru_ok), MAX_RU_SHARE)
    fo_take = min(len(fo_ok), MAX_TOTAL - ru_take)
    ru_take = min(len(ru_ok), MAX_TOTAL - fo_take)
    return ru_ok[:ru_take], fo_ok[:fo_take]


def main():
    global geo_starts, geo_ends, geo_codes
    geo_starts, geo_ends, geo_codes = load_geo()

    unique = {}
    stats = Counter()
    for url in load_sources():
        try:
            lines = fetch_lines(url)
        except Exception as e:
            print("Ошибка источника:", url, e)
            continue
        print(f"{len(lines):6d}  {url}")
        for link in lines:
            parsed = parse_vless(link)
            if parsed is None:
                stats["bad_format"] += 1
                continue
            key = f"{parsed['uuid']}@{parsed['host']}:{parsed['port']}"
            if key in unique:
                stats["duplicate"] += 1
                continue
            unique[key] = parsed

    items = [(k, v["host"], v["port"]) for k, v in unique.items()]
    ru_ok, fo_ok = [], []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for status, key, latency, code in ex.map(evaluate, items):
            stats[status] += 1
            if status != "ok":
                continue
            u = unique[key]
            if code == RU:
                if latency > MAX_LATENCY_RU:
                    stats["ru_slow"] += 1
                    continue
                ru_ok.append((mobile_rank(u, latency), u, code))
            else:
                if FOREIGN_BLOCK_RE.search(name_of(u["link"])):
                    stats["blocked_name"] += 1
                    continue
                if latency > MAX_LATENCY_FOREIGN:
                    stats["foreign_slow"] += 1
                    continue
                fo_ok.append((mobile_rank(u, latency), u, code))

    ru_ok.sort(key=lambda x: x[0])
    fo_ok.sort(key=lambda x: x[0])

    for k, v in stats.most_common():
        print(f"{k}: {v}")

    ru_sel, fo_sel = pick(ru_ok, fo_ok)
    chosen = [(u, c) for _, u, c in ru_sel] + [(u, c) for _, u, c in fo_sel]

    if len(chosen) < MIN_TOTAL:
        sys.exit(f"FATAL: найдено серверов {len(chosen)}, файлы не обновлены")

    lines = []
    for n, (u, code) in enumerate(chosen, 1):
        base = u["link"].split("#", 1)[0]
        label = quote(f"{flag(code)} {code}-{n:04d}")
        lines.append(f"{base}#{label}")

    text = "\n".join(lines) + "\n"
    with open(LIST_FILE, "w", encoding="utf-8") as f:
        f.write(text)
    with open(SUB_FILE, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(text.encode("utf-8")).decode("ascii") + "\n")

    print(f"Записано: {len(lines)} серверов (RU: {len(ru_sel)}, зарубежных: {len(fo_sel)})")


if __name__ == "__main__":
    main()