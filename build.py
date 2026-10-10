import base64
import bisect
import csv
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address
from urllib.parse import parse_qs, quote, unquote, urlparse

socket.setdefaulttimeout(5)

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

PROTOCOL = "vless://"
OUT_FILE = "config.json"
HISTORY_FILE = "history.json"
MAX_SERVERS = 300
MAX_LATENCY = 0.8
SINGBOX_BIN = "sing-box"
SINGBOX_TIMEOUT = 30
SINGBOX_WORKERS = 8
TEST_URL = "https://www.gstatic.com/generate_204"

ALLOWED_CODES = {
    "US", "CA", "GB", "DE", "FR", "NL", "SE", "FI", "NO", "DK", "CH", "IE",
    "AT", "BE", "IT", "ES", "PT", "PL", "CZ", "JP", "SG", "AU",
}

BLOCKED_NAME_WORDS = [
    "Russia", "Russian", "РФ", "Россия", "Timeweb", "Selectel", "Beget",
    "Yandex", "VK", "Belarus", "China", "Hong Kong", "Iran",
]

# Эти домены всегда идут через VPN, даже если попали под правило для российских адресов
PROXY_DOMAINS = [
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
    "claude.ai", "anthropic.com",
    "gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com",
    "alkalimakersuite-pa.clients6.google.com", "proactivebackend-pa.googleapis.com",
    "deepmind.google", "bard.google.com",
    "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com",
    "telegram.org", "t.me", "telegram.me",
]

# Российские домены (punycode для .рф) идут напрямую
DIRECT_DOMAINS = [".ru", ".xn--p1ai", ".su"]

GEO_CSV_URL = "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-country/geolite2-country-ipv4.csv"

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")
PBK_RE = re.compile(r"^[A-Za-z0-9_\-]{43}$")
SID_RE = re.compile(r"^(?:[0-9a-fA-F]{2}){0,8}$")
ALLOWED_FP = {"chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"}
ALLOWED_TYPE = {"tcp", "ws", "grpc"}
ALLOWED_FLOW = {"xtls-rprx-vision"}


def _word_re(words, flags=0):
    alt = "|".join(re.escape(w) for w in words)
    return re.compile(rf"(?<!\w)(?:{alt})(?!\w)", flags)


NAME_WORDS_RE = _word_re(BLOCKED_NAME_WORDS, re.IGNORECASE)


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
        sys.exit(f"FATAL: GeoIP не загружен ({e}), {OUT_FILE} не обновлён")

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
        sys.exit(f"FATAL: GeoIP пустой, {OUT_FILE} не обновлён")

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
    try:
        u = urlparse(link)
        uuid = u.username or ""
        host = u.hostname or ""
        port = u.port
        params = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
    except ValueError:
        return None

    if not UUID_RE.match(uuid):
        return None
    if not HOST_RE.match(host) or not port or not (1 <= port <= 65535):
        return None
    if params.get("encryption", "none") != "none":
        return None

    security = params.get("security", "")
    if security not in ("reality", "tls"):
        return None

    net = params.get("type", "tcp")
    if net not in ALLOWED_TYPE:
        return None

    flow = params.get("flow", "")
    if flow and (flow not in ALLOWED_FLOW or security != "reality" or net != "tcp"):
        return None

    fp = params.get("fp", "")
    if fp and fp not in ALLOWED_FP:
        return None

    sni = params.get("sni", "")
    if sni and not HOST_RE.match(sni):
        return None

    if security == "reality":
        if not PBK_RE.match(params.get("pbk", "")):
            return None
        if not SID_RE.match(params.get("sid", "")):
            return None

    return {"host": host, "port": port, "uuid": uuid, "security": security, "params": params}


def singbox_outbound(parsed, tag):
    q = parsed["params"]
    ob = {
        "type": "vless",
        "tag": tag,
        "server": parsed["host"],
        "server_port": parsed["port"],
        "uuid": parsed["uuid"],
    }
    if q.get("flow"):
        ob["flow"] = q["flow"]

    net = q.get("type", "tcp")
    if net == "ws":
        t = {"type": "ws", "path": q.get("path", "/")}
        if q.get("host"):
            t["headers"] = {"Host": q["host"]}
        ob["transport"] = t
    elif net == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": q.get("serviceName", "")}

    security = parsed["security"]
    tls = {"enabled": True, "server_name": q.get("sni") or parsed["host"]}
    fp = q.get("fp") or ("chrome" if security == "reality" else "")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if security == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": q["pbk"],
            "short_id": q.get("sid", ""),
        }
    ob["tls"] = tls
    return ob


def sb_check(cfg):
    fd, path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        r = subprocess.run(
            [SINGBOX_BIN, "check", "-c", path],
            capture_output=True,
            text=True,
            timeout=SINGBOX_TIMEOUT,
        )
        return r.returncode == 0, (r.stderr or r.stdout).strip()[:800]
    except Exception as e:
        return False, str(e)
    finally:
        os.unlink(path)


def single_ok(link):
    parsed = parse_vless(link)
    if parsed is None:
        return False
    cfg = {
        "log": {"disabled": True},
        "outbounds": [singbox_outbound(parsed, "proxy"), {"type": "direct", "tag": "direct"}],
    }
    ok, _ = sb_check(cfg)
    return ok


def evaluate(item):
    key, host, port = item
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET)[0][4][0]
    except Exception:
        return "dns_fail", key, None, None

    code = country_of(ip)
    if code is None:
        return "geo_unknown", key, None, None
    if code not in ALLOWED_CODES:
        return "country_not_allowed", key, None, None

    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=3):
            pass
    except Exception:
        return "dead", key, None, None

    latency = time.monotonic() - t0
    if latency > MAX_LATENCY:
        return "slow", key, latency, code
    return "ok", key, latency, code


def load_history():
    try:
        with open(HISTORY_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_history(history):
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=1)


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


def build_config(outbounds_servers):
    tags = [ob["tag"] for ob in outbounds_servers]
    return {
        "log": {"level": "warn"},
        "dns": {
            "servers": [{"tag": "remote", "type": "https", "server": "1.1.1.1"}],
            "final": "remote",
        },
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"] + tags, "default": "auto"},
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": tags,
                "url": TEST_URL,
                "interval": "3m",
                "tolerance": 50,
            },
            *outbounds_servers,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [
                {"ip_is_private": True, "outbound": "direct"},
                {"domain_suffix": PROXY_DOMAINS, "outbound": "proxy"},
                {"domain_suffix": DIRECT_DOMAINS, "outbound": "direct"},
            ],
            "final": "proxy",
            "auto_detect_interface": True,
        },
    }


def main():
    if shutil.which(SINGBOX_BIN) is None:
        sys.exit("FATAL: sing-box не найден, " + OUT_FILE + " не обновлён")

    global geo_starts, geo_ends, geo_codes
    geo_starts, geo_ends, geo_codes = load_geo()
    old_history = load_history()
    now = time.time()

    unique = {}
    stats = Counter()
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
            key = f"{parsed['uuid']}@{parsed['host']}:{parsed['port']}"
            if key in unique:
                stats["duplicate"] += 1
                continue
            unique[key] = {**parsed, "link": link}

    print("Всего строк:", raw_total)
    print("Уникальных после разбора:", len(unique))

    items = [(k, v["host"], v["port"]) for k, v in unique.items()]
    results = {}
    with ThreadPoolExecutor(max_workers=30) as ex:
        for status, key, latency, code in ex.map(evaluate, items):
            stats[status] += 1
            results[key] = (status, latency, code)

    ranked = []
    for key, (status, latency, code) in results.items():
        if status != "ok":
            continue
        u = unique[key]
        streak = old_history.get(key, {}).get("streak", 0) + 1
        ranked.append((
            -streak,
            0 if u["security"] == "reality" else 1,
            0 if u["port"] == 443 else 1,
            latency,
            key,
            code,
            streak,
        ))
    ranked.sort()

    if not ranked:
        sys.exit(f"FATAL: ни один сервер не прошёл сетевую проверку, {OUT_FILE} не обновлён")

    accepted = []
    i = 0
    with ThreadPoolExecutor(max_workers=SINGBOX_WORKERS) as ex:
        while i < len(ranked) and len(accepted) < MAX_SERVERS:
            batch = ranked[i:i + 64]
            i += len(batch)
            verdicts = list(ex.map(lambda row: single_ok(unique[row[4]]["link"]), batch))
            for row, ok in zip(batch, verdicts):
                if ok:
                    accepted.append(row)
                else:
                    stats["singbox_reject"] += 1

    accepted = accepted[:MAX_SERVERS]
    stats["singbox_accept"] = len(accepted)

    for k, v in stats.most_common():
        print(f"{k}: {v}")

    if not accepted:
        sys.exit(f"FATAL: sing-box отклонил все серверы, {OUT_FILE} не обновлён")

    servers = []
    for idx, row in enumerate(accepted, 1):
        key, code = row[4], row[5]
        tag = f"{flag(code)} {code}-{idx:03d}"
        servers.append(singbox_outbound(unique[key], tag))

    config = build_config(servers)
    ok, err = sb_check(config)
    if not ok:
        sys.exit(f"FATAL: итоговый конфиг не прошёл sing-box check, {OUT_FILE} не обновлён:\n{err}")

    new_history = {}
    for row in accepted:
        new_history[row[4]] = {"streak": row[6], "seen": now}
    save_history(new_history)

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=1)
    print(f"Серверов в {OUT_FILE}: {len(servers)}, групп: proxy (auto + ручной выбор)")


if __name__ == "__main__":
    main()