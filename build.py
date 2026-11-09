import base64
import bisect
import csv
import datetime
import io
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

socket.setdefaulttimeout(6)

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"}

SOURCES_FILE = "sources.txt"
TG_POOL_FILE = "tg_discovered_pool.txt"
HISTORY_FILE = "history.json"
README_FILE = "README.md"

# Выходные файлы (включая обратную совместимость со старыми list.txt и sub.txt)
OUT_ALL = "all.txt"
OUT_WL = "whitelist-mobile.txt"
OUT_AI = "ai-claude-gemini.txt"
OUT_FAST = "fast.txt"
LEGACY_LIST = "list.txt"
LEGACY_SUB = "sub.txt"

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_TOTAL = 1000
FAST_LIMIT = 100
MIN_TOTAL = 5
BATCH_SIZE = 50
WORKERS = 35

# Критерии авто-источников
MIN_WORKING_FOR_ACTIVE = 3
MAX_AUTO_FAILS = 3

GEO_CSV_URL = "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-country/geolite2-country-ipv4.csv"

PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")

# Регионы, где Claude и Gemini заблокированы или требуют обхода
AI_BLOCKED_COUNTRIES = {"RU", "BY", "CN", "HK", "MO", "IR", "KP", "SY", "CU"}

# Домены из российских «белых списков» для эвристики SNI
WHITELIST_SNI_DOMAINS = (
    "vk.com", "vk.ru", "userapi.com", "yandex.ru", "yandex.net", "ya.ru", "dzen.ru",
    "mail.ru", "imgsmail.ru", "ok.ru", "ozon.ru", "ozone.ru", "wb.ru", "wildberries.ru",
    "sberbank.ru", "sber.ru", "vtb.ru", "tbank.ru", "tinkoff.ru", "gosuslugi.ru",
    "rutube.ru", "kinopoisk.ru", "avito.ru", "2gis.ru", "kaspersky.com", "kaspersky.ru",
    "cdnvideo.ru", "selectel.ru", "timeweb.com", "beget.com", "mts.ru", "megafon.ru",
    "yota.ru", "tele2.ru", "rostelecom.ru",
)

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")
PBK_RE = re.compile(r"^[A-Za-z0-9_\-]{42,44}$")
SID_RE = re.compile(r"^(?:[0-9a-fA-F]{2}){0,8}$")
CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
ALLOWED_FP = {"chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized", "qq", "360"}

geo_starts, geo_ends, geo_codes = [], [], []
wl_cidr_starts, wl_cidr_ends = [], []


def flag(code):
    if not code or len(code) != 2 or not code.isalpha():
        return "UN"
    code = code.upper()
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def safe_http_get(url, timeout=20):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise ValueError("Превышен лимит 5 МБ")
        if b"\x00" in data[:1024]:
            raise ValueError("Бинарный файл")
        return data.decode("utf-8", errors="ignore")


def load_geo():
    try:
        raw = safe_http_get(GEO_CSV_URL, 60)
    except Exception as e:
        sys.exit(f"FATAL: GeoIP не загружен ({e}), файлы не обновлены")
    starts, ends, codes = [], [], []
    for row in csv.reader(io.StringIO(raw)):
        if len(row) < 3:
            continue
        try:
            starts.append(int(ipaddress.IPv4Address(row[0])))
            ends.append(int(ipaddress.IPv4Address(row[1])))
            codes.append(row[2].strip().upper())
        except ValueError:
            continue
    if not starts:
        sys.exit("FATAL: GeoIP пустой")
    print(f"GeoIP загружен: {len(starts)} диапазонов")
    return starts, ends, codes


def country_of(ip):
    try:
        n = int(ipaddress.IPv4Address(ip))
    except ValueError:
        return None
    i = bisect.bisect_right(geo_starts, n) - 1
    if i >= 0 and geo_starts[i] <= n <= geo_ends[i]:
        return geo_codes[i]
    return None


def rebuild_cidr_index(networks):
    if not networks:
        return [], []
    intervals = sorted((int(net.network_address), int(net.broadcast_address)) for net in networks)
    merged = [intervals[0]]
    for start, end in intervals[1:]:
        prev_s, prev_e = merged[-1]
        if start <= prev_e + 1:
            merged[-1] = (prev_s, max(prev_e, end))
        else:
            merged.append((start, end))
    return [x[0] for x in merged], [x[1] for x in merged]


def in_whitelist_cidr(ip):
    if not wl_cidr_starts:
        return False
    try:
        n = int(ipaddress.IPv4Address(ip))
    except ValueError:
        return False
    i = bisect.bisect_right(wl_cidr_starts, n) - 1
    return i >= 0 and wl_cidr_starts[i] <= n <= wl_cidr_ends[i]


def is_whitelist_sni(sni):
    if not sni:
        return False
    sni = sni.lower().strip(".")
    if sni.endswith((".ru", ".su", ".рф", ".xn--p1ai")):
        return True
    return any(sni == d or sni.endswith("." + d) for d in WHITELIST_SNI_DOMAINS)


def decode_base64_padded(text):
    text = "".join(text.split())
    text = text.replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)
    return base64.b64decode(text).decode("utf-8", errors="ignore")


def fetch_source_content(url):
    text = safe_http_get(url, 25)
    sample = text[:512].lstrip().lower()
    if sample.startswith("<!doctype html") or sample.startswith("<html"):
        raise ValueError("Получен HTML вместо списка")

    if not any(p in text for p in PROTOCOLS) and not CIDR_RE.search(text[:200]):
        try:
            text = decode_base64_padded(text)
        except Exception:
            pass

    proxy_lines = []
    cidrs = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith(PROTOCOLS):
            proxy_lines.append(line)
        elif CIDR_RE.match(line):
            try:
                cidrs.append(ipaddress.IPv4Network(line, strict=False))
            except ValueError:
                pass
    return proxy_lines, cidrs


def parse_meta(meta_str):
    meta = {"tags": set(), "status": "active", "fails": 0, "last_count": 0}
    for part in meta_str.split():
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k == "tags":
            meta["tags"] = {t.strip() for t in v.split(",") if t.strip()}
        elif k == "status":
            meta["status"] = v.strip()
        elif k == "fails" and v.isdigit():
            meta["fails"] = int(v)
        elif k == "last_count" and v.isdigit():
            meta["last_count"] = int(v)
    return meta


def format_meta(meta):
    tags_str = ",".join(sorted(meta["tags"])) if meta["tags"] else "general"
    return f"tags={tags_str} status={meta['status']} fails={meta['fails']} last_count={meta['last_count']}"


def read_sources():
    if not os.path.exists(SOURCES_FILE):
        return []
    with open(SOURCES_FILE, encoding="utf-8") as f:
        lines = f.read().splitlines()

    entries = []
    section = "MANUAL"
    for line in lines:
        s = line.strip()
        if s == "# MANUAL":
            section = "MANUAL"
            continue
        if s == "# AUTO":
            section = "AUTO"
            continue
        if not s or s.startswith("#"):
            continue
        url = s.split("#", 1)[0].strip()
        meta_raw = s.split("#", 1)[1].strip() if "#" in s else ""
        meta = parse_meta(meta_raw)
        if not url.startswith(("http://", "https://")) or not url.isascii():
            continue
        entries.append({"section": section, "url": url, "meta": meta})
    return entries


def write_sources(entries):
    manual = [e for e in entries if e["section"] == "MANUAL"]
    auto = [e for e in entries if e["section"] == "AUTO"]

    out = [
        "# ==============================================================================",
        "# БЛОК РУЧНЫХ ИСТОЧНИКОВ (discover.py никогда не удаляет строки из этого блока)",
        "# ==============================================================================",
        "# MANUAL",
    ]
    for e in manual:
        out.append(f"{e['url']} # {format_meta(e['meta'])}")
    out.append("")
    out.append("# ==============================================================================")
    out.append("# БЛОК АВТОМАТИЧЕСКИХ ИСТОЧНИКОВ (управляется discover.py и build.py)")
    out.append("# ==============================================================================")
    out.append("# AUTO")
    for e in auto:
        out.append(f"{e['url']} # {format_meta(e['meta'])}")

    with open(SOURCES_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return {}
    try:
        with open(HISTORY_FILE, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        print("WARN: history.json поврежден, создаем чистую историю")
        return {}


def save_history(history):
    now = time.time()
    # Храним историю максимум 14 дней, чтобы файл не разрастался
    cleaned = {
        k: v for k, v in history.items()
        if isinstance(v, dict) and now - v.get("seen", 0) < 14 * 86400
    }
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(cleaned, f, indent=1)


def parse_proxy(link):
    link = link.strip()
    low = link.lower()
    if low.startswith("vless://"):
        return parse_vless(link)
    if low.startswith("vmess://"):
        return parse_vmess(link)
    if low.startswith("trojan://"):
        return parse_trojan(link)
    if low.startswith("ss://"):
        return parse_ss(link)
    if low.startswith(("hysteria2://", "hy2://")):
        return parse_hysteria2(link)
    if low.startswith("tuic://"):
        return parse_tuic(link)
    return None


def build_tls_block(security, sni, fp, alpn=None, pbk=None, sid=None, insecure=False):
    if security not in ("tls", "reality"):
        return None
    tls = {
        "enabled": True,
        "server_name": sni or "",
        "insecure": bool(insecure),
    }
    if alpn:
        tls["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
    if fp and fp in ALLOWED_FP:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if security == "reality":
        tls["reality"] = {"enabled": True, "public_key": pbk, "short_id": sid or ""}
        if "utls" not in tls:
            tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
    return tls


def build_transport_block(net, params):
    if net == "ws":
        t = {"type": "ws", "path": params.get("path", "/")}
        if params.get("host"):
            t["headers"] = {"Host": params["host"]}
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": params.get("serviceName", "")}
    return None


def parse_vless(link):
    try:
        u = urllib.parse.urlparse(link)
        params = {k: v[0] for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}
        uuid, host, port = u.username or "", u.hostname or "", u.port
    except Exception:
        return None

    if not UUID_RE.match(uuid) or not HOST_RE.match(host) or not port or not (1 <= port <= 65535):
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

    fp = params.get("fp", "chrome")
    if fp and fp not in ALLOWED_FP:
        return None

    pbk, sid = params.get("pbk", ""), params.get("sid", "")
    if security == "reality":
        if not PBK_RE.match(pbk) or not SID_RE.match(sid):
            return None

    sni = params.get("sni") or params.get("host") or host
    outbound = {
        "type": "vless",
        "server": host,
        "server_port": port,
        "uuid": uuid,
    }
    if flow:
        outbound["flow"] = flow
    tls = build_tls_block(security, sni, fp, params.get("alpn"), pbk, sid)
    if tls:
        outbound["tls"] = tls
    transport = build_transport_block(net, params)
    if transport:
        outbound["transport"] = transport

    proto_tag = "VLESS-Reality" if security == "reality" else "VLESS-TLS"
    return {
        "key": f"vless:{uuid}@{host}:{port}",
        "host": host,
        "port": port,
        "proto_tag": proto_tag,
        "is_reality": security == "reality",
        "is_udp": False,
        "sni": sni,
        "outbound": outbound,
        "link": link,
    }


def parse_trojan(link):
    try:
        u = urllib.parse.urlparse(link)
        params = {k: v[0] for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}
        password = urllib.parse.unquote(u.username or "")
        host, port = u.hostname or "", u.port
    except Exception:
        return None
    if not password or not HOST_RE.match(host) or not port or not (1 <= port <= 65535):
        return None

    net = params.get("type", "tcp")
    if net not in ("tcp", "ws", "grpc"):
        return None
    security = params.get("security", "tls")
    if security not in ("tls", "reality"):
        return None
    sni = params.get("sni") or params.get("host") or host
    fp = params.get("fp", "chrome")
    pbk, sid = params.get("pbk", ""), params.get("sid", "")
    if security == "reality" and (not PBK_RE.match(pbk) or not SID_RE.match(sid)):
        return None

    outbound = {
        "type": "trojan",
        "server": host,
        "server_port": port,
        "password": password,
    }
    tls = build_tls_block(security, sni, fp, params.get("alpn"), pbk, sid)
    if tls:
        outbound["tls"] = tls
    transport = build_transport_block(net, params)
    if transport:
        outbound["transport"] = transport

    return {
        "key": f"trojan:{password[:16]}@{host}:{port}",
        "host": host,
        "port": port,
        "proto_tag": "Trojan",
        "is_reality": security == "reality",
        "is_udp": False,
        "sni": sni,
        "outbound": outbound,
        "link": link,
    }


def parse_vmess(link):
    try:
        b64 = link[len("vmess://"):].split("#", 1)[0]
        raw = decode_base64_padded(b64)
        data = json.loads(raw)
        host = str(data.get("add", "")).strip()
        port = int(data.get("port", 0))
        uuid = str(data.get("id", "")).strip()
        net = str(data.get("net", "tcp")).strip()
        tls_flag = str(data.get("tls", "")).strip()
        sni = str(data.get("sni") or data.get("host") or host).strip()
    except Exception:
        return None

    if not UUID_RE.match(uuid) or not HOST_RE.match(host) or not (1 <= port <= 65535):
        return None
    if net not in ("tcp", "ws", "grpc"):
        return None

    outbound = {
        "type": "vmess",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "security": str(data.get("scy", "auto")),
        "alter_id": int(data.get("aid", 0) or 0),
    }
    if tls_flag == "tls":
        outbound["tls"] = build_tls_block("tls", sni, str(data.get("fp", "chrome")))
    transport = build_transport_block(net, {"path": data.get("path", "/"), "host": data.get("host", ""), "serviceName": data.get("path", "")})
    if transport:
        outbound["transport"] = transport

    return {
        "key": f"vmess:{uuid}@{host}:{port}",
        "host": host,
        "port": port,
        "proto_tag": "VMess",
        "is_reality": False,
        "is_udp": False,
        "sni": sni,
        "outbound": outbound,
        "link": link,
    }


def parse_ss(link):
    try:
        body = link[len("ss://"):].split("#", 1)[0].split("?", 1)[0]
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            if ":" not in userinfo:
                userinfo = decode_base64_padded(userinfo)
        else:
            decoded = decode_base64_padded(body)
            userinfo, hostport = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
        method = urllib.parse.unquote(method)
        password = urllib.parse.unquote(password)
        host, port_str = hostport.rsplit(":", 1)
        port = int(port_str)
    except Exception:
        return None

    allowed_ciphers = {
        "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    }
    if method not in allowed_ciphers or not HOST_RE.match(host) or not (1 <= port <= 65535) or not password:
        return None

    outbound = {
        "type": "shadowsocks",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }
    return {
        "key": f"ss:{method}:{password[:12]}@{host}:{port}",
        "host": host,
        "port": port,
        "proto_tag": "Shadowsocks",
        "is_reality": False,
        "is_udp": False,
        "sni": "",
        "outbound": outbound,
        "link": link,
    }


def parse_hysteria2(link):
    norm = "hysteria2://" + link.split("://", 1)[1]
    try:
        u = urllib.parse.urlparse(norm)
        params = {k: v[0] for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}
        password = urllib.parse.unquote(u.username or "")
        host, port = u.hostname or "", u.port
    except Exception:
        return None

    if not password or not HOST_RE.match(host) or not port or not (1 <= port <= 65535):
        return None
    sni = params.get("sni") or host
    insecure = params.get("insecure") in ("1", "true")

    outbound = {
        "type": "hysteria2",
        "server": host,
        "server_port": port,
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": sni,
            "insecure": insecure,
        },
    }
    if params.get("obfs") == "salamander" and params.get("obfs-password"):
        outbound["obfs"] = {"type": "salamander", "password": params["obfs-password"]}

    return {
        "key": f"hy2:{password[:16]}@{host}:{port}",
        "host": host,
        "port": port,
        "proto_tag": "Hysteria2",
        "is_reality": False,
        "is_udp": True,
        "sni": sni,
        "outbound": outbound,
        "link": link,
    }


def parse_tuic(link):
    try:
        u = urllib.parse.urlparse(link)
        params = {k: v[0] for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}
        uuid = urllib.parse.unquote(u.username or "")
        password = urllib.parse.unquote(u.password or "")
        host, port = u.hostname or "", u.port
    except Exception:
        return None

    if not UUID_RE.match(uuid) or not HOST_RE.match(host) or not port or not (1 <= port <= 65535):
        return None
    sni = params.get("sni") or host

    outbound = {
        "type": "tuic",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "password": password,
        "congestion_control": params.get("congestion_control", "bbr"),
        "tls": {
            "enabled": True,
            "server_name": sni,
            "alpn": ["h3"],
        },
    }
    return {
        "key": f"tuic:{uuid}@{host}:{port}",
        "host": host,
        "port": port,
        "proto_tag": "TUIC",
        "is_reality": False,
        "is_udp": True,
        "sni": sni,
        "outbound": outbound,
        "link": link,
    }


def prefilter_node(node):
    host, port = node["host"], node["port"]
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET)[0][4][0]
    except Exception:
        return "dns_fail", node, None, None

    code = country_of(ip) or "UN"
    no