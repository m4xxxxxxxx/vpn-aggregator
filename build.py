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

socket.setdefaulttimeout(5)

UA = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )
}

SOURCES_FILE = "sources.txt"
TG_POOL_FILE = "tg_discovered_pool.txt"
HISTORY_FILE = "history.json"
README_FILE = "README.md"

OUT_ALL = "all.txt"
OUT_WL = "whitelist-mobile.txt"
OUT_AI = "ai-claude-gemini.txt"
OUT_FAST = "fast.txt"
LEGACY_LIST = "list.txt"
LEGACY_SUB = "sub.txt"

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_GEO_BYTES = 30 * 1024 * 1024  # 30 МБ для CSV-базы GeoIP
MAX_CANDIDATES_FOR_SINGBOX = 300
MAX_MOBILE_OUT = 150
FAST_LIMIT = 50
MIN_TOTAL = 3
BATCH_SIZE = 50
WORKERS = 40

MIN_WORKING_FOR_ACTIVE = 2
MAX_AUTO_FAILS = 3

GEO_CSV_URL = "https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-country/geolite2-country-ipv4.csv"

AI_BLOCKED_COUNTRIES = {"RU", "BY", "CN", "HK", "MO", "IR", "KP", "SY", "CU"}

WHITELIST_SNI_DOMAINS = (
    "vk.com", "vk.ru", "userapi.com", "yandex.ru", "yandex.net", "ya.ru", "dzen.ru",
    "mail.ru", "imgsmail.ru", "ok.ru", "ozon.ru", "ozone.ru", "wb.ru", "wildberries.ru",
    "sberbank.ru", "sber.ru", "vtb.ru", "tbank.ru", "tinkoff.ru", "gosuslugi.ru",
    "rutube.ru", "kinopoisk.ru", "avito.ru", "2gis.ru", "kaspersky.com", "kaspersky.ru",
    "cdnvideo.ru", "selectel.ru", "timeweb.com", "beget.com", "mts.ru", "megafon.ru",
    "yota.ru", "tele2.ru", "t2.ru", "rostelecom.ru", "pochta.ru", "rzd.ru", "mos.ru",
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


def safe_http_get(url, timeout=20, max_bytes=MAX_FILE_BYTES):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"Превышен лимит {max_bytes // (1024 * 1024)} МБ")
        if b"\x00" in data[:1024]:
            raise ValueError("Бинарный файл")
        return data.decode("utf-8", errors="ignore")


def load_geo():
    try:
        raw = safe_http_get(GEO_CSV_URL, timeout=60, max_bytes=MAX_GEO_BYTES)
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
    text = safe_http_get(url, 20)
    sample = text[:512].lstrip().lower()
    if sample.startswith("<!doctype html") or sample.startswith("<html"):
        raise ValueError("Получен HTML вместо списка")

    if "vless://" not in text.lower() and not CIDR_RE.search(text[:200]):
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
        if line.lower().startswith("vless://"):
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
        return {}


def save_history(history):
    now = time.time()
    cleaned = {
        k: v for k, v in history.items()
        if isinstance(v, dict) and now - v.get("seen", 0) < 14 * 86400
    }
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(cleaned, f, indent=1)


def parse_vless_mobile(link):
    link = link.strip()
    if not link.lower().startswith("vless://"):
        return None
    try:
        u = urllib.parse.urlparse(link)
        params = {k: v[0] for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}
        uuid, host, port = u.username or "", u.hostname or "", u.port
    except Exception:
        return None

    if port != 443:
        return None
    if not UUID_RE.match(uuid) or not HOST_RE.match(host):
        return None
    if params.get("encryption", "none") != "none":
        return None

    security = params.get("security", "")
    if security != "reality":
        return None

    net = params.get("type", "tcp")
    if net not in ("tcp", "grpc", "ws"):
        return None

    flow = params.get("flow", "")
    if flow and (flow != "xtls-rprx-vision" or net != "tcp"):
        return None

    fp = params.get("fp", "chrome")
    if not fp or fp not in ALLOWED_FP:
        fp = "chrome"

    pbk = params.get("pbk", "")
    sid = params.get("sid", "")
    if not PBK_RE.match(pbk) or not SID_RE.match(sid):
        return None

    sni = params.get("sni") or params.get("host") or host
    if not HOST_RE.match(sni):
        return None

    outbound = {
        "type": "vless",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "tls": {
            "enabled": True,
            "server_name": sni,
            "utls": {"enabled": True, "fingerprint": fp},
            "reality": {"enabled": True, "public_key": pbk, "short_id": sid},
        },
    }
    if flow:
        outbound["flow"] = flow
    if net == "ws":
        t = {"type": "ws", "path": params.get("path", "/")}
        if params.get("host"):
            t["headers"] = {"Host": params["host"]}
        outbound["transport"] = t
    elif net == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": params.get("serviceName", "")}

    return {
        "key": f"{uuid}@{host}:{port}",
        "host": host,
        "port": port,
        "net": net,
        "has_vision": flow == "xtls-rprx-vision",
        "proto_tag": "Reality-Vision" if flow == "xtls-rprx-vision" else f"Reality-{net.upper()}",
        "sni": sni,
        "outbound": outbound,
        "link": link,
    }


def prefilter_node(node):
    host, port = node["host"], node["port"]
    try:
        ip = socket.getaddrinfo(host, port, socket.AF_INET)[0][4][0]
    except Exception:
        return "dns_fail", node

    code = country_of(ip) or "UN"
    node["entry_ip"] = ip
    node["entry_country"] = code

    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=2.2):
            pass
    except Exception:
        return "tcp_dead", node

    node["tcp_latency"] = time.monotonic() - t0
    node["sni_whitelisted"] = is_whitelist_sni(node["sni"])
    node["cidr_whitelisted"] = in_whitelist_cidr(ip)
    node["is_ru_entry"] = (code == "RU")
    node["is_whitelist"] = bool(
        node["from_wl_source"]
        or node["sni_whitelisted"]
        or node["cidr_whitelisted"]
        or node["is_ru_entry"]
    )
    return "prefilter_ok", node


def build_singbox_config(batch_nodes, base_port=20000):
    inbounds, outbounds, rules = [], [], []
    for idx, node in enumerate(batch_nodes):
        in_tag = f"in_{idx}"
        out_tag = f"out_{idx}"
        port = base_port + idx
        node["_local_port"] = port

        inbounds.append({
            "type": "mixed",
            "tag": in_tag,
            "listen": "127.0.0.1",
            "listen_port": port,
        })
        ob = dict(node["outbound"])
        ob["tag"] = out_tag
        outbounds.append(ob)
        rules.append({"inbound": [in_tag], "outbound": out_tag})

    outbounds.append({"type": "direct", "tag": "direct"})
    return {
        "log": {"level": "panic"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "direct"},
    }


def check_singbox_config_valid(singbox_bin, batch_nodes):
    if not batch_nodes:
        return []
    cfg = build_singbox_config(batch_nodes)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
        json.dump(cfg, tmp)
        tmp_path = tmp.name

    try:
        res = subprocess.run(
            [singbox_bin, "check", "-c", tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        ok = (res.returncode == 0)
    except Exception:
        ok = False
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    if ok:
        return batch_nodes
    if len(batch_nodes) == 1:
        return []
    mid = len(batch_nodes) // 2
    return (
        check_singbox_config_valid(singbox_bin, batch_nodes[:mid])
        + check_singbox_config_valid(singbox_bin, batch_nodes[mid:])
    )


def proxy_get(local_port, url, timeout=4.5):
    proxy_url = f"http://127.0.0.1:{local_port}"
    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(url, headers=UA)
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read(32768).decode("utf-8", errors="ignore")
        return resp.status, resp.geturl(), body


def verify_tunnel_and_ai(node):
    port = node["_local_port"]
    t0 = time.monotonic()
    try:
        status, _, trace_body = proxy_get(port, "https://www.cloudflare.com/cdn-cgi/trace", timeout=4.5)
        if status != 200 or "ip=" not in trace_body:
            return "tunnel_fail", node
    except Exception:
        return "tunnel_fail", node

    latency = time.monotonic() - t0
    trace_map = {}
    for line in trace_body.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            trace_map[k.strip()] = v.strip()

    exit_ip = trace_map.get("ip", "")
    exit_country = trace_map.get("loc", "").upper() or country_of(exit_ip) or node["entry_country"]

    node["latency"] = latency
    node["exit_ip"] = exit_ip
    node["exit_country"] = exit_country
    node["ai_claude"] = False
    node["ai_gemini"] = False

    if exit_country not in AI_BLOCKED_COUNTRIES:
        try:
            st, final_url, body = proxy_get(port, "https://gemini.google.com/app", timeout=4.5)
            low_body = body.lower()
            if (
                st == 200
                and "/sorry/" not in final_url
                and "not available in your country" not in low_body
                and "isn't currently supported" not in low_body
            ):
                node["ai_gemini"] = True
        except Exception:
            pass

        try:
            st, final_url, body = proxy_get(port, "https://claude.ai/login", timeout=4.5)
            low_body = body.lower()
            if (
                st == 200
                and "unavailable" not in final_url.lower()
                and "app-unavailable-in-region" not in low_body
                and "just a moment..." not in low_body
            ):
                node["ai_claude"] = True
        except Exception:
            pass

    return "tunnel_ok", node


def write_sub_pair(filename, links):
    text = "\n".join(links) + ("\n" if links else "")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(text)
    b64_name = filename.rsplit(".", 1)[0] + ".base64.txt"
    b64_text = base64.b64encode(text.encode("utf-8")).decode("ascii") + "\n"
    with open(b64_name, "w", encoding="utf-8") as f:
        f.write(b64_text)


def update_readme_stats(total, wl_count, ai_count, fast_count):
    if not os.path.exists(README_FILE):
        return
    with open(README_FILE, encoding="utf-8") as f:
        content = f.read()

    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    block = (
        "<!-- STATUS_START -->\n"
        f"- **Последнее обновление**: `{now_str}`\n"
        f"- **Всего рабочих серверов (`all.txt`)**: `{total}`\n"
        f"- **Под мобильные белые списки (`whitelist-mobile.txt` / `sub.txt`)**: `{wl_count}`\n"
        f"- **Доступ к Claude + Gemini (`ai-claude-gemini.txt`)**: `{ai_count}`\n"
        f"- **Быстрые серверы (`fast.txt`)**: `{fast_count}`\n"
        "<!-- STATUS_END -->"
    )
    if "<!-- STATUS_START -->" in content and "<!-- STATUS_END -->" in content:
        content = re.sub(
            r"<!-- STATUS_START -->.*?<!-- STATUS_END -->",
            block,
            content,
            flags=re.DOTALL,
        )
        with open(README_FILE, "w", encoding="utf-8") as f:
            f.write(content)


def main():
    global geo_starts, geo_ends, geo_codes, wl_cidr_starts, wl_cidr_ends
    geo_starts, geo_ends, geo_codes = load_geo()

    history = load_history()
    entries = read_sources()
    unique = {}
    cidr_networks = []
    source_raw_keys = {}
    stats = Counter()

    for idx, entry in enumerate(entries):
        url = entry["url"]
        tags = entry["meta"]["tags"]
        is_wl_source = (
            "whitelist" in tags
            or "priority" in tags
            or any(k in url.lower() for k in ("igareck", "zieng2", "alley", "white"))
        )
        is_cidr_source = "cidr" in tags or "cidr" in url.lower()
        source_raw_keys[idx] = set()

        try:
            proxy_lines, cidrs = fetch_source_content(url)
            cidr_networks.extend(cidrs)
            print(f"[{entry['section']:6s}] {len(proxy_lines):5d} VLESS, {len(cidrs):4d} CIDR | {url}")
        except Exception as e:
            print(f"[{entry['section']:6s}] ОШИБКА источника {url}: {e}")
            entry["_fetch_failed"] = True
            continue

        entry["_fetch_failed"] = False
        for link in proxy_lines:
            parsed = parse_vless_mobile(link)
            if not parsed:
                stats["filtered_non_mobile"] += 1
                continue
            key = parsed["key"]
            source_raw_keys[idx].add(key)

            if is_cidr_source:
                try:
                    ip_obj = ipaddress.IPv4Address(parsed["host"])
                    cidr_networks.append(ipaddress.IPv4Network(f"{ip_obj}/24", strict=False))
                except ValueError:
                    pass

            if key in unique:
                stats["duplicate"] += 1
                if is_wl_source:
                    unique[key]["from_wl_source"] = True
                continue

            parsed["from_wl_source"] = is_wl_source
            prev_hist = history.get(key, {})
            parsed["prev_streak"] = int(prev_hist.get("streak", 0)) if isinstance(prev_hist, dict) else 0
            unique[key] = parsed

    if os.path.exists(TG_POOL_FILE):
        try:
            with open(TG_POOL_FILE, encoding="utf-8") as f:
                for line in f:
                    parsed = parse_vless_mobile(line)
                    if parsed and parsed["key"] not in unique:
                        parsed["from_wl_source"] = False
                        prev_hist = history.get(parsed["key"], {})
                        parsed["prev_streak"] = int(prev_hist.get("streak", 0)) if isinstance(prev_hist, dict) else 0
                        unique[parsed["key"]] = parsed
        except Exception:
            pass

    wl_cidr_starts, wl_cidr_ends = rebuild_cidr_index(cidr_networks)
    print(f"Индекс CIDR белых списков: {len(wl_cidr_starts)} подсетей")

    tcp_alive = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for status, node in ex.map(prefilter_node, unique.values()):
            stats[status] += 1
            if status == "prefilter_ok":
                tcp_alive.append(node)

    tcp_alive.sort(key=lambda n: (
        0 if (n["sni_whitelisted"] or n["cidr_whitelisted"] or n["from_wl_source"]) else 1,
        0 if n["has_vision"] else 1,
        -min(n["prev_streak"], 10),
        n["tcp_latency"],
    ))

    candidates = tcp_alive[:MAX_CANDIDATES_FOR_SINGBOX]
    print(f"Отобрано лучших мобильных кандидатов: {len(candidates)} из {len(tcp_alive)} живых по TCP")

    singbox_bin = shutil.which("sing-box")
    verified = []

    if singbox_bin:
        for i in range(0, len(candidates), BATCH_SIZE):
            raw_batch = candidates[i:i + BATCH_SIZE]
            valid_batch = check_singbox_config_valid(singbox_bin, raw_batch)
            stats["config_invalid"] += len(raw_batch) - len(valid_batch)
            if not valid_batch:
                continue

            cfg = build_singbox_config(valid_batch, base_port=20000)
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
                json.dump(cfg, tmp)
                cfg_path = tmp.name

            proc = subprocess.Popen(
                [singbox_bin, "run", "-c", cfg_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                time.sleep(0.7)
                with ThreadPoolExecutor(max_workers=min(WORKERS, len(valid_batch))) as ex:
                    for st, checked_node in ex.map(verify_tunnel_and_ai, valid_batch):
                        stats[st] += 1
                        if st == "tunnel_ok":
                            verified.append(checked_node)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                if os.path.exists(cfg_path):
                    os.remove(cfg_path)
    else:
        print("WARN: sing-box не найден в PATH, используется резервный TCP-режим")
        for n in candidates:
            n["latency"] = n["tcp_latency"]
            n["exit_ip"] = n["entry_ip"]
            n["exit_country"] = n["entry_country"]
            n["ai_claude"] = n["entry_country"] not in AI_BLOCKED_COUNTRIES
            n["ai_gemini"] = n["entry_country"] not in AI_BLOCKED_COUNTRIES
            verified.append(n)

    alive_keys = {n["key"] for n in verified}
    updated_entries = []
    for idx, entry in enumerate(entries):
        meta = entry["meta"]
        working_from_src = len(source_raw_keys.get(idx, set()) & alive_keys)
        meta["last_count"] = working_from_src

        if entry.get("_fetch_failed") or working_from_src == 0:
            meta["fails"] += 1
            if entry["section"] == "MANUAL":
                meta["status"] = "dead" if entry.get("_fetch_failed") else "active"
                updated_entries.append(entry)
            else:
                if meta["fails"] < MAX_AUTO_FAILS:
                    updated_entries.append(entry)
        else:
            meta["fails"] = 0
            if entry["section"] == "MANUAL" or working_from_src >= MIN_WORKING_FOR_ACTIVE:
                meta["status"] = "active"
            updated_entries.append(entry)

    if updated_entries:
        write_sources(updated_entries)

    now_ts = time.time()
    for n in verified:
        k = n["key"]
        streak = n["prev_streak"] + 1
        history[k] = {"streak": streak, "seen": now_ts}
        n["streak"] = streak

    save_history(history)

    verified.sort(key=lambda n: (
        0 if (n["sni_whitelisted"] or n["cidr_whitelisted"]) else 1,
        0 if n["from_wl_source"] else 1,
        0 if n["has_vision"] else 1,
        0 if n["streak"] >= 2 else 1,
        n["latency"],
    ))

    for k, v in stats.most_common():
        print(f"{k}: {v}")

    if len(verified) < MIN_TOTAL:
        sys.exit(f"FATAL: живых серверов всего {len(verified)}, файлы не перезаписаны")

    all_links, wl_links, ai_links = [], [], []

    for idx, n in enumerate(verified, 1):
        base = n["link"].split("#", 1)[0]
        code = n["exit_country"]
        ms = int(n["latency"] * 1000)

        tags = [f"{flag(code)} {code}", n["proto_tag"], f"{ms}ms"]
        if n["sni_whitelisted"]:
            tags.append(f"SNI:{n['sni']}")
        elif n["is_whitelist"]:
            tags.append("WL")
        if n["ai_claude"]:
            tags.append("Claude")
        if n["ai_gemini"]:
            tags.append("Gemini")
        tags.append(f"#{idx:03d}")

        label = urllib.parse.quote(" | ".join(tags))
        formatted = f"{base}#{label}"

        all_links.append(formatted)
        if n["is_whitelist"] and len(wl_links) < MAX_MOBILE_OUT:
            wl_links.append(formatted)
        if n["ai_claude"] and n["ai_gemini"]:
            ai_links.append(formatted)

    if len(wl_links) < 20:
        for link in all_links:
            if link not in wl_links and len(wl_links) < MAX_MOBILE_OUT:
                wl_links.append(link)

    fast_nodes = sorted(verified, key=lambda x: x["latency"])[:FAST_LIMIT]
    fast_links = []
    for idx, n in enumerate(fast_nodes, 1):
        base = n["link"].split("#", 1)[0]
        code = n["exit_country"]
        ms = int(n["latency"] * 1000)
        label = urllib.parse.quote(f"{flag(code)} {code} | {n['proto_tag']} | {ms}ms | FAST #{idx:02d}")
        fast_links.append(f"{base}#{label}")

    write_sub_pair(OUT_ALL, all_links)
    write_sub_pair(OUT_WL, wl_links)
    write_sub_pair(OUT_AI, ai_links)
    write_sub_pair(OUT_FAST, fast_links)

    shutil.copyfile(OUT_WL, LEGACY_LIST)
    shutil.copyfile("whitelist-mobile.base64.txt", LEGACY_SUB)

    update_readme_stats(len(all_links), len(wl_links), len(ai_links), len(fast_links))
    print(
        f"Готово: mobile_wl={len(wl_links)} (записано в {OUT_WL} и {LEGACY_SUB}), "
        f"all={len(all_links)}, ai={len(ai_links)}, fast={len(fast_links)}"
    )


if __name__ == "__main__":
    main()
