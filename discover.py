import base64
import html
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

SOURCES_FILE = "sources.txt"
CHANNELS_FILE = "channels.txt"
CACHE_FILE = "discover_cache.json"
TG_POOL_FILE = "tg_discovered_pool.txt"

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 МБ жесткий лимит
HTTP_TIMEOUT = 15
MAX_NEW_SOURCES = 20              # максимум новых источников за один запуск
MIN_VALID_LINES_CANDIDATE = 3     # минимум валидных прокси-строк для добавления в candidate
MAX_DEPTH = 2                     # глубина рекурсивного обхода ссылок
CACHE_TTL_SEC = 3 * 86400         # 3 суток кэша для отброшенных URL
WORKERS = 12

UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")
PROXY_LINE_RE = re.compile(
    r"(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[A-Za-z0-9_\-@.:?=&/%#+~]+",
    re.IGNORECASE,
)
URL_RE = re.compile(
    r"https?://[A-Za-z0-9.\-_/~:%+@#?=&]+",
    re.IGNORECASE,
)

SKIP_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip",
    ".tar", ".gz", ".rar", ".7z", ".exe", ".apk", ".dmg", ".mp4", ".mp3",
    ".py", ".go", ".js", ".ts", ".c", ".cpp", ".rs", ".sh", ".bat", ".html",
)

GITHUB_QUERIES = [
    "vless reality russia",
    "v2ray configs sub",
    "free-vpn-configs vless",
    "xray reality sub",
    "sing-box configs",
    "whitelist russia vless",
]


def safe_http_get(url, headers=None, timeout=HTTP_TIMEOUT):
    req_headers = dict(UA)
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if any(bad in ctype for bad in ("image/", "video/", "audio/", "application/octet-stream", "application/zip")):
            raise ValueError(f"Unsupported Content-Type: {ctype}")
        clen = resp.headers.get("Content-Length")
        if clen and clen.isdigit() and int(clen) > MAX_FILE_BYTES:
            raise ValueError(f"File too large: {clen} bytes")
        data = resp.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise ValueError("File exceeds 5 MB limit")
        if b"\x00" in data[:1024]:
            raise ValueError("Binary file detected")
        return data.decode("utf-8", errors="ignore")


def maybe_decode_base64(text):
    stripped = "".join(text.split())
    if not stripped or len(stripped) < 32:
        return text
    if any(p in text for p in PROTOCOLS):
        return text
    try:
        padded = stripped + "=" * (-len(stripped) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        if any(p in decoded for p in PROTOCOLS):
            return decoded
    except Exception:
        pass
    return text


def is_html(text):
    sample = text[:1000].lstrip().lower()
    return sample.startswith("<!doctype html") or sample.startswith("<html") or "<body" in sample


def normalize_sub_url(url):
    url = url.strip().rstrip(".,;)'\"<>]")
    if not url.startswith(("http://", "https://")) or not url.isascii():
        return None
    parsed = urllib.parse.urlparse(url)
    if not parsed.netloc or parsed.netloc in ("github.com", "t.me", "telegram.me"):
        # Конвертируем github blob в raw
        if parsed.netloc == "github.com" and "/blob/" in parsed.path:
            raw_path = parsed.path.replace("/blob/", "/")
            return f"https://raw.githubusercontent.com{raw_path}"
        return None
    lower_path = parsed.path.lower()
    if any(lower_path.endswith(ext) for ext in SKIP_EXTENSIONS):
        return None
    return url


def extract_proxies_and_links(text):
    decoded = maybe_decode_base64(text)
    proxies = []
    for line in decoded.splitlines():
        line = line.strip()
        if line.lower().startswith(PROTOCOLS) and len(line) < 2048:
            proxies.append(line)
    if not proxies:
        proxies = [m.group(0) for m in PROXY_LINE_RE.finditer(decoded)]

    links = set()
    for m in URL_RE.finditer(text):
        u = normalize_sub_url(m.group(0))
        if u:
            links.add(u)
    return proxies, links


def load_sources_file():
    if not os.path.exists(SOURCES_FILE):
        return [], []
    with open(SOURCES_FILE, encoding="utf-8") as f:
        raw_lines = f.read().splitlines()

    manual_lines = []
    auto_entries = []
    mode = "MANUAL"

    for line in raw_lines:
        stripped = line.strip()
        if stripped == "# MANUAL":
            mode = "MANUAL"
            continue
        if stripped == "# AUTO":
            mode = "AUTO"
            continue
        if mode == "MANUAL":
            manual_lines.append(line)
        else:
            if not stripped or stripped.startswith("#"):
                continue
            url = stripped.split("#", 1)[0].strip()
            meta = stripped.split("#", 1)[1].strip() if "#" in stripped else "tags=auto status=candidate fails=0 last_count=0"
            auto_entries.append((url, meta))

    return manual_lines, auto_entries


def save_sources_file(manual_lines, auto_entries):
    out = []
    has_manual_header = any(l.strip() == "# MANUAL" for l in manual_lines)
    if not has_manual_header:
        out.append("# MANUAL")
    out.extend(manual_lines)
    if out and out[-1].strip() != "":
        out.append("")
    out.append("# AUTO")
    for url, meta in auto_entries:
        out.append(f"{url} # {meta}")
    with open(SOURCES_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


def load_cache():
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, encoding="utf-8") as f:
            data = json.load(f)
        now = time.time()
        return {k: v for k, v in data.items() if now - v.get("ts", 0) < CACHE_TTL_SEC}
    except Exception:
        return {}


def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=1)


def github_api_search():
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    found_urls = set()
    readme_Check_repos = []

    for q in GITHUB_QUERIES:
        encoded_q = urllib.parse.quote(q)
        api_url = f"https://api.github.com/search/repositories?q={encoded_q}&sort=updated&per_page=10"
        try:
            raw = safe_http_get(api_url, headers=headers, timeout=15)
            payload = json.loads(raw)
            for repo in payload.get("items", []):
                full_name = repo.get("full_name")
                default_branch = repo.get("default_branch", "main")
                if full_name:
                    readme_Check_repos.append((full_name, default_branch))
            time.sleep(1.5)
        except Exception as e:
            print(f"[GitHub Search] Пропуск запроса '{q}': {e}")

    for full_name, branch in readme_Check_repos[:25]:
        readme_url = f"https://raw.githubusercontent.com/{full_name}/{branch}/README.md"
        try:
            text = safe_http_get(readme_url, timeout=10)
            _, links = extract_proxies_and_links(text)
            found_urls.update(links)
        except Exception:
            pass

    return found_urls


def scrape_telegram_channels():
    if not os.path.exists(CHANNELS_FILE):
        return set(), set()

    with open(CHANNELS_FILE, encoding="utf-8") as f:
        channels = [
            l.split("#", 1)[0].strip().lstrip("@")
            for l in f
            if l.strip() and not l.strip().startswith("#")
        ]

    sub_links = set()
    direct_proxies = set()

    for ch in channels:
        if not re.match(r"^[A-Za-z0-9_]{4,64}$", ch):
            continue
        url = f"https://t.me/s/{ch}"
        try:
            raw_html = safe_http_get(url, timeout=12)
            clean_text = html.unescape(re.sub(r"<[^>]+>", "\n", raw_html))
            proxies, links = extract_proxies_and_links(clean_text)
            direct_proxies.update(proxies)
            sub_links.update(links)
        except Exception as e:
            print(f"[Telegram] Канал {ch} недоступен: {e}")

    return sub_links, direct_proxies


def probe_candidate(url):
    try:
        text = safe_http_get(url, timeout=HTTP_TIMEOUT)
    except Exception:
        return url, 0, set()
    if is_html(text):
        return url, 0, set()
    proxies, nested_links = extract_proxies_and_links(text)
    return url, len(set(proxies)), nested_links


def main():
    manual_lines, auto_entries = load_sources_file()
    existing_urls = set()

    for line in manual_lines:
        s = line.strip()
        if s and not s.startswith("#"):
            existing_urls.add(s.split("#", 1)[0].strip())
    for url, _ in auto_entries:
        existing_urls.add(url)

    cache = load_cache()
    candidate_Queue = set()

    # 1. GitHub Search + README/Awesome
    gh_links = github_api_search()
    candidate_Queue.update(gh_links)

    # 2. Telegram каналы
    tg_links, tg_proxies = scrape_telegram_channels()
    candidate_Queue.update(tg_links)

    if tg_proxies:
        with open(TG_POOL_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(tg_proxies)) + "\n")
        print(f"[Telegram] Собрано прямых конфигов в {TG_POOL_FILE}: {len(tg_proxies)}")

    # 3. Обход вложенных ссылок до глубины MAX_DEPTH
    visited = set(existing_urls) | set(cache.keys())
    valid_new = []

    current_level = [u for u in candidate_Queue if u not in visited]
    for depth in range(1, MAX_DEPTH + 1):
        if not current_level or len(valid_new) >= MAX_NEW_SOURCES:
            break
        batch = current_level[:80]
        for u in batch:
            visited.add(u)
        next_level = set()

        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            for url, count, nested in ex.map(probe_candidate, batch):
                cache[url] = {"ts": time.time(), "count": count}
                if count >= MIN_VALID_LINES_CANDIDATE:
                    if len(valid_new) < MAX_NEW_SOURCES:
                        valid_new.append((url, count))
                elif depth < MAX_DEPTH and nested:
                    for nu in nested:
                        if nu not in visited:
                            next_level.add(nu)

        current_level = list(next_level)

    for url, count in valid_new:
        meta = f"tags=auto status=candidate fails=0 last_count={count}"
        auto_entries.append((url, meta))

    save_sources_file(manual_lines, auto_entries)
    save_cache(cache)

    print("=== ОТЧЕТ DISCOVER.PY ===")
    print(f"Проверено кандидатов: {len(visited) - len(existing_urls)}")
    print(f"Добавлено новых источников (candidate): {len(valid_new)}")
    for url, count in valid_new:
        print(f"  + [{count:4d} конфигов] {url}")


if __name__ == "__main__":
    main()
