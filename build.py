import urllib.request
import base64

PROTOCOLS = ("vless://", "vmess://", "ss://", "trojan://")

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
        if line.startswith(PROTOCOLS):
            servers.add(line)

result = "\n".join(sorted(servers))
open("list.txt", "w", encoding="utf-8").write(result)
print("Серверов:", len(servers))