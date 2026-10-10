import urllib.request
import base64
import re
from urllib.parse import unquote

PROTOCOLS = ("vless://", "vmess://", "ss://", "trojan://")

BLOCKED = [
    "RU", "Russia", "РФ", "CN", "China", "HK", "Hong Kong", "IR", "Iran",
    "SY", "Syria", "CU", "Cuba", "BY", "Belarus", "VE", "Venezuela",
    "MM", "Myanmar", "PK", "Pakistan", "KZ", "Kazakhstan", "EG", "Egypt",
    "IN", "India", "IQ", "Iraq", "SA", "Saudi Arabia", "AE", "United Arab Emirates",
    "VN", "Vietnam", "AZ", "Azerbaijan", "TR", "Turkey", "AF", "Afghanistan",
    "AR", "Argentina",
]

def is_blocked(link):
    # Название сервера идёт после символа # в конце ссылки
    name = unquote(link.split("#", 1)[1]) if "#" in link else ""
    for tag in BLOCKED:
        if re.search(r"(?<![A-Za-zА-Яа-я])" + re.escape(tag) + r"(?![A-Za-zА-Яа-я])", name, re.IGNORECASE):
            return True
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
        if line.startswith(PROTOCOLS) and not is_blocked(line):
            servers.add(line)

result = "\n".join(sorted(servers))
open("list.txt", "w", encoding="utf-8").write(result)
print("Серверов:", len(servers))