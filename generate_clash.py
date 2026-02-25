import yaml
import base64
import json
import re
from urllib.parse import urlparse, parse_qs

INPUT_FILE = "configs/mixed-all.txt"
OUTPUT_FILE = "configs/clash.yaml"

proxies = []

# ---------- helpers ----------

def parse_vmess(url):
    data = json.loads(base64.b64decode(url.replace("vmess://", "")).decode())
    return {
        "name": data.get("ps", "vmess"),
        "type": "vmess",
        "server": data["add"],
        "port": int(data["port"]),
        "uuid": data["id"],
        "alterId": int(data.get("aid", 0)),
        "cipher": "auto",
        "udp": True,
        "tls": data.get("tls") == "tls",
        "skip-cert-verify": True,
    }

def parse_vless(url):
    u = urlparse(url)
    qs = parse_qs(u.query)
    return {
        "name": u.fragment or "vless",
        "type": "vless",
        "server": u.hostname,
        "port": u.port,
        "uuid": u.username,
        "udp": True,
        "tls": qs.get("security", [""])[0] == "tls",
        "skip-cert-verify": True,
    }

def parse_trojan(url):
    u = urlparse(url)
    return {
        "name": u.fragment or "trojan",
        "type": "trojan",
        "server": u.hostname,
        "port": u.port,
        "password": u.username,
        "udp": True,
        "tls": True,
        "skip-cert-verify": True,
    }

def parse_ss(url):
    body = url.replace("ss://", "")
    if "#" in body:
        body, name = body.split("#", 1)
    else:
        name = "ss"

    decoded = base64.b64decode(body).decode()
    method, rest = decoded.split(":", 1)
    password, server = rest.split("@", 1)
    host, port = server.split(":")

    return {
        "name": name,
        "type": "ss",
        "server": host,
        "port": int(port),
        "cipher": method,
        "password": password,
        "udp": True,
    }

# ---------- main ----------

with open(INPUT_FILE, encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue

        try:
            if line.startswith("vmess://"):
                proxies.append(parse_vmess(line))

            elif line.startswith("vless://"):
                proxies.append(parse_vless(line))

            elif line.startswith("trojan://"):
                proxies.append(parse_trojan(line))

            elif line.startswith("ss://"):
                proxies.append(parse_ss(line))

        except Exception:
            continue  # اگر یه کانفیگ خراب بود، کل فایل نخوابه

# ---------- clash config ----------

config = {
    "port": 7890,
    "socks-port": 7891,
    "allow-lan": True,
    "mode": "rule",
    "log-level": "silent",

    "proxies": proxies,

    "proxy-groups": [
        {
            "name": "AUTO",
            "type": "url-test",
            "proxies": [p["name"] for p in proxies],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300
        }
    ],

    "rules": [
        "MATCH,AUTO"
    ]
}

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    yaml.dump(config, f, allow_unicode=True, sort_keys=False)

print(f"Generated clash.yaml with {len(proxies)} proxies ✔")
