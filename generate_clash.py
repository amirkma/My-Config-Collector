import yaml
import base64
import json

INPUT_FILE = "configs/mixed-all.txt"
OUTPUT_FILE = "configs/clash.yaml"

proxies = []

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue

        if line.startswith("vmess://"):
            raw = base64.b64decode(line.replace("vmess://", "")).decode()
            data = json.loads(raw)
            proxies.append({
                "name": data.get("ps", "vmess"),
                "type": "vmess",
                "server": data["add"],
                "port": int(data["port"]),
                "uuid": data["id"],
                "alterId": int(data.get("aid", 0)),
                "cipher": "auto",
                "udp": True,
                "tls": data.get("tls") == "tls"
            })

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
    yaml.dump(config, f, allow_unicode=True)

print("clash.yaml generated ✔")
