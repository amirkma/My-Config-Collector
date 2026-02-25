import requests
import re
import json
import base64
import pandas as pd
from bs4 import BeautifulSoup
import os
import argparse
import logging
from collections import defaultdict

# ================= CONFIG =================

MAX_MESSAGES = 100
MAX_CONFIGS_PER_CHANNEL_LIGHT = 10
HEADERS = {"User-Agent": "Mozilla/5.0"}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CONFIGS = {
    "ss": "",
    "vmess": "",
    "trojan": "",
    "vless": "",
    "mixed": "",
    "mixed-light": "",
    "proxy": ""
}

CONFIG_FILE_IDS = defaultdict(int)
LIGHT_COUNTER = defaultdict(int)

# ================= REGEX =================

REGEX = {
    "vmess": re.compile(r'vmess://[A-Za-z0-9+/=]+'),
    "vless": re.compile(r'vless://[^\s#]+'),
    "trojan": re.compile(r'trojan://[^\s#]+'),
    "ss": re.compile(r'ss://[^\s#]+'),
}

PROXY_REGEX = re.compile(
    r'(tg://proxy/\S+|tg://socks\?\S+|mtproto://\S+|socks5://\S+)'
)

# ================= UTILS =================

def change_url_to_telegram_web(url: str) -> str:
    if url.startswith("@"):
        return f"https://t.me/s/{url[1:]}"
    if url.startswith("https://t.me/") and "/s/" not in url:
        return url.replace("https://t.me/", "https://t.me/s/")
    return url

def http_get(url: str) -> str:
    r = requests.get(url, headers=HEADERS, timeout=15)
    r.raise_for_status()
    return r.text

def remove_duplicates_preserve_order(text: str) -> str:
    seen = set()
    out = []
    for line in text.splitlines():
        if line and line not in seen:
            seen.add(line)
            out.append(line)
    return "\n".join(out)

# ================= EXTRACTION =================

def extract_configs(text: str):
    results = []
    for proto, regex in REGEX.items():
        for match in regex.findall(text):
            results.append((proto, match))
    return results

def extract_proxies(text: str):
    return PROXY_REGEX.findall(text)

# ================= TELEGRAM CRAWLER =================

def get_more_messages(base_soup, channel_url, last_id):
    url = f"{channel_url}?before={last_id}"
    soup = BeautifulSoup(http_get(url), "html.parser")
    base_soup.body.extend(soup.body.contents)
    return base_soup

def crawl_channel(channel_url, all_messages, channel_name):
    channel_url = change_url_to_telegram_web(channel_url)
    soup = BeautifulSoup(http_get(channel_url), "html.parser")

    messages = soup.select(".tgme_widget_message_wrap")
    if len(messages) < MAX_MESSAGES:
        last = soup.select_one(".tgme_widget_message_wrap:last-child")
        if last and last.get("data-post"):
            last_id = last["data-post"].split("/")[-1]
            soup = get_more_messages(soup, channel_url, last_id)

    selector = ".tgme_widget_message_text" if all_messages else "code, pre"

    for msg in soup.select(selector):
        text = msg.get_text("\n", strip=True)
        links = [a["href"] for a in msg.find_all("a", href=True)]

        # ---- CONFIGS ----
        for proto, conf in extract_configs(text):
            add_config(conf, proto, channel_name)

        # ---- PROXIES ----
        for proxy in extract_proxies(text + " " + " ".join(links)):
            add_config(proxy, "proxy", channel_name)

# ================= STORAGE =================

def add_config(conf, proto, channel):
    line = f"{conf}|SEP|{channel}\n"

    CONFIGS[proto] += line
    CONFIGS["mixed"] += line

    if LIGHT_COUNTER[channel] < MAX_CONFIGS_PER_CHANNEL_LIGHT:
        CONFIGS["mixed-light"] += line
        LIGHT_COUNTER[channel] += 1

# ================= FORMAT OUTPUT =================

def edit_vmess_ps(config, name):
    try:
        raw = base64.b64decode(config.replace("vmess://", "")).decode()
        data = json.loads(raw)
        CONFIG_FILE_IDS[name] += 1
        data["ps"] = f"{data.get('ps','node')}-{CONFIG_FILE_IDS[name]}"
        new = base64.b64encode(json.dumps(data).encode()).decode()
        return "vmess://" + new
    except:
        return ""

def add_names(text, proto):
    out = []
    for line in text.splitlines():
        conf, channel = line.split("|SEP|")
        if conf.startswith("vmess://"):
            fixed = edit_vmess_ps(conf, proto)
            if fixed:
                out.append(fixed)
        else:
            CONFIG_FILE_IDS[proto] += 1
            clean = conf.split("#")[0]
            out.append(f"{clean}#{channel}-{CONFIG_FILE_IDS[proto]}")
    return "\n".join(out)

# ================= MAIN =================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sort", action="store_true")
    args = parser.parse_args()

    df = pd.read_csv("channels.csv")
    channels = df.to_dict(orient="records")

    for ch in channels:
        url = ch["URL"]
        all_flag = ch.get("AllMessagesFlag", False)
        name = url.rstrip("/").split("/")[-1]
        logger.info(f"Crawling {name}")
        crawl_channel(url, all_flag, name)

    os.makedirs("configs", exist_ok=True)

    for proto, content in CONFIGS.items():
        content = remove_duplicates_preserve_order(content)
        content = add_names(content, proto)
        fname = "proxies-all.txt" if proto == "proxy" else f"{proto}-all.txt"
        with open(f"configs/{fname}", "w", encoding="utf-8") as f:
            f.write(content.strip())
        logger.info(f"Saved {fname}")

    logger.info("DONE ✔")

if __name__ == "__main__":
    main()
