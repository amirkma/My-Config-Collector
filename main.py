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

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MAX_MESSAGES = 200
MAX_CONFIGS_PER_CHANNEL_LIGHT = 10

CONFIGS = defaultdict(str)  # راحت‌تر مدیریت می‌شه

CONFIG_FILE_IDS = defaultdict(int)

MY_REGEX = {
    "ss": r'(?i)(?:ss|shadowsocks)://[^\s#|]+(?:#[^\s|]*)?',
    "vmess": r'(?i)vmess://[A-Za-z0-9+/=_-]+',
    "trojan": r'(?i)trojan://[^\s#|]+(?:#[^\s|]*)?',
    "vless": r'(?i)vless://[^\s#|]+(?:#[^\s|]*)?'
}

PROXY_REGEX = r'(?i)(?:tg://(?:proxy|socks)\?.+|mtproto://.+|socks5://.+|https?://t\.me/proxy\?.+)'

def change_url_to_telegram_web_url(url):
    url = url.strip()
    if url.startswith("https://t.me/"):
        return url.replace("https://t.me/", "https://t.me/s/")
    elif url.startswith("@"):
        return f"https://t.me/s/{url.lstrip('@')}"
    return url

def http_request(url):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        resp = requests.get(url, headers=headers, timeout=12)
        resp.raise_for_status()
        return resp
    except Exception as e:
        logger.error(f"Request failed: {url} → {e}")
        return None

def extract_configs(text):
    found = defaultdict(list)
    for proto, regex in MY_REGEX.items():
        matches = re.findall(regex, text)
        found[proto].extend(matches)
    return found

def extract_proxies(text, hrefs):
    matches = re.findall(PROXY_REGEX, text)
    for h in hrefs:
        if re.match(PROXY_REGEX, h):
            matches.append(h)
    return list(set(matches))

def crawl_for_v2ray(channel_url, all_messages_flag, channel_name):
    channel_url = change_url_to_telegram_web_url(channel_url)
    resp = http_request(channel_url)
    if not resp:
        return

    soup = BeautifulSoup(resp.text, 'html.parser')

    # بارگذاری بیشتر پیام‌ها
    if len(soup.select(".tgme_widget_message_wrap")) < MAX_MESSAGES:
        last_msg = soup.select_one(".tgme_widget_message_wrap:last-child .js-widget_message")
        if last_msg and (pid := last_msg.get("data-post", "").split("/")[-1]):
            soup = get_messages(MAX_MESSAGES, soup, pid, channel_url)

    selector = ".tgme_widget_message_text" if all_messages_flag else "code, pre, .tgme_widget_message_text"
    light_count = 0

    channel_stats = defaultdict(int)  # آمار این کانال

    for elem in soup.select(selector):
        text = elem.get_text(separator="\n", strip=True)
        hrefs = [a.get('href', '') for a in elem.find_all('a')]

        # configs
        extracted = extract_configs(text)
        for proto, confs in extracted.items():
            for conf in confs:
                conf = conf.strip()
                if not conf:
                    continue
                CONFIGS[proto] += conf + "|SEP|" + channel_name + "\n"
                CONFIGS["mixed"] += conf + "|SEP|" + channel_name + "\n"
                channel_stats[proto] += 1
                channel_stats["mixed"] += 1
                if light_count < MAX_CONFIGS_PER_CHANNEL_LIGHT:
                    CONFIGS["mixed-light"] += conf + "|SEP|" + channel_name + "\n"
                    light_count += 1

        # proxies
        proxies = extract_proxies(text, hrefs)
        for p in proxies:
            p = p.strip()
            if not p:
                continue
            CONFIGS["proxy"] += p + "|SEP|" + channel_name + "\n"
            CONFIGS["mixed"] += p + "|SEP|" + channel_name + "\n"
            channel_stats["proxy"] += 1
            channel_stats["mixed"] += 1
            if light_count < MAX_CONFIGS_PER_CHANNEL_LIGHT:
                CONFIGS["mixed-light"] += p + "|SEP|" + channel_name + "\n"
                light_count += 1

    # لاگ آمار کانال
    total = sum(channel_stats.values())
    if total > 0:
        stats_str = " | ".join(f"{k}: {v}" for k, v in sorted(channel_stats.items()) if v > 0)
        logger.info(f"از کانال {channel_name} پیدا شد: {stats_str} (مجموع: {total})")
    else:
        logger.warning(f"از کانال {channel_name} هیچ کانفیگی پیدا نشد!")

def get_messages(target, soup, post_id, channel):
    url = f"{channel}?before={post_id}"
    resp = http_request(url)
    if not resp:
        return soup
    new_soup = BeautifulSoup(resp.text, 'html.parser')
    new_msgs = new_soup.select(".tgme_widget_message_wrap")
    if new_msgs:
        soup.select_one("body").append(new_soup.select_one("body"))
    if len(soup.select(".tgme_widget_message_wrap")) >= target or not new_msgs:
        return soup
    last = soup.select_one(".tgme_widget_message_wrap:last-child .js-widget_message")
    if last and (new_pid := last.get("data-post", "").split("/")[-1]):
        if new_pid == post_id:
            return soup
        return get_messages(target, soup, new_pid, channel)
    return soup

def normalize_for_dedup(conf):
    conf = conf.strip()
    if conf.startswith("vmess://"):
        try:
            b64 = conf[8:].rstrip(' \n\r\t=')
            pad = (4 - len(b64) % 4) % 4
            decoded = base64.b64decode(b64 + '=' * pad)
            data = json.loads(decoded)
            return f"vmess:{data.get('add')}:{data.get('port')}:{data.get('id')}"
        except:
            return conf
    return conf.split("#")[0].strip()

def remove_duplicates(text):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    seen = set()
    result = []
    for line in lines:
        conf_part = line.split("|SEP|", 1)[0]
        norm = normalize_for_dedup(conf_part)
        if norm not in seen:
            seen.add(norm)
            result.append(line)
    return "\n".join(result)

def edit_vmess_ps(config, ctype, ch_name):
    if not config.startswith("vmess://"):
        return ""
    raw = config[8:].strip()
    raw = re.sub(r'[^A-Za-z0-9+/=_-]', '', raw)  # فقط کاراکترهای مجاز
    pad = (4 - len(raw) % 4) % 4
    raw += '=' * pad
    try:
        dec = base64.b64decode(raw)
        js = json.loads(dec)
        CONFIG_FILE_IDS[ctype] += 1
        js["ps"] = f"{ch_name}-{CONFIG_FILE_IDS[ctype]}"
        new_json = json.dumps(js, separators=(',', ':'))
        enc = base64.urlsafe_b64encode(new_json.encode()).decode().rstrip('=')
        return f"vmess://{enc}"
    except Exception:
        return ""

def add_names(config_text, ctype):
    lines = []
    for ln in config_text.splitlines():
        if not ln.strip():
            continue
        parts = ln.split("|SEP|", 1)
        conf = parts[0]
        ch = parts[1] if len(parts) > 1 else "Unknown"
        if conf.startswith("vmess://"):
            fixed = edit_vmess_ps(conf, ctype, ch)
            if fixed:
                lines.append(fixed)
        else:
            CONFIG_FILE_IDS[ctype] += 1
            clean = conf.split("#")[0].rstrip()
            lines.append(f"{clean}#{ch}-{CONFIG_FILE_IDS[ctype]}")
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sort", action="store_true")
    args = parser.parse_args()

    try:
        df = pd.read_csv("channels.csv")
    except Exception as e:
        logger.error(f"channels.csv پیدا نشد یا مشکل دارد: {e}")
        return

    for row in df.to_dict("records"):
        url = str(row.get("URL", "")).strip()
        if not url:
            continue
        all_flag = bool(row.get("AllMessagesFlag", False))
        ch_name = url.rstrip("/").split("/")[-1].lstrip("@")
        logger.info(f"شروع کراول → {ch_name} ({url})")
        crawl_for_v2ray(url, all_flag, ch_name)

    os.makedirs("configs", exist_ok=True)
    logger.info("ذخیره فایل‌ها...")

    for key, content in CONFIGS.items():
        if not content.strip():
            continue
        cleaned = remove_duplicates(content)
        final = add_names(cleaned, key)
        fname = "proxies-all.txt" if key == "proxy" else f"{key}-all.txt"
        path = f"configs/{fname}"
        with open(path, "w", encoding="utf-8") as f:
            f.write(final.strip() + "\n")
        logger.info(f"ذخیره شد: {path} ({len(final.splitlines())} کانفیگ)")

    logger.info("تموم شد ✓")

if __name__ == "__main__":
    main()
