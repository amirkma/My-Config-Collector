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

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

MAX_MESSAGES = 200
MAX_CONFIGS_PER_CHANNEL_LIGHT = 10

CONFIGS = defaultdict(str)
CONFIG_FILE_IDS = defaultdict(int)

MY_REGEX = {
    "ss": r'(?i)(?:ss|shadowsocks)://[^\s#|]+(?:#[^\s|]*)?',
    "vmess": r'(?i)vmess://[A-Za-z0-9+/=_-]{20,}',
    "trojan": r'(?i)trojan://[^\s#|]+(?:#[^\s|]*)?',
    "vless": r'(?i)vless://[^\s#|]+(?:#[^\s|]*)?'
}

PROXY_REGEX = r'(?i)(?:tg://(?:proxy|socks)\?.+|mtproto://.+|socks5://.+|https?://t\.me/proxy\?.+)'

def change_url_to_telegram_web_url(url: str) -> str:
    url = url.strip()
    if url.startswith("https://t.me/"):
        return url.replace("https://t.me/", "https://t.me/s/")
    if url.startswith("@"):
        return f"https://t.me/s/{url.lstrip('@')}"
    return url

def http_request(url: str):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        r = requests.get(url, headers=headers, timeout=12)
        r.raise_for_status()
        return r
    except Exception as e:
        logger.error(f"خطا در دریافت {url} → {e}")
        return None

def extract_configs(text: str) -> dict:
    found = defaultdict(list)
    for proto, regex in MY_REGEX.items():
        matches = re.findall(regex, text)
        found[proto].extend([m.strip() for m in matches if m.strip()])
    return found

def extract_proxies(text: str, hrefs: list) -> list:
    matches = re.findall(PROXY_REGEX, text)
    for h in hrefs:
        if re.match(PROXY_REGEX, h):
            matches.append(h)
    return list(set(matches))

def crawl_for_v2ray(channel_url: str, all_messages_flag: bool, channel_name: str):
    url = change_url_to_telegram_web_url(channel_url)
    resp = http_request(url)
    if not resp:
        return

    soup = BeautifulSoup(resp.text, "html.parser")

    if len(soup.select(".tgme_widget_message_wrap")) < MAX_MESSAGES:
        last_msg = soup.select_one(".tgme_widget_message_wrap:last-child .js-widget_message")
        if last_msg and (pid := last_msg.get("data-post", "").split("/")[-1]):
            soup = get_messages(MAX_MESSAGES, soup, pid, url)

    selector = ".tgme_widget_message_text" if all_messages_flag else "code, pre, .tgme_widget_message_text"
    light_count = 0
    channel_stats = defaultdict(int)

    for elem in soup.select(selector):
        text = elem.get_text(separator="\n", strip=True)
        hrefs = [a.get("href", "") for a in elem.find_all("a")]

        # کانفیگ‌ها (vmess / vless / trojan / ss)
        extracted = extract_configs(text)
        for proto, confs in extracted.items():
            for conf in confs:
                CONFIGS[proto] += conf + "|SEP|" + channel_name + "\n"
                CONFIGS["mixed"] += conf + "|SEP|" + channel_name + "\n"
                channel_stats[proto] += 1
                channel_stats["mixed"] += 1
                if light_count < MAX_CONFIGS_PER_CHANNEL_LIGHT:
                    CONFIGS["mixed-light"] += conf + "|SEP|" + channel_name + "\n"
                    light_count += 1

        # پروکسی‌ها (فقط در proxy)
        proxies = extract_proxies(text, hrefs)
        for p in proxies:
            p = p.strip()
            if p:
                CONFIGS["proxy"] += p + "|SEP|" + channel_name + "\n"
                channel_stats["proxy"] += 1

    # نمایش آمار کانال
    total = sum(channel_stats.values())
    if total > 0:
        stats = " | ".join(f"{k.upper()}: {v}" for k, v in sorted(channel_stats.items()) if v > 0)
        logger.info(f"کانال {channel_name:20} → {stats}  (مجموع: {total})")
    else:
        logger.warning(f"کانال {channel_name} → هیچ کانفیگی پیدا نشد")

def get_messages(target: int, soup, post_id: str, channel: str):
    url = f"{channel}?before={post_id}"
    resp = http_request(url)
    if not resp:
        return soup

    new_soup = BeautifulSoup(resp.text, "html.parser")
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

def normalize_for_dedup(conf: str) -> str:
    conf = conf.strip()
    if conf.startswith("vmess://"):
        try:
            b64 = re.sub(r'[^A-Za-z0-9+/=_-]', '', conf[8:])
            pad = (4 - len(b64) % 4) % 4
            decoded = base64.b64decode(b64 + "=" * pad)
            data = json.loads(decoded)
            return f"vmess:{data.get('add','')}:{data.get('port','')}:{data.get('id','')}"
        except:
            return conf
    return conf.split("#")[0].strip()

def remove_duplicates(text: str) -> str:
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

def edit_vmess_ps(config: str, ctype: str, ch_name: str) -> str:
    if not config.startswith("vmess://"):
        return ""
    raw = re.sub(r'[^A-Za-z0-9+/=_-]', '', config[8:].strip())
    pad = (4 - len(raw) % 4) % 4
    raw += "=" * pad
    try:
        dec = base64.b64decode(raw)
        js = json.loads(dec)
        CONFIG_FILE_IDS[ctype] += 1
        js["ps"] = f"{ch_name}-{CONFIG_FILE_IDS[ctype]}"
        new_json = json.dumps(js, separators=(",", ":"))
        enc = base64.urlsafe_b64encode(new_json.encode()).decode().rstrip("=")
        return f"vmess://{enc}"
    except Exception:
        return ""

def add_names(config_text: str, ctype: str) -> str:
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
    parser = argparse.ArgumentParser(description="جمع‌آوری کانفیگ از کانال‌های تلگرام")
    parser.add_argument("--sort", action="store_true", help="مرتب‌سازی (فعلاً پیاده‌سازی نشده)")
    args = parser.parse_args()

    try:
        df = pd.read_csv("channels.csv")
    except Exception as e:
        logger.error(f"فایل channels.csv مشکل دارد یا پیدا نشد → {e}")
        return

    for row in df.to_dict("records"):
        url = str(row.get("URL", "")).strip()
        if not url:
            continue
        all_flag = bool(row.get("AllMessagesFlag", False))
        ch_name = url.rstrip("/").split("/")[-1].lstrip("@")
        logger.info(f"شروع → {ch_name} ({url})")
        crawl_for_v2ray(url, all_flag, ch_name)

    os.makedirs("configs", exist_ok=True)
    logger.info("ذخیره فایل‌های نهایی...")

    for key, content in list(CONFIGS.items()):
        if not content.strip():
            continue
        cleaned = remove_duplicates(content)
        final = add_names(cleaned, key)
        fname = "proxies-all.txt" if key == "proxy" else f"{key}-all.txt"
        path = f"configs/{fname}"
        with open(path, "w", encoding="utf-8") as f:
            f.write(final.strip() + "\n")
        count = len([l for l in final.splitlines() if l.strip()])
        logger.info(f"ذخیره شد → {path:25} ({count} مورد)")

    logger.info("عملیات به پایان رسید ✓")

if __name__ == "__main__":
    main()
