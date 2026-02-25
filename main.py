import requests
import re
import os
import logging
from bs4 import BeautifulSoup
import pandas as pd   # ← این خط رو حتماً داشته باش
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

MY_REGEX = {
    "ss": r'(?i)(?:ss|shadowsocks)://[^\s#|]+(?:#[^\s|]*)?',
    "vmess": r'(?i)vmess://[A-Za-z0-9+/=_-]{20,}',
    "trojan": r'(?i)trojan://[^\s#|]+(?:#[^\s|]*)?',
    "vless": r'(?i)vless://[^\s#|]+(?:#[^\s|]*)?'
}

PROXY_REGEX = r'(?i)(?:tg://(?:proxy|socks)\?.+|mtproto://.+|socks5://.+|https?://t\.me/proxy\?.+)'

def change_url_to_telegram_web_url(url):
    url = url.strip()
    if url.startswith("https://t.me/"):
        return url.replace("https://t.me/", "https://t.me/s/")
    if url.startswith("@"):
        return f"https://t.me/s/{url.lstrip('@')}"
    return url

def http_request(url):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        r = requests.get(url, headers=headers, timeout=12)
        r.raise_for_status()
        return r
    except Exception as e:
        logger.error(f"خطا در دریافت {url} → {e}")
        return None

def extract_configs(text):
    found = []
    for regex in MY_REGEX.values():
        matches = re.findall(regex, text)
        found.extend([m.strip() for m in matches if m.strip()])
    return found

def extract_proxies(text, hrefs):
    matches = re.findall(PROXY_REGEX, text)
    for h in hrefs:
        if re.match(PROXY_REGEX, h):
            matches.append(h)
    return list(set([h.strip() for h in matches if h.strip()]))

def crawl_for_v2ray(channel_url, all_messages_flag, channel_name):
    url = change_url_to_telegram_web_url(channel_url)
    resp = http_request(url)
    if not resp:
        return

    soup = BeautifulSoup(resp.text, 'html.parser')

    if len(soup.select(".tgme_widget_message_wrap")) < MAX_MESSAGES:
        last_msg = soup.select_one(".tgme_widget_message_wrap:last-child .js-widget_message")
        if last_msg and (pid := last_msg.get("data-post", "").split("/")[-1]):
            soup = get_messages(MAX_MESSAGES, soup, pid, url)

    selector = ".tgme_widget_message_text" if all_messages_flag else "code, pre, .tgme_widget_message_text"
    light_count = 0
    channel_configs = 0
    channel_proxies = 0

    for elem in soup.select(selector):
        text = elem.get_text(separator="\n", strip=True)
        hrefs = [a.get("href", "") for a in elem.find_all("a")]

        # کانفیگ‌ها - خام بدون هیچ تغییری
        configs = extract_configs(text)
        for conf in configs:
            CONFIGS["mixed"] += conf + "|SEP|" + channel_name + "\n"
            proto_key = conf.split("://")[0].lower()
            if proto_key in ["ss", "vmess", "trojan", "vless"]:
                CONFIGS[proto_key] += conf + "|SEP|" + channel_name + "\n"
            channel_configs += 1
            if light_count < MAX_CONFIGS_PER_CHANNEL_LIGHT:
                CONFIGS["mixed-light"] += conf + "|SEP|" + channel_name + "\n"
                light_count += 1

        # پروکسی‌ها - فقط در proxy
        proxies = extract_proxies(text, hrefs)
        for p in proxies:
            CONFIGS["proxy"] += p + "|SEP|" + channel_name + "\n"
            channel_proxies += 1

    total = channel_configs + channel_proxies
    if total > 0:
        logger.info(f"{channel_name:20} → کانفیگ: {channel_configs} | پروکسی: {channel_proxies} | مجموع: {total}")
    else:
        logger.warning(f"{channel_name} → هیچ کانفیگی پیدا نشد")

def get_messages(target, soup, post_id, channel):
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

def remove_duplicates(text):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    seen = set()
    result = []
    for line in lines:
        conf = line.split("|SEP|", 1)[0].strip()
        if conf not in seen:
            seen.add(conf)
            result.append(line)
    return "\n".join(result)

def main():
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
        logger.info(f"شروع کراول → {ch_name}")
        crawl_for_v2ray(url, all_flag, ch_name)

    os.makedirs("configs", exist_ok=True)
    logger.info("ذخیره فایل‌ها...")

    for key in ["mixed", "mixed-light", "proxy", "ss", "vmess", "trojan", "vless"]:
        content = CONFIGS.get(key, "")
        if not content.strip():
            continue
        cleaned = remove_duplicates(content)
        fname = "proxies-all.txt" if key == "proxy" else f"{key}-all.txt"
        path = f"configs/{fname}"
        with open(path, "w", encoding="utf-8") as f:
            f.write(cleaned.strip() + "\n")
        count = len([l for l in cleaned.splitlines() if l.strip()])
        logger.info(f"ذخیره شد → {path:25} ({count} کانفیگ)")

    logger.info("کار تموم شد ✓")

if __name__ == "__main__":
    main()
