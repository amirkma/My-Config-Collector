import requests
import re
import json
import base64
import pandas as pd
from bs4 import BeautifulSoup
import os
import argparse
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_MESSAGES = 200  # افزایش برای پوشش بیشتر
MAX_CONFIGS_PER_CHANNEL_LIGHT = 10

CONFIGS = {
    "ss": "",
    "vmess": "",
    "trojan": "",
    "vless": "",
    "mixed": "",
    "mixed-light": "",
    "proxy": ""
}
CONFIG_FILE_IDS = {
    "ss": 0,
    "vmess": 0,
    "trojan": 0,
    "vless": 0,
    "mixed": 0,
    "mixed-light": 0,
    "proxy": 0
}

# regexهای بهبودیافته بر اساس استانداردهای V2Ray (از منابع مثل Sub-Config-Extractor و wikiها)
MY_REGEX = {
    "ss": r'(?i)ss://(?:[A-Za-z0-9+/=]+@)?[\w\.-]+:\d+(?:#[^#\n\r]*)?',
    "vmess": r'(?i)vmess://[A-Za-z0-9+/=]+',
    "trojan": r'(?i)trojan://(?:[^@#\n\r]+@)?[\w\.-]+:\d+(?:\?[^#\n\r]*)?(?:#[^#\n\r]*)?',
    "vless": r'(?i)vless://(?:[0-9a-f-]+@)?[\w\.-]+:\d+(?:\?[^#\n\r]*)?(?:#[^#\n\r]*)?'
}

PROXY_REGEX = r'(?i)(tg://(?:proxy|socks)\?.+|mtproto://.+|socks5://.+|https?://t.me/proxy\?.+)'

def change_url_to_telegram_web_url(url):
    if url.startswith("https://t.me/"):
        return url.replace("https://t.me/", "https://t.me/s/")
    elif url.startswith("@"):
        return f"https://t.me/s/{url.lstrip('@')}"
    return url

def http_request(url):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp
    except requests.RequestException as e:
        logger.error(f"Error fetching {url}: {e}")
        return None

def extract_configs(text):
    all_configs = []
    for proto, regex in MY_REGEX.items():
        matches = re.findall(regex, text)
        for match in matches:
            all_configs.append((proto, match))
    return all_configs

def extract_proxies(text, hrefs):
    matches = re.findall(PROXY_REGEX, text)
    for href in hrefs:
        if re.match(PROXY_REGEX, href):
            matches.append(href)
    return list(set(matches))  # حذف duplicate زودرس

def crawl_for_v2ray(channel_url, all_messages_flag, channel_name):
    channel_url = change_url_to_telegram_web_url(channel_url)
    resp = http_request(channel_url)
    if not resp:
        return
    soup = BeautifulSoup(resp.text, 'html.parser')

    messages = soup.select(".tgme_widget_message_wrap")
    loaded_messages = len(messages)
    if loaded_messages < MAX_MESSAGES:
        last_post = soup.select_one(".tgme_widget_message_wrap .js-widget_message:last-child")
        if last_post:
            post_id = last_post.get("data-post", "").split("/")[-1]
            soup = get_messages(MAX_MESSAGES, soup, post_id, channel_url)

    selector = "code, pre" if not all_messages_flag else ".tgme_widget_message_text"
    light_count = 0

    for elem in soup.select(selector):
        message_text = elem.get_text().replace("<br>", "\n").strip()
        hrefs = [a.get('href', '') for a in elem.find_all('a') if 'href' in a.attrs]

        # استخراج configs
        extracted_configs = extract_configs(message_text)
        for proto, conf in extracted_configs:
            if conf.strip():
                CONFIGS[proto] += conf.strip() + "|SEP|" + channel_name + "\n"
                CONFIGS["mixed"] += conf.strip() + "|SEP|" + channel_name + "\n"
                if light_count < MAX_CONFIGS_PER_CHANNEL_LIGHT:
                    CONFIGS["mixed-light"] += conf.strip() + "|SEP|" + channel_name + "\n"
                    light_count += 1

        # استخراج proxies
        extracted_proxies = extract_proxies(message_text, hrefs)
        for proxy in extracted_proxies:
            if proxy.strip():
                CONFIGS["proxy"] += proxy.strip() + "|SEP|" + channel_name + "\n"
                CONFIGS["mixed"] += proxy.strip() + "|SEP|" + channel_name + "\n"
                if light_count < MAX_CONFIGS_PER_CHANNEL_LIGHT:
                    CONFIGS["mixed-light"] += proxy.strip() + "|SEP|" + channel_name + "\n"
                    light_count += 1

def get_messages(target_length, soup, post_id, channel):
    if not post_id:
        return soup
    url = f"{channel}?before={post_id}"
    resp = http_request(url)
    if not resp:
        return soup
    new_soup = BeautifulSoup(resp.text, 'html.parser')
    new_messages = new_soup.select(".tgme_widget_message_wrap")
    if new_messages:
        soup.select_one("body").append(new_soup.select_one("body"))
    current_length = len(soup.select(".tgme_widget_message_wrap"))
    if current_length >= target_length or not new_messages:
        return soup
    last_post = soup.select_one(".tgme_widget_message_wrap .js-widget_message:last-child")
    if last_post:
        new_post_id = last_post.get("data-post", "").split("/")[-1]
        if new_post_id == post_id:  # جلوگیری از لوپ
            return soup
        return get_messages(target_length, soup, new_post_id, channel)
    return soup

def normalize_config(conf):
    if conf.startswith("vmess://"):
        try:
            decoded = base64.b64decode(conf[8:])
            data = json.loads(decoded)
            return json.dumps(data, sort_keys=True)
        except:
            pass
    return conf.split("#")[0]

def remove_duplicates(text):
    lines = text.strip().split("\n")
    seen = set()
    unique_lines = []
    for line in lines:
        if not line:
            continue
        conf, sep, channel = line.partition("|SEP|")
        norm = normalize_config(conf)
        if norm not in seen:
            seen.add(norm)
            unique_lines.append(line)
    return "\n".join(unique_lines)

def add_config_names(config, config_type):
    lines = config.split("\n")
    new_configs = []
    for line in lines:
        if not line:
            continue
        parts = line.split("|SEP|")
        extracted_config = parts[0]
        channel_name = parts[1] if len(parts) > 1 else "Unknown"
        if extracted_config.startswith("vmess://"):
            formatted = edit_vmess_ps(extracted_config, config_type, channel_name)
            if formatted:
                new_configs.append(formatted)
        else:
            CONFIG_FILE_IDS[config_type] += 1
            clean_config = extracted_config.split("#")[0].rstrip()
            new_configs.append(f"{clean_config}#{channel_name}-{CONFIG_FILE_IDS[config_type]}")
    return "\n".join(new_configs)

def edit_vmess_ps(config, config_type, channel_name):
    if not config.startswith("vmess://"):
        return ""
    try:
        decoded = base64.b64decode(config[8:])
        data = json.loads(decoded)
        CONFIG_FILE_IDS[config_type] += 1
        data["ps"] = f"{channel_name}-{CONFIG_FILE_IDS[config_type]}"
        json_data = json.dumps(data)
        return "vmess://" + base64.b64encode(json_data.encode()).decode()
    except Exception as e:
        logger.warning(f"Error editing vmess: {e}")
        return ""

def main():
    parser = argparse.ArgumentParser(description="Telegram Channel V2Ray Config Crawler")
    parser.add_argument("--sort", action="store_true", help="sort from latest to oldest (not implemented yet)")
    args = parser.parse_args()

    try:
        df = pd.read_csv("channels.csv")
        channels = df.to_dict(orient="records")
    except FileNotFoundError:
        logger.error("channels.csv not found!")
        return

    for channel in channels:
        url = channel.get("URL", "")
        if not url:
            continue
        all_flag = channel.get("AllMessagesFlag", False)
        channel_name = url.rstrip("/").split("/")[-1].lstrip("@")
        logger.info(f"Crawling {url}")
        crawl_for_v2ray(url, all_flag, channel_name)
        logger.info(f"Crawled {url}!")

    logger.info("Creating output files!")
    os.makedirs("configs", exist_ok=True)
    for proto, config_content in CONFIGS.items():
        if not config_content:
            continue
        unique = remove_duplicates(config_content)
        final_output = add_config_names(unique, proto)
        final_output = final_output.strip()
        file_name = f"proxies-all.txt" if proto == "proxy" else f"{proto}-all.txt"
        with open(f"configs/{file_name}", "w", encoding="utf-8") as f:
            f.write(final_output)
        logger.info(f"Saved {file_name}")

    logger.info("All Done :D")

if __name__ == "__main__":
    main()
