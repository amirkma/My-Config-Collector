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

MAX_MESSAGES = 100
CONFIGS = {
    "ss": "",
    "vmess": "",
    "trojan": "",
    "vless": "",
    "mixed": "",
    "proxy": ""  # فولدر جدید برای پروکسی تلگرام
}
CONFIG_FILE_IDS = {
    "ss": 0,
    "vmess": 0,
    "trojan": 0,
    "vless": 0,
    "mixed": 0,
    "proxy": 0
}
MY_REGEX = {
    "ss": r'(?m)(...ss:|^ss:)\/\/.+?(%3A%40|#|$)',
    "vmess": r'(?m)vmess:\/\/.+',
    "trojan": r'(?m)trojan:\/\/.+?(%3A%40|#|$)',
    "vless": r'(?m)vless:\/\/.+?(%3A%40|#|$)'
}
PROXY_REGEX = r'(?m)tg:\/\/proxy\/.+|mtproto:\/\/.+|socks5:\/\/.+|https:\/\/t.me\/proxy\?.+'  # regex برای پروکسی تلگرام (tg://proxy, mtproto, socks5 از ت.me/proxy)

def change_url_to_telegram_web_url(url):
    if url.startswith("https://t.me/"):
        return url.replace("https://t.me/", "https://t.me/s/")
    elif url.startswith("@"):
        return f"https://t.me/s/{url.lstrip('@')}"
    return url

def http_request(url):
    headers = {"User-Agent": "Mozilla/5.0"}
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    return resp

def extract_config(txt, temp_configs):
    for regex_value in MY_REGEX.values():
        match = re.search(regex_value, txt)
        if match:
            config = match.group(0)
            temp_configs.append(config)
            txt = txt.replace(config, "")
            return extract_config(txt, temp_configs)
    return "\n".join(temp_configs)

def extract_proxy(txt, temp_configs):
    match = re.search(PROXY_REGEX, txt)
    if match:
        proxy = match.group(0)
        temp_configs.append(proxy)
        txt = txt.replace(proxy, "")
        return extract_proxy(txt, temp_configs)
    return "\n".join(temp_configs)

def crawl_for_v2ray(channel_url, all_messages_flag, channel_name):
    channel_url = change_url_to_telegram_web_url(channel_url)
    resp = http_request(channel_url)
    soup = BeautifulSoup(resp.text, 'html.parser')

    messages = soup.select(".tgme_widget_message_wrap")
    if len(messages) < MAX_MESSAGES:
        last_post = soup.select_one(".tgme_widget_message_wrap .js-widget_message:last-child")
        if last_post:
            post_id = last_post.get("data-post", "").split("/")[-1]
            soup = get_messages(MAX_MESSAGES, soup, post_id, channel_url)

    selector = "code, pre" if not all_messages_flag else ".tgme_widget_message_text"
    for elem in soup.select(selector):
        message_text = elem.get_text().replace("<br>", "\n")
        lines = message_text.split("\n")
        for data in lines:
            # استخراج کانفیگ‌های V2Ray و غیره
            extracted = extract_config(data.strip(), [])
            if extracted:
                configs_for_line = extracted.split("\n")
                for conf in configs_for_line:
                    if conf.strip():
                        proto = "mixed"
                        if not all_messages_flag:
                            for p, reg in MY_REGEX.items():
                                if re.match(reg, conf):
                                    proto = p
                                    break
                        CONFIGS[proto] += conf.strip() + "|SEP|" + channel_name + "\n"
                        CONFIGS["mixed"] += conf.strip() + "|SEP|" + channel_name + "\n"

            # استخراج پروکسی تلگرام
            extracted_proxy = extract_proxy(data.strip(), [])
            if extracted_proxy:
                proxies_for_line = extracted_proxy.split("\n")
                for proxy in proxies_for_line:
                    if proxy.strip():
                        CONFIGS["proxy"] += proxy.strip() + "|SEP|" + channel_name + "\n"

def get_messages(length, soup, number, channel):
    url = f"{channel}?before={number}"
    resp = http_request(url)
    new_soup = BeautifulSoup(resp.text, 'html.parser')
    soup.select_one("body").append(new_soup.select_one("body"))
    if len(soup.select(".js-widget_message_wrap")) > length:
        return soup
    num = int(number) - 21
    if num > 0:
        return get_messages(length, soup, str(num), channel)
    return soup

def add_config_names(config, config_type):
    lines = config.split("\n")
    new_configs = ""
    for line in lines:
        if not line:
            continue
        parts = line.split("|SEP|")
        extracted_config = parts[0]
        channel_name = parts[1] if len(parts) > 1 else "Unknown"
        if extracted_config.startswith("vmess://"):
            formatted = edit_vmess_ps(extracted_config, config_type, channel_name)
            if formatted:
                new_configs += formatted + "\n"
        else:
            CONFIG_FILE_IDS[config_type] += 1
            clean_config = extracted_config.split("#")[0]
            new_configs += f"{clean_config}#{channel_name}-{CONFIG_FILE_IDS[config_type]}\n"
    return new_configs

def edit_vmess_ps(config, file_name, channel_name):
    slice_ = config.split("vmess://")
    if len(slice_) < 2:
        return ""
    try:
        decoded = base64.b64decode(slice_[1])
        data = json.loads(decoded)
        CONFIG_FILE_IDS[file_name] += 1
        data["ps"] = f"{channel_name}-{CONFIG_FILE_IDS[file_name]}"
        json_data = json.dumps(data)
        return "vmess://" + base64.b64encode(json_data.encode()).decode()
    except:
        return ""

def remove_duplicates(text):
    lines = set(text.split("\n"))
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sort", action="store_true", help="sort from latest to oldest")
    args = parser.parse_args()

    df = pd.read_csv("channels.csv")
    channels = df.to_dict(orient="records")

    for channel in channels:
        url = channel.get("URL", "")
        all_flag = channel.get("AllMessagesFlag", False)
        parts = url.rstrip("/").split("/")
        channel_name = parts[-1]
        logger.info(f"Crawling {url}")
        crawl_for_v2ray(url, all_flag, channel_name)
        logger.info(f"Crawled {url}!")

    logger.info("Creating output files!")
    os.makedirs("configs", exist_ok=True)
    for proto, config_content in CONFIGS.items():
        unique = remove_duplicates(config_content)
        final_output = add_config_names(unique, proto)
        final_output = final_output.strip()
        file_name = f"proxies_iran.txt" if proto == "proxy" else f"{proto}_iran.txt"
        with open(f"configs/{file_name}", "w", encoding="utf-8") as f:
            f.write(final_output)
        logger.info(f"Saved {file_name}")

    logger.info("All Done :D")

if __name__ == "__main__":
    main()
