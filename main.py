import requests
import re
import json
import base64
import pandas as pd
from bs4 import BeautifulSoup
import os
import argparse
import logging
from urllib.parse import urlparse, parse_qs

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MAX_MESSAGES = 100
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

# بهبود یافته: regexهای قوی‌تر برای شناسایی همه فرمت‌ها
MY_REGEX = {
    "ss": r'(?i)(ss:\/\/|shadowsocks:\/\/)[a-zA-Z0-9@:%._\+~#?&=/-]+',
    "vmess": r'(?i)vmess:\/\/[a-zA-Z0-9=+\/]+',
    "trojan": r'(?i)(trojan:\/\/|trojan-go:\/\/)[a-zA-Z0-9@:%._\+~#?&=/-]+',
    "vless": r'(?i)vless:\/\/[a-zA-Z0-9@:%._\+~#?&=/-]+'
}

# بهبود یافته: پشتیبانی از همه فرمت‌های پروکسی تلگرام
PROXY_REGEX = r'(?i)(tg:\/\/proxy\/[a-zA-Z0-9@.\-_&=?]+|mtproto:\/\/[a-zA-Z0-9@.\-_&=?]+|https:\/\/t\.me\/proxy\?[a-zA-Z0-9=&._-]+|tg:\/\/socks\?[a-zA-Z0-9=&._-]+)'

def change_url_to_telegram_web_url(url):
    """تبدیل لینک کانال به فرمت وب تلگرام"""
    url = url.strip()
    if url.startswith("https://t.me/") and not "/s/" in url:
        return url.replace("https://t.me/", "https://t.me/s/")
    elif url.startswith("@"):
        return f"https://t.me/s/{url.lstrip('@')}"
    return url

def http_request(url, retries=3):
    """درخواست HTTP با مدیریت خطا"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    for i in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            resp.raise_for_status()
            return resp
        except Exception as e:
            logger.warning(f"Attempt {i+1} failed for {url}: {e}")
            if i == retries - 1:
                raise
    return None

def extract_all_configs(text):
    """استخراج همه کانفیگ‌ها از متن - بهبود یافته"""
    found_configs = []
    
    # بررسی همه regexها روی کل متن
    for proto, pattern in MY_REGEX.items():
        matches = re.findall(pattern, text)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0] if match[0] else match[-1]
            if match and match not in found_configs:
                found_configs.append((proto, match.strip()))
    
    return found_configs

def extract_all_proxies(text):
    """استخراج همه پروکسی‌ها از متن - بهبود یافته"""
    found_proxies = []
    
    # پیدا کردن همه پروکسی‌ها با regex
    matches = re.findall(PROXY_REGEX, text)
    for match in matches:
        if isinstance(match, tuple):
            match = match[0] if match[0] else match[-1]
        if match and match not in found_proxies:
            found_proxies.append(match.strip())
    
    return found_proxies

def crawl_for_v2ray(channel_url, all_messages_flag, channel_name):
    """کراول کردن کانال و استخراج کانفیگ‌ها"""
    try:
        channel_url = change_url_to_telegram_web_url(channel_url)
        logger.info(f"Crawling {channel_url}")
        
        resp = http_request(channel_url)
        if not resp:
            return
            
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        messages = soup.select(".tgme_widget_message_wrap")
        if len(messages) < MAX_MESSAGES:
            last_post = soup.select_one(".tgme_widget_message_wrap .js-widget_message:last-child")
            if last_post:
                post_id = last_post.get("data-post", "").split("/")[-1]
                soup = get_messages(MAX_MESSAGES, soup, post_id, channel_url)
        
        # انتخاب المان‌های مناسب بر اساس فلگ
        if all_messages_flag:
            elements = soup.select(".tgme_widget_message_text")
        else:
            elements = soup.select("code, pre, .tgme_widget_message_text")
        
        light_count = 0
        
        for elem in elements:
            message_text = elem.get_text()
            
            # استخراج همه کانفیگ‌ها
            configs = extract_all_configs(message_text)
            for proto, config in configs:
                # اضافه به فایل کامل
                CONFIGS[proto] += f"{config}|SEP|{channel_name}\n"
                CONFIGS["mixed"] += f"{config}|SEP|{channel_name}\n"
                
                # اضافه به فایل لایت (با محدودیت)
                if light_count < MAX_CONFIGS_PER_CHANNEL_LIGHT:
                    CONFIGS["mixed-light"] += f"{config}|SEP|{channel_name}\n"
                    light_count += 1
            
            # استخراج همه پروکسی‌ها
            proxies = extract_all_proxies(message_text)
            for proxy in proxies:
                CONFIGS["proxy"] += f"{proxy}|SEP|{channel_name}\n"
                CONFIGS["mixed"] += f"{proxy}|SEP|{channel_name}\n"
                
                if light_count < MAX_CONFIGS_PER_CHANNEL_LIGHT:
                    CONFIGS["mixed-light"] += f"{proxy}|SEP|{channel_name}\n"
                    light_count += 1
        
        logger.info(f"✅ Finished crawling {channel_url}")
        
    except Exception as e:
        logger.error(f"❌ Error crawling {channel_url}: {e}")

def get_messages(length, soup, number, channel):
    """دریافت پیام‌های بیشتر برای pagination"""
    try:
        url = f"{channel}?before={number}"
        resp = http_request(url)
        if not resp:
            return soup
            
        new_soup = BeautifulSoup(resp.text, 'html.parser')
        soup.body.append(new_soup.body)
        
        if len(soup.select(".js-widget_message_wrap")) > length:
            return soup
            
        num = int(number) - 21
        if num > 0:
            return get_messages(length, soup, str(num), channel)
            
    except Exception as e:
        logger.error(f"Error in pagination: {e}")
    
    return soup

def edit_vmess_ps(config, channel_name, config_id):
    """ویرایش نام VMess برای شناسایی بهتر"""
    try:
        if not config.startswith("vmess://"):
            return config
            
        encoded = config[8:]  # حذف "vmess://"
        # اطمینان از صحت base64
        missing_padding = len(encoded) % 4
        if missing_padding:
            encoded += '=' * (4 - missing_padding)
            
        decoded = base64.b64decode(encoded).decode('utf-8')
        data = json.loads(decoded)
        data["ps"] = f"{channel_name}-{config_id}"
        new_json = json.dumps(data, separators=(',', ':'))
        return "vmess://" + base64.b64encode(new_json.encode()).decode()
    except Exception as e:
        logger.warning(f"Failed to edit vmess ps: {e}")
        return config

def add_config_names(config_text, config_type):
    """اضافه کردن نام کانال به کانفیگ‌ها"""
    if not config_text:
        return ""
    
    lines = config_text.split("\n")
    new_configs = []
    
    for line in lines:
        if not line or "|SEP|" not in line:
            continue
            
        parts = line.split("|SEP|")
        config = parts[0].strip()
        channel_name = parts[1].strip() if len(parts) > 1 else "Unknown"
        
        if not config:
            continue
            
        CONFIG_FILE_IDS[config_type] += 1
        config_id = CONFIG_FILE_IDS[config_type]
        
        if config.startswith("vmess://"):
            config = edit_vmess_ps(config, channel_name, config_id)
            new_configs.append(config)
        else:
            # برای بقیه پروتکل‌ها، نام کانال رو به عنوان کامنت اضافه کن
            if "#" in config:
                base_config = config.split("#")[0]
                new_configs.append(f"{base_config}#{channel_name}-{config_id}")
            else:
                new_configs.append(f"{config}#{channel_name}-{config_id}")
    
    return "\n".join(new_configs)

def remove_duplicates(text):
    """حذف کانفیگ‌های تکراری"""
    if not text:
        return ""
    
    lines = text.strip().split("\n")
    unique_lines = []
    seen = set()
    
    for line in lines:
        if not line:
            continue
            
        # استخراج بخش اصلی کانفیگ بدون کامنت
        base_config = line.split("#")[0] if "#" in line else line.split("|SEP|")[0]
        
        if base_config not in seen:
            seen.add(base_config)
            unique_lines.append(line)
    
    return "\n".join(unique_lines)

def save_configs_to_file(configs, filename):
    """ذخیره کانفیگ‌ها در فایل"""
    try:
        unique_configs = remove_duplicates(configs)
        final_output = add_config_names(unique_configs, filename.replace("-all.txt", ""))
        
        with open(f"configs/{filename}", "w", encoding="utf-8") as f:
            f.write(final_output.strip())
        
        config_count = len(final_output.strip().split("\n")) if final_output.strip() else 0
        logger.info(f"💾 Saved {filename} with {config_count} configs")
        
    except Exception as e:
        logger.error(f"Error saving {filename}: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sort", action="store_true", help="sort from latest to oldest")
    args = parser.parse_args()

    try:
        df = pd.read_csv("channels.csv")
        channels = df.to_dict(orient="records")
        
        if not channels:
            logger.warning("No channels found in channels.csv")
            return
        
        logger.info(f"Found {len(channels)} channels to crawl")
        
        for channel in channels:
            url = channel.get("URL", "").strip()
            all_flag = channel.get("AllMessagesFlag", False)
            
            if not url:
                continue
                
            channel_name = url.rstrip("/").split("/")[-1]
            crawl_for_v2ray(url, all_flag, channel_name)
        
        logger.info("📁 Creating output files...")
        os.makedirs("configs", exist_ok=True)
        
        # ذخیره فایل‌ها
        file_mapping = {
            "ss": "ss-all.txt",
            "vmess": "vmess-all.txt",
            "trojan": "trojan-all.txt",
            "vless": "vless-all.txt",
            "mixed": "mixed-all.txt",
            "mixed-light": "mixed-light-all.txt",
            "proxy": "proxies-all.txt"
        }
        
        for proto, filename in file_mapping.items():
            if CONFIGS[proto]:
                save_configs_to_file(CONFIGS[proto], filename)
            else:
                # فایل خالی ایجاد کن
                with open(f"configs/{filename}", "w", encoding="utf-8") as f:
                    f.write("")
                logger.info(f"📄 Created empty {filename}")
        
        logger.info("🎉 All Done! Configs updated successfully.")
        
    except Exception as e:
        logger.error(f"Fatal error in main: {e}")
        raise

if __name__ == "__main__":
    main()
