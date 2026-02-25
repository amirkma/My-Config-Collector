import requests
import re
import json
import base64
import pandas as pd
from bs4 import BeautifulSoup
import os
import argparse
import logging
from collections import deque
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

# اضافه کردن دیکشنری برای ذخیره آخرین کانفیگ‌ها
LAST_CONFIGS = {
    "ss": deque(maxlen=MAX_CONFIGS_PER_CHANNEL_LIGHT),
    "vmess": deque(maxlen=MAX_CONFIGS_PER_CHANNEL_LIGHT),
    "trojan": deque(maxlen=MAX_CONFIGS_PER_CHANNEL_LIGHT),
    "vless": deque(maxlen=MAX_CONFIGS_PER_CHANNEL_LIGHT),
    "proxy": deque(maxlen=MAX_CONFIGS_PER_CHANNEL_LIGHT)
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

# بهبود یافته: پشتیبانی از همه فرمت‌های پروکسی
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
    """استخراج همه کانفیگ‌ها از متن"""
    found_configs = []
    
    for proto, pattern in MY_REGEX.items():
        matches = re.findall(pattern, text)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0] if match[0] else match[-1]
            if match and match.strip():
                # پاکسازی کانفیگ
                clean_config = match.strip().split('#')[0] if '#' in match else match.strip()
                found_configs.append((proto, clean_config))
    
    return found_configs

def extract_all_proxies(text):
    """استخراج همه پروکسی‌ها از متن"""
    found_proxies = []
    
    matches = re.findall(PROXY_REGEX, text)
    for match in matches:
        if isinstance(match, tuple):
            match = match[0] if match[0] else match[-1]
        if match and match.strip():
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
        
        # دریافت همه پیام‌ها
        messages = soup.select(".tgme_widget_message_wrap")
        if len(messages) < MAX_MESSAGES:
            last_post = soup.select_one(".tgme_widget_message_wrap .js-widget_message:last-child")
            if last_post:
                post_id = last_post.get("data-post", "").split("/")[-1]
                soup = get_messages(MAX_MESSAGES, soup, post_id, channel_url)
        
        # انتخاب المان‌ها بر اساس فلگ
        if all_messages_flag:
            elements = soup.select(".tgme_widget_message_text")
        else:
            elements = soup.select("code, pre, .tgme_widget_message_text")
        
        # لیست برای ذخیره موقت کانفیگ‌های این کانال
        channel_configs = []
        
        for elem in elements:
            message_text = elem.get_text()
            
            # استخراج کانفیگ‌ها
            configs = extract_all_configs(message_text)
            for proto, config in configs:
                channel_configs.append({
                    'proto': proto,
                    'config': config,
                    'channel': channel_name
                })
            
            # استخراج پروکسی‌ها
            proxies = extract_all_proxies(message_text)
            for proxy in proxies:
                channel_configs.append({
                    'proto': 'proxy',
                    'config': proxy,
                    'channel': channel_name
                })
        
        # اضافه کردن به CONFIGS (به ترتیب دریافت)
        for item in reversed(channel_configs):  # معکوس کردن برای آخرین‌ها اول باشن
            proto = item['proto']
            config = item['config']
            channel = item['channel']
            
            # اضافه به فایل کامل
            if proto in CONFIGS:
                CONFIGS[proto] += f"{config}|SEP|{channel}\n"
                CONFIGS["mixed"] += f"{config}|SEP|{channel}\n"
            
            # ذخیره در LAST_CONFIGS برای mixed-light (آخرین‌ها)
            if proto in LAST_CONFIGS:
                LAST_CONFIGS[proto].appendleft(f"{config}|SEP|{channel}")
        
        logger.info(f"✅ Finished crawling {channel_url} - Found {len(channel_configs)} items")
        
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
        
        # اضافه کردن پیام‌های جدید به soup اصلی
        for msg in new_soup.select(".tgme_widget_message_wrap"):
            soup.body.append(msg)
        
        if len(soup.select(".tgme_widget_message_wrap")) > length:
            return soup
            
        num = int(number) - 21
        if num > 0:
            return get_messages(length, soup, str(num), channel)
            
    except Exception as e:
        logger.error(f"Error in pagination: {e}")
    
    return soup

def safe_base64_decode(data):
    """دیکد ایمن base64 با مدیریت خطا"""
    try:
        # پاکسازی data
        data = data.strip()
        
        # اضافه کردن padding در صورت نیاز
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        
        # تلاش برای دیکد با utf-8
        try:
            decoded = base64.b64decode(data).decode('utf-8')
            return decoded
        except UnicodeDecodeError:
            # اگه utf-8 جواب نداد، latin-1 رو امتحان کن
            decoded = base64.b64decode(data).decode('latin-1')
            return decoded
            
    except Exception as e:
        logger.debug(f"Base64 decode failed: {e}")
        return None

def edit_vmess_ps(config, channel_name, config_id):
    """ویرایش نام VMess برای شناسایی بهتر - با مدیریت خطای بهتر"""
    try:
        if not config.startswith("vmess://"):
            return config
            
        encoded_part = config[8:]  # حذف "vmess://"
        
        # دیکد کردن بخش encoded
        decoded_json = safe_base64_decode(encoded_part)
        if not decoded_json:
            return config  # اگه دیکد نشد، همون config اصلی رو برگردون
        
        # پارس کردن JSON
        try:
            data = json.loads(decoded_json)
        except json.JSONDecodeError:
            return config
        
        # اضافه کردن نام کانال
        data["ps"] = f"{channel_name}-{config_id}"
        
        # انکد دوباره
        new_json = json.dumps(data, separators=(',', ':'))
        encoded = base64.b64encode(new_json.encode()).decode()
        
        return f"vmess://{encoded}"
        
    except Exception as e:
        logger.debug(f"Failed to edit vmess ps for {channel_name}: {e}")
        return config  # برگردوندن config اصلی به جای حذف

def add_config_names(config_text, config_type):
    """اضافه کردن نام کانال به کانفیگ‌ها"""
    if not config_text:
        return ""
    
    lines = config_text.strip().split("\n")
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
        if "|SEP|" in line:
            base_config = line.split("|SEP|")[0].split("#")[0]
        else:
            base_config = line.split("#")[0]
        
        if base_config not in seen:
            seen.add(base_config)
            unique_lines.append(line)
    
    return "\n".join(unique_lines)

def create_mixed_light():
    """ایجاد mixed-light از آخرین کانفیگ‌های هر کانال"""
    mixed_light = []
    
    # از هر پروتکل، آخرین کانفیگ‌ها رو بردار
    for proto, configs in LAST_CONFIGS.items():
        for config in configs:
            if config and config not in mixed_light:
                mixed_light.append(config)
    
    # محدود کردن به MAX_CONFIGS_PER_CHANNEL_LIGHT
    mixed_light = mixed_light[:MAX_CONFIGS_PER_CHANNEL_LIGHT * len(LAST_CONFIGS)]
    
    return "\n".join(mixed_light)

def save_configs_to_file(configs, filename):
    """ذخیره کانفیگ‌ها در فایل"""
    try:
        if not configs:
            # فایل خالی ایجاد کن
            with open(f"configs/{filename}", "w", encoding="utf-8") as f:
                f.write("")
            logger.info(f"📄 Created empty {filename}")
            return
        
        unique_configs = remove_duplicates(configs)
        
        # برای mixed-light از متد خاص استفاده کن
        if filename == "mixed-light-all.txt":
            final_output = add_config_names(unique_configs, "mixed-light")
        else:
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
        # خوندن کانال‌ها
        if not os.path.exists("channels.csv"):
            logger.error("channels.csv not found!")
            return
            
        df = pd.read_csv("channels.csv")
        channels = df.to_dict(orient="records")
        
        if not channels:
            logger.warning("No channels found in channels.csv")
            return
        
        logger.info(f"Found {len(channels)} channels to crawl")
        
        # کراول کردن کانال‌ها
        for channel in channels:
            url = channel.get("URL", "").strip()
            all_flag = channel.get("AllMessagesFlag", False)
            
            if not url:
                continue
                
            channel_name = url.rstrip("/").split("/")[-1]
            crawl_for_v2ray(url, all_flag, channel_name)
        
        logger.info("📁 Creating output files...")
        os.makedirs("configs", exist_ok=True)
        
        # ایجاد mixed-light از آخرین کانفیگ‌ها
        CONFIGS["mixed-light"] = create_mixed_light()
        
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
            if proto in CONFIGS and CONFIGS[proto]:
                save_configs_to_file(CONFIGS[proto], filename)
            else:
                # فایل خالی ایجاد کن
                with open(f"configs/{filename}", "w", encoding="utf-8") as f:
                    f.write("")
                logger.info(f"📄 Created empty {filename}")
        
        # گزارش نهایی
        total_configs = sum(len(CONFIGS[p].strip().split("\n")) if CONFIGS[p] else 0 for p in CONFIGS)
        logger.info(f"🎉 All Done! Total configs collected: {total_configs}")
        
    except Exception as e:
        logger.error(f"Fatal error in main: {e}")
        raise

if __name__ == "__main__":
    main()
