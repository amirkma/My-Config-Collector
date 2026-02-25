import requests
import re
import json
import base64
import pandas as pd
from bs4 import BeautifulSoup
import os
import argparse
import logging
from collections import deque, defaultdict
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MAX_MESSAGES = 100
MAX_LIGHT_PER_CHANNEL = 10  # از هر کانال 10 تا آخرین

# ==================== پروتکل‌ها و الگوها ====================

CONFIG_TYPES = {
    "ss": "shadowsocks",
    "vmess": "vmess",
    "trojan": "trojan",
    "vless": "vless",
    "proxy": "proxy"
}

# REGEXهای قدرتمند برای تشخیص همه فرمت‌ها
PATTERNS = {
    "vmess": [
        r'vmess:\/\/[a-zA-Z0-9+\/=\-_]+',
        r'VMess:\/\/[a-zA-Z0-9+\/=\-_]+',
    ],
    "vless": [
        r'vless:\/\/[a-f0-9\-]+@[a-zA-Z0-9.\-]+:\d+\?[a-zA-Z0-9=&_\-\%]+(?:#.+)?',
        r'vless:\/\/[a-zA-Z0-9\-]+@[a-zA-Z0-9.\-]+:\d+[^\s<>"]*',
        r'vless:\/\/[a-zA-Z0-9+\/=\-_]+',
    ],
    "trojan": [
        r'trojan:\/\/[a-zA-Z0-9\-]+@[a-zA-Z0-9.\-]+:\d+\?[a-zA-Z0-9=&_\-\%]+(?:#.+)?',
        r'trojan:\/\/[a-zA-Z0-9\-]+@[a-zA-Z0-9.\-]+:\d+[^\s<>"]*',
        r'trojan:\/\/[a-zA-Z0-9+\/=\-_]+',
    ],
    "ss": [
        r'ss:\/\/[a-zA-Z0-9+\/=\-_]+',
        r'shadowsocks:\/\/[a-zA-Z0-9+\/=\-_]+',
        r'ss:\/\/[a-zA-Z0-9@:%._\+~#?&=/-]+',
    ],
    "proxy": [
        r'tg:\/\/proxy\?[a-zA-Z0-9@.\-_&=?]+',
        r'tg:\/\/proxy\/[a-zA-Z0-9@.\-_&=?]+',
        r'mtproto:\/\/[a-zA-Z0-9@.\-_&=?]+',
        r'https:\/\/t\.me\/proxy\?[a-zA-Z0-9=&._-]+',
        r'tg:\/\/socks\?[a-zA-Z0-9=&._-]+',
        r'socks5:\/\/[a-zA-Z0-9@.\-_&=?]+',
        r'socks4:\/\/[a-zA-Z0-9@.\-_&=?]+',
        r'http:\/\/[a-zA-Z0-9@.\-_&=?]+',
        r'https:\/\/[a-zA-Z0-9@.\-_&=?]+',
    ]
}

# ==================== ذخیره‌سازی ====================

CONFIGS = {
    "ss": [],
    "vmess": [],
    "trojan": [],
    "vless": [],
    "mixed": [],
    "mixed-light": [],
    "proxy": []
}

# برای ذخیره آخرین کانفیگ‌های هر کانال (برای لایت)
CHANNEL_LATEST = defaultdict(list)  # هر کانال، لیست آخرین کانفیگ‌هاش

CONFIG_FILE_IDS = {
    "ss": 0,
    "vmess": 0,
    "trojan": 0,
    "vless": 0,
    "mixed": 0,
    "mixed-light": 0,
    "proxy": 0
}

# ==================== توابع کمکی ====================

def normalize_url(url):
    """تبدیل لینک کانال به فرمت وب تلگرام"""
    url = url.strip()
    if url.startswith("https://t.me/") and not "/s/" in url:
        return url.replace("https://t.me/", "https://t.me/s/")
    elif url.startswith("@"):
        return f"https://t.me/s/{url.lstrip('@')}"
    elif "t.me" in url and not "/s/" in url:
        return url.replace("t.me/", "t.me/s/")
    return url

def fetch_url(url, retries=3):
    """درخواست HTTP با مدیریت خطا"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    
    for i in range(retries):
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            return resp
        except Exception as e:
            logger.warning(f"Attempt {i+1} failed for {url}: {e}")
            if i == retries - 1:
                raise
    return None

def extract_configs_from_text(text):
    """استخراج همه کانفیگ‌ها از متن"""
    found = []
    
    lines = text.split('\n')
    for line in lines:
        line = line.strip()
        if not line or len(line) < 10:
            continue
        
        # بررسی هر پروتکل
        for proto, patterns in PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, line, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match[0] else match[-1]
                    match = match.strip()
                    
                    if match and len(match) > 10:
                        # پالایش نهایی
                        match = match.split()[0] if ' ' in match else match
                        match = match.split('<')[0] if '<' in match else match
                        
                        found.append({
                            'proto': proto,
                            'config': match,
                            'raw': line
                        })
    
    return found

# ==================== کراولر اصلی ====================

def crawl_channel_full(channel_url, all_messages_flag, channel_name):
    """کراول کامل برای جمع‌آوری همه کانفیگ‌ها (برای mixed)"""
    try:
        channel_url = normalize_url(channel_url)
        logger.info(f"🔍 FULL CRAWL: {channel_url}")
        
        resp = fetch_url(channel_url)
        if not resp:
            return []
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # دریافت همه پیام‌ها
        messages = soup.select(".tgme_widget_message_wrap")
        if len(messages) < MAX_MESSAGES:
            last_post = soup.select_one(".tgme_widget_message_wrap .js-widget_message:last-child")
            if last_post:
                post_id = last_post.get("data-post", "").split("/")[-1]
                soup = get_all_messages(MAX_MESSAGES, soup, post_id, channel_url)
        
        # انتخاب المان‌ها
        if all_messages_flag:
            elements = soup.select(".tgme_widget_message_text")
        else:
            elements = soup.select("code, pre, .tgme_widget_message_text")
        
        # استخراج کانفیگ‌ها
        all_configs = []
        
        for elem in elements:
            text = elem.get_text()
            configs = extract_configs_from_text(text)
            all_configs.extend(configs)
        
        logger.info(f"✅ FULL: Found {len(all_configs)} configs in {channel_url}")
        return all_configs
        
    except Exception as e:
        logger.error(f"❌ Error in full crawl {channel_url}: {e}")
        return []

def crawl_channel_light(channel_url, all_messages_flag, channel_name):
    """کراول سبک برای گرفتن فقط ۱۰ تا آخرین کانفیگ (برای mixed-light)"""
    try:
        channel_url = normalize_url(channel_url)
        logger.info(f"⚡ LIGHT CRAWL: {channel_url} (last {MAX_LIGHT_PER_CHANNEL} configs)")
        
        resp = fetch_url(channel_url)
        if not resp:
            return []
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # فقط اولین صفحه رو بگیر (آخرین پیام‌ها)
        messages = soup.select(".tgme_widget_message_wrap")[:MAX_LIGHT_PER_CHANNEL * 2]  # یه کم بیشتر بگیر
        
        # انتخاب المان‌ها
        if all_messages_flag:
            elements = soup.select(".tgme_widget_message_text")[:MAX_LIGHT_PER_CHANNEL * 3]
        else:
            elements = soup.select("code, pre, .tgme_widget_message_text")[:MAX_LIGHT_PER_CHANNEL * 3]
        
        # استخراج کانفیگ‌ها
        latest_configs = []
        
        for elem in elements:
            if len(latest_configs) >= MAX_LIGHT_PER_CHANNEL:
                break
                
            text = elem.get_text()
            configs = extract_configs_from_text(text)
            
            for cfg in configs:
                if len(latest_configs) >= MAX_LIGHT_PER_CHANNEL:
                    break
                if cfg not in latest_configs:
                    latest_configs.append(cfg)
        
        logger.info(f"⚡ LIGHT: Found {len(latest_configs)} latest configs in {channel_url}")
        return latest_configs
        
    except Exception as e:
        logger.error(f"❌ Error in light crawl {channel_url}: {e}")
        return []

def get_all_messages(length, soup, number, channel):
    """دریافت پیام‌های بیشتر (صفحه‌بندی)"""
    try:
        url = f"{channel}?before={number}"
        resp = fetch_url(url)
        if not resp:
            return soup
            
        new_soup = BeautifulSoup(resp.text, 'html.parser')
        
        for msg in new_soup.select(".tgme_widget_message_wrap"):
            soup.body.append(msg)
        
        if len(soup.select(".tgme_widget_message_wrap")) > length:
            return soup
            
        num = int(number) - 21
        if num > 0:
            return get_all_messages(length, soup, str(num), channel)
            
    except Exception as e:
        logger.error(f"Error in pagination: {e}")
    
    return soup

# ==================== پردازش کانفیگ‌ها ====================

def process_configs(configs_list, channel_name, for_light=False):
    """پردازش و اضافه کردن کانفیگ‌ها به CONFIGS"""
    for item in configs_list:
        proto = item['proto']
        config = item['config']
        
        # اضافه به فایل‌های اصلی
        if proto in CONFIGS:
            CONFIGS[proto].append(f"{config}|SEP|{channel_name}")
            CONFIGS["mixed"].append(f"{config}|SEP|{channel_name}")
        
        # اگه برای لایت هست، جداگانه ذخیره کن
        if for_light:
            # برای mixed-light، مستقیم به پروتکل مربوطه اضافه می‌کنیم
            if proto in CONFIGS:
                # یه کپی برای mixed-light (با محدودیت بعداً اعمال میشه)
                CONFIGS["mixed-light"].append(f"{config}|SEP|{channel_name}")

def edit_vmess_ps(config, channel_name, config_id):
    """ویرایش نام VMess"""
    try:
        if not config.startswith('vmess://'):
            return config
        
        encoded = config[8:]
        
        # دیکد کردن
        missing_padding = len(encoded) % 4
        if missing_padding:
            encoded += '=' * (4 - missing_padding)
        
        decoded = base64.b64decode(encoded).decode('utf-8')
        data = json.loads(decoded)
        
        # تغییر نام
        data['ps'] = f"{channel_name}-{config_id}"
        
        # انکد مجدد
        new_json = json.dumps(data, separators=(',', ':'))
        new_encoded = base64.b64encode(new_json.encode()).decode()
        
        return f"vmess://{new_encoded}"
    except:
        return config

def format_final_configs(config_list, config_type):
    """فرمت‌دهی نهایی فایل‌ها"""
    if not config_list:
        return ""
    
    # حذف تکراری‌ها
    unique_configs = []
    seen = set()
    
    for item in config_list:
        if "|SEP|" not in item:
            continue
            
        parts = item.split("|SEP|")
        config = parts[0].strip()
        channel = parts[1].strip() if len(parts) > 1 else "Unknown"
        
        if not config:
            continue
        
        # کلید برای تشخیص تکراری
        config_key = config.split('#')[0] if '#' in config else config
        if config_key in seen:
            continue
        seen.add(config_key)
        
        CONFIG_FILE_IDS[config_type] += 1
        config_id = CONFIG_FILE_IDS[config_type]
        
        # ویرایش VMess
        if config.startswith('vmess://'):
            config = edit_vmess_ps(config, channel, config_id)
            unique_configs.append(config)
        else:
            if '#' in config:
                base = config.split('#')[0]
                unique_configs.append(f"{base}#{channel}-{config_id}")
            else:
                unique_configs.append(f"{config}#{channel}-{config_id}")
    
    return '\n'.join(unique_configs)

def limit_light_version():
    """محدود کردن mixed-light به ۱۰ تا از هر کانال"""
    if not CONFIGS["mixed-light"]:
        return
    
    # گروه‌بندی بر اساس کانال
    channel_groups = defaultdict(list)
    
    for item in CONFIGS["mixed-light"]:
        if "|SEP|" in item:
            channel = item.split("|SEP|")[1]
            channel_groups[channel].append(item)
    
    # ساخت مجدد mixed-light با محدودیت
    limited = []
    for channel, items in channel_groups.items():
        # فقط ۱۰ تا آخرین از هر کانال
        limited.extend(items[:MAX_LIGHT_PER_CHANNEL])
    
    CONFIGS["mixed-light"] = limited

# ==================== MAIN ====================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sort", action="store_true", help="sort from latest to oldest")
    args = parser.parse_args()
    
    try:
        # خوندن کانال‌ها
        if not os.path.exists("channels.csv"):
            logger.error("❌ channels.csv not found!")
            return
        
        df = pd.read_csv("channels.csv")
        channels = df.to_dict(orient="records")
        
        logger.info(f"📡 Found {len(channels)} channels")
        logger.info("=" * 60)
        
        # ========== مرحله ۱: کراول کامل برای mixed ==========
        logger.info("🔴 PHASE 1: FULL CRAWL for mixed-all.txt")
        logger.info("=" * 60)
        
        for channel in channels:
            url = channel.get("URL", "").strip()
            all_flag = channel.get("AllMessagesFlag", False)
            
            if url:
                channel_name = url.rstrip('/').split('/')[-1]
                
                # کراول کامل
                full_configs = crawl_channel_full(url, all_flag, channel_name)
                
                # پردازش و اضافه به mixed
                process_configs(full_configs, channel_name, for_light=False)
                
                # کمی صبر بین درخواست‌ها
                time.sleep(2)
        
        logger.info("=" * 60)
        
        # ========== مرحله ۲: کراول سبک برای mixed-light ==========
        logger.info("🟢 PHASE 2: LIGHT CRAWL for mixed-light-all.txt")
        logger.info("=" * 60)
        
        # ریست کردن CONFIGS برای mixed-light (اختیاری - می‌خوایم جدا باشه)
        CONFIGS["mixed-light"] = []
        
        for channel in channels:
            url = channel.get("URL", "").strip()
            all_flag = channel.get("AllMessagesFlag", False)
            
            if url:
                channel_name = url.rstrip('/').split('/')[-1]
                
                # کراول سبک (فقط آخرین‌ها)
                light_configs = crawl_channel_light(url, all_flag, channel_name)
                
                # پردازش و اضافه به mixed-light
                for item in light_configs:
                    proto = item['proto']
                    config = item['config']
                    CONFIGS["mixed-light"].append(f"{config}|SEP|{channel_name}")
                
                time.sleep(1)  # صبر کمتر برای کراول سبک
        
        logger.info("=" * 60)
        
        # ========== اعمال محدودیت نهایی ==========
        logger.info("📊 Applying final limits...")
        limit_light_version()
        
        # ========== ذخیره همه فایل‌ها ==========
        logger.info("💾 Saving files...")
        os.makedirs("configs", exist_ok=True)
        
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
                formatted = format_final_configs(CONFIGS[proto], proto)
                with open(f"configs/{filename}", "w", encoding="utf-8") as f:
                    f.write(formatted)
                count = len(formatted.split('\n')) if formatted else 0
                logger.info(f"✅ Saved {filename} with {count} configs")
            else:
                with open(f"configs/{filename}", "w", encoding="utf-8") as f:
                    f.write("")
                logger.info(f"📄 Created empty {filename}")
        
        # ========== گزارش نهایی ==========
        logger.info("=" * 60)
        total_full = sum(len(CONFIGS[p]) for p in ["ss", "vmess", "trojan", "vless", "proxy"])
        logger.info(f"🎉 FINAL REPORT:")
        logger.info(f"   - Total configs in mixed-all: {len(CONFIGS['mixed'])}")
        logger.info(f"   - Total configs in mixed-light: {len(CONFIGS['mixed-light'])}")
        logger.info(f"   - Light version has max {MAX_LIGHT_PER_CHANNEL} per channel")
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error(f"💥 Fatal error: {e}")
        raise

if __name__ == "__main__":
    main()
