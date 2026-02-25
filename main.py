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
import urllib.parse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MAX_MESSAGES = 100
MAX_LIGHT_PER_CHANNEL = 10  # از هر کانال 10 تا آخرین

# ==================== پشتیبانی از همه فرمت‌های ممکن ====================

# پروتکل‌های اصلی
CONFIG_TYPES = {
    "ss": "shadowsocks",
    "vmess": "vmess",
    "trojan": "trojan",
    "vless": "vless",
    "proxy": "proxy"
}

# REGEXهای قدرتمند برای تشخیص همه فرمت‌ها
PATTERNS = {
    # VMess - همه فرمت‌ها
    "vmess": [
        r'vmess:\/\/[a-zA-Z0-9+\/=\-_]+',
        r'VMess:\/\/[a-zA-Z0-9+\/=\-_]+',
        r'vmess1:\/\/[a-zA-Z0-9+\/=\-_]+',
    ],
    
    # VLESS - همه فرمت‌ها
    "vless": [
        r'vless:\/\/[a-f0-9\-]+@[a-zA-Z0-9.\-]+:\d+\?[a-zA-Z0-9=&_\-\%]+(?:#.+)?',
        r'vless:\/\/[a-zA-Z0-9\-]+@[a-zA-Z0-9.\-]+:\d+[^\s<>"]*',
        r'vless:\/\/[a-zA-Z0-9+\/=\-_]+',
        r'VLESS:\/\/[a-zA-Z0-9+\/=\-_]+',
    ],
    
    # Trojan - همه فرمت‌ها
    "trojan": [
        r'trojan:\/\/[a-zA-Z0-9\-]+@[a-zA-Z0-9.\-]+:\d+\?[a-zA-Z0-9=&_\-\%]+(?:#.+)?',
        r'trojan:\/\/[a-zA-Z0-9\-]+@[a-zA-Z0-9.\-]+:\d+[^\s<>"]*',
        r'trojan:\/\/[a-zA-Z0-9+\/=\-_]+',
        r'trojan-go:\/\/[a-zA-Z0-9+\/=\-_]+',
    ],
    
    # Shadowsocks - همه فرمت‌ها
    "ss": [
        r'ss:\/\/[a-zA-Z0-9+\/=\-_]+',
        r'shadowsocks:\/\/[a-zA-Z0-9+\/=\-_]+',
        r'ss:\/\/[a-zA-Z0-9@:%._\+~#?&=/-]+',
        r'SS:\/\/[a-zA-Z0-9+\/=\-_]+',
    ],
    
    # پروکسی تلگرام - همه فرمت‌ها
    "proxy": [
        # MTProto
        r'tg:\/\/proxy\?[a-zA-Z0-9@.\-_&=?]+',
        r'tg:\/\/proxy\/[a-zA-Z0-9@.\-_&=?]+',
        r'mtproto:\/\/[a-zA-Z0-9@.\-_&=?]+',
        r'https:\/\/t\.me\/proxy\?[a-zA-Z0-9=&._-]+',
        
        # SOCKS
        r'tg:\/\/socks\?[a-zA-Z0-9=&._-]+',
        r'socks5:\/\/[a-zA-Z0-9@.\-_&=?]+',
        r'socks4:\/\/[a-zA-Z0-9@.\-_&=?]+',
        r'socks:\/\/[a-zA-Z0-9@.\-_&=?]+',
        
        # HTTP/HTTPS Proxy
        r'http:\/\/[a-zA-Z0-9@.\-_&=?]+',
        r'https:\/\/[a-zA-Z0-9@.\-_&=?]+',
        
        # فرمت‌های خاص تلگرام
        r'tg:\/\/[a-zA-Z0-9@.\-_&=?]+',
        r'https:\/\/t\.me\/socks\?[a-zA-Z0-9=&._-]+',
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
CHANNEL_LIGHT = defaultdict(lambda: deque(maxlen=MAX_LIGHT_PER_CHANNEL))

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
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
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

def extract_all_configs_from_text(text):
    """استخراج همه کانفیگ‌ها از متن با بالاترین دقت"""
    found = {
        "ss": [],
        "vmess": [],
        "trojan": [],
        "vless": [],
        "proxy": []
    }
    
    # بررسی خط به خط
    lines = text.split('\n')
    for line in lines:
        line = line.strip()
        if not line or len(line) < 10:  # حداقل طول منطقی برای کانفیگ
            continue
        
        # بررسی هر پروتکل
        for proto, patterns in PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, line, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match[0] else match[-1]
                    match = match.strip()
                    
                    # پالایش و تمیزکاری
                    if match and len(match) > 10:
                        # جدا کردن کانفیگ از متن اضافی
                        match = match.split()[0] if ' ' in match else match
                        match = match.split('<')[0] if '<' in match else match
                        
                        if match not in found[proto]:
                            found[proto].append(match)
                            logger.debug(f"Found {proto}: {match[:50]}...")
    
    return found

def clean_config(config, proto):
    """تمیز کردن کانفیگ از کاراکترهای اضافی"""
    # حذف تگ‌های HTML
    config = re.sub(r'<[^>]+>', '', config)
    
    # حذف فاصله‌های اضافی
    config = config.strip()
    
    # اطمینان از صحت پروتکل
    if proto == "vmess" and not config.startswith(('vmess://', 'VMess://')):
        return None
    elif proto == "vless" and not config.startswith(('vless://', 'VLESS://')):
        return None
    elif proto == "trojan" and not config.startswith(('trojan://', 'Trojan://', 'trojan-go://')):
        return None
    elif proto == "ss" and not config.startswith(('ss://', 'SS://', 'shadowsocks://')):
        return None
    
    return config

# ==================== کراولر اصلی ====================

def crawl_channel(channel_url, all_messages_flag, channel_name):
    """کراول کردن کانال با قدرت بالا"""
    try:
        channel_url = normalize_url(channel_url)
        logger.info(f"🔍 Crawling {channel_url}")
        
        resp = fetch_url(channel_url)
        if not resp:
            return
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # دریافت همه پیام‌ها
        messages = soup.select(".tgme_widget_message_wrap")
        if len(messages) < MAX_MESSAGES:
            last_post = soup.select_one(".tgme_widget_message_wrap .js-widget_message:last-child")
            if last_post:
                post_id = last_post.get("data-post", "").split("/")[-1]
                soup = get_all_messages(MAX_MESSAGES, soup, post_id, channel_url)
        
        # انتخاب المان‌های حاوی متن
        if all_messages_flag:
            elements = soup.select(".tgme_widget_message_text")
        else:
            elements = soup.select("code, pre, .tgme_widget_message_text, .message-text")
        
        # پردازش هر المان
        channel_configs = []
        
        for elem in elements:
            text = elem.get_text()
            
            # استخراج همه کانفیگ‌ها از متن
            found_configs = extract_all_configs_from_text(text)
            
            # ذخیره کانفیگ‌های پیدا شده
            for proto, configs in found_configs.items():
                for config in configs:
                    cleaned = clean_config(config, proto)
                    if cleaned:
                        channel_configs.append({
                            'proto': proto,
                            'config': cleaned,
                            'channel': channel_name,
                            'raw': config
                        })
        
        # اضافه کردن به CONFIGS (به ترتیب زمان - آخرین‌ها اول)
        for item in reversed(channel_configs):
            proto = item['proto']
            config = item['config']
            channel = item['channel']
            
            # اضافه به فایل کامل
            if proto in CONFIGS:
                CONFIGS[proto].append(f"{config}|SEP|{channel}")
                CONFIGS["mixed"].append(f"{config}|SEP|{channel}")
            
            # اضافه به لایت (آخرین‌های هر کانال)
            light_key = f"{channel}_{proto}"
            CHANNEL_LIGHT[light_key].appendleft(f"{config}|SEP|{channel}")
        
        logger.info(f"✅ Found {len(channel_configs)} configs in {channel_url}")
        
    except Exception as e:
        logger.error(f"❌ Error crawling {channel_url}: {e}")

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

# ==================== پردازش و ذخیره ====================

def edit_vmess_ps(config, channel_name, config_id):
    """ویرایش نام VMess با مدیریت خطا"""
    try:
        if not config.startswith('vmess://'):
            return config
        
        encoded = config[8:]
        
        # دیکد کردن
        try:
            # اضافه کردن padding
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
            
    except Exception as e:
        logger.debug(f"VMess edit failed: {e}")
        return config

def format_configs(config_list, config_type):
    """فرمت‌دهی نهایی کانفیگ‌ها"""
    if not config_list:
        return ""
    
    formatted = []
    seen = set()
    
    for item in config_list:
        if "|SEP|" not in item:
            continue
            
        parts = item.split("|SEP|")
        config = parts[0].strip()
        channel = parts[1].strip() if len(parts) > 1 else "Unknown"
        
        if not config:
            continue
        
        # حذف تکراری
        config_key = config.split('#')[0] if '#' in config else config
        if config_key in seen:
            continue
        seen.add(config_key)
        
        CONFIG_FILE_IDS[config_type] += 1
        config_id = CONFIG_FILE_IDS[config_type]
        
        # ویرایش VMess
        if config.startswith('vmess://'):
            config = edit_vmess_ps(config, channel, config_id)
            formatted.append(config)
        else:
            # اضافه کردن کامنت
            if '#' in config:
                base = config.split('#')[0]
                formatted.append(f"{base}#{channel}-{config_id}")
            else:
                formatted.append(f"{config}#{channel}-{config_id}")
    
    return '\n'.join(formatted)

def create_light_version():
    """ایجاد نسخه لایت از آخرین کانفیگ‌های هر کانال"""
    all_light = []
    seen = set()
    
    # از هر کانال-پروتکل، آخرین‌ها رو بردار
    for key, configs in CHANNEL_LIGHT.items():
        for config in configs:
            if config and config not in seen:
                # استخراج بخش اصلی برای تشخیص تکراری
                config_key = config.split('|SEP|')[0].split('#')[0]
                if config_key not in seen:
                    seen.add(config_key)
                    all_light.append(config)
    
    # محدودیت کلی (اختیاری)
    # all_light = all_light[:MAX_LIGHT_PER_CHANNEL * 10]
    
    return all_light

def save_all():
    """ذخیره همه فایل‌ها"""
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
    
    # ایجاد نسخه لایت
    CONFIGS["mixed-light"] = create_light_version()
    
    # ذخیره همه فایل‌ها
    for proto, filename in file_mapping.items():
        if proto in CONFIGS and CONFIGS[proto]:
            formatted = format_configs(CONFIGS[proto], proto)
            with open(f"configs/{filename}", "w", encoding="utf-8") as f:
                f.write(formatted)
            count = len(formatted.split('\n')) if formatted else 0
            logger.info(f"💾 Saved {filename} with {count} configs")
        else:
            with open(f"configs/{filename}", "w", encoding="utf-8") as f:
                f.write("")
            logger.info(f"📄 Created empty {filename}")

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
        
        logger.info(f"📡 Found {len(channels)} channels to crawl")
        
        # کراول کردن هر کانال
        for channel in channels:
            url = channel.get("URL", "").strip()
            all_flag = channel.get("AllMessagesFlag", False)
            
            if url:
                channel_name = url.rstrip('/').split('/')[-1]
                crawl_channel(url, all_flag, channel_name)
        
        # ذخیره همه چیز
        logger.info("📁 Saving files...")
        save_all()
        
        # گزارش نهایی
        total = sum(len(CONFIGS[p]) for p in CONFIGS)
        logger.info(f"🎉 ALL DONE! Total configs: {total}")
        logger.info(f"✨ Light version has {len(CONFIGS['mixed-light'])} latest configs")
        
    except Exception as e:
        logger.error(f"💥 Fatal error: {e}")
        raise

if __name__ == "__main__":
    main()
