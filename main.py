import requests
import re
import base64
import time
import random
from bs4 import BeautifulSoup
import pandas as pd
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_PAGES = 6               # ≈ ۱۰۰–۱۸۰ پیام اخیر (بیشتر از این اغلب بلاک می‌شه)
MAX_LIGHT_PER_CHANNEL = 20
OUTPUT_DIR = "configs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

REGEX_CONFIG = r'(vmess|vless|trojan|ss)://[^\s#|]+'

SUBCONVERTER_API = "https://pub-api-1.bianyuan.xyz/sub"   # یکی از پایدارترین عمومی‌ها در ۲۰۲۶ (اگر کار نکرد، بگو عوض کنیم)

def get_preview_url(url):
    url = url.strip()
    if url.startswith('@'):
        return f"https://t.me/s/{url[1:]}"
    if 't.me/' in url:
        return url.replace('https://t.me/', 'https://t.me/s/')
    return f"https://t.me/s/{url}"

def scrape_channel(channel_url, channel_name):
    url = get_preview_url(channel_url)
    configs = []
    before = None
    page = 0

    while page < MAX_PAGES:
        try:
            page_url = f"{url}?before={before}" if before else url
            headers = {"User-Agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            ])}
            r = requests.get(page_url, headers=headers, timeout=15)
            r.raise_for_status()

            soup = BeautifulSoup(r.text, 'html.parser')
            messages = soup.select('.tgme_widget_message_text')

            if not messages:
                break

            for msg in messages:
                text = msg.get_text(separator='\n', strip=True)
                found = re.findall(REGEX_CONFIG, text, re.IGNORECASE)
                configs.extend(found)

            last = soup.select_one('.tgme_widget_message[data-post]')
            if last:
                before = last['data-post'].split('/')[-1]
            else:
                break

            page += 1
            time.sleep(random.uniform(5, 12))

        except Exception as e:
            logger.warning(f"خطا در {channel_name} صفحه {page}: {e}")
            break

    return list(set(configs))

def save_base64(name, cfgs):
    if not cfgs:
        return None
    content = '\n'.join(cfgs).strip()
    b64 = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    path = os.path.join(OUTPUT_DIR, f"{name}.txt")
    with open(path, 'w', encoding='utf-8') as f:
        f.write(b64)
    logger.info(f"ذخیره شد: {path}")
    return f"https://raw.githubusercontent.com/{os.getenv('GITHUB_REPOSITORY', 'unknown/repo')}/main/{path}"

def convert_to_clash(sub_raw_url, output_name):
    if not sub_raw_url:
        return
    try:
        params = {
            'target': 'clash',
            'url': sub_raw_url,
            'config': 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini',
            'emoji': 'true',
            'new_name': 'true'
        }
        resp = requests.get(SUBCONVERTER_API, params=params, timeout=40)
        if resp.status_code == 200 and 'proxies:' in resp.text:
            yaml_path = os.path.join(OUTPUT_DIR, f"{output_name}.yaml")
            with open(yaml_path, 'w', encoding='utf-8') as f:
                f.write(resp.text)
            logger.info(f"Clash yaml ساخته شد: {yaml_path}")
        else:
            logger.warning(f"Clash تبدیل نشد: status {resp.status_code}")
    except Exception as e:
        logger.error(f"خطا Clash تبدیل: {e}")

def main():
    if not os.path.exists('channels.csv'):
        logger.error("channels.csv نیست!")
        return

    df = pd.read_csv('channels.csv')
    channels = df['URL'].dropna().tolist()

    all_cfgs = []
    lite_cfgs = []

    for ch_url in channels:
        name = ch_url.split('/')[-1].replace('@', '')
        logger.info(f"جمع‌آوری از: {name}")

        cfgs = scrape_channel(ch_url, name)
        all_cfgs.extend(cfgs)
        lite_cfgs.extend(cfgs[:MAX_LIGHT_PER_CHANNEL])

        time.sleep(random.uniform(8, 18))

    all_cfgs = list(set(all_cfgs))
    lite_cfgs = list(set(lite_cfgs))

    logger.info(f"مجموع mixed: {len(all_cfgs)} | lite: {len(lite_cfgs)}")

    mixed_url = save_base64('mixed', all_cfgs)
    lite_url = save_base64('lite-mixed', lite_cfgs)

    convert_to_clash(mixed_url, 'clash-mixed')
    convert_to_clash(lite_url, 'clash-lite-mixed')

if __name__ == '__main__':
    main()
