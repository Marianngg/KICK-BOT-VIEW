#!/usr/bin/env python3
# ──────────────────────────────────────────────────────────────
#  KICK VIEWER BOT
#  Author: Mariann
#  Purpose: Educational pentest / viewer-count research tool
#  Note: For authorized security testing only
# ──────────────────────────────────────────────────────────────

import sys
import time
import random
import datetime
import threading
import asyncio
import websockets
import json
import os
import re
import socket
import signal
import urllib.request
import urllib.error
from threading import Thread, Semaphore, Lock
from collections import deque
from fake_useragent import UserAgent
import tls_client

# ───────────────────────────── CONFIG ─────────────────────────────

CLIENT_TOKEN = "e1393935a959b4020a4491574f6490129f678acdaa92760471263db43487f823"
PROXY_FILE = "proxies.txt"
AUTO_SCRAPE_PROXIES = True
MAX_PROXIES = 3000

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/main/all_proxies.txt",
    "https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/all.txt",
    "https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/http.txt",
    "https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/socks5.txt",
    "https://hproxy.com/api/proxy-list?format=txt",
]

# ──────────────────────────── GLOBALS ────────────────────────────

channel = ""
channel_id = None
stream_id = None
max_threads = 0
threads = []
thread_limit = None
active = 0
stop = False
start_time = None
lock = Lock()
connections = 0
attempts = 0
successful = 0
pings = 0
heartbeats = 0
disconnects = 0
viewers = 0
last_check = 0

proxy_list = []
proxy_lock = Lock()
proxy_index = 0
proxy_working = 0
proxy_failed = 0

session_durations = deque(maxlen=50)

ua = UserAgent()

# ──────────────────────── PROXY SCRAPER ────────────────────────

def fetch_url(url, timeout=10):
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except:
        return None

def is_valid_proxy(line):
    line = line.strip()
    if not line:
        return False
    return bool(re.match(r'^[a-zA-Z0-9\.\-]+:\d+$', line))

def normalize_proxy(p):
    p = p.strip()
    if not p.startswith("http://") and not p.startswith("https://") and not p.startswith("socks4://") and not p.startswith("socks5://"):
        p = f"http://{p}"
    return p

def scrape_proxies():
    print("[*] Scraping proxies from public sources...")
    all_proxies = set()
    for url in PROXY_SOURCES:
        try:
            text = fetch_url(url)
            if text:
                before = len(all_proxies)
                for line in text.splitlines():
                    line = line.strip()
                    if is_valid_proxy(line):
                        all_proxies.add(normalize_proxy(line))
                print(f"  [+] {url.split('/')[-1].split('?')[0]:30s} → +{len(all_proxies)-before:>4d}")
            else:
                print(f"  [-] {url.split('/')[-1].split('?')[0]:30s} → failed")
        except Exception as e:
            print(f"  [!] {url.split('/')[-1].split('?')[0]:30s} → {e}")
    pl = list(all_proxies)[:MAX_PROXIES]
    random.shuffle(pl)
    print(f"\n[+] Total scraped proxies: {len(pl)}")
    return pl

def load_proxies(path=PROXY_FILE):
    global proxy_list
    combined = set()
    if os.path.exists(path):
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    p = normalize_proxy(line)
                    cleaned = p.replace("http://","").replace("https://","").replace("socks4://","").replace("socks5://","")
                    if is_valid_proxy(cleaned):
                        combined.add(p)
        print(f"[+] Loaded {len(combined)} proxies from '{path}'")
    if AUTO_SCRAPE_PROXIES:
        combined.update(scrape_proxies())
    proxy_list = list(combined)
    random.shuffle(proxy_list)
    print(f"[+] Total proxies available: {len(proxy_list)}")
    return proxy_list

def get_next_proxy():
    global proxy_index
    if not proxy_list:
        return None
    with proxy_lock:
        p = proxy_list[proxy_index % len(proxy_list)]
        proxy_index += 1
        return p

# ──────────────────────── FINGERPRINT / HEADERS ────────────────────────

def random_fingerprint():
    return random.choice(["chrome_120","chrome_119","chrome_118","firefox_120","firefox_119","opera_100","opera_99","edge_120","edge_119"])

def random_headers(is_websocket_token=False):
    if is_websocket_token:
        return {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': random.choice(['en-US,en;q=0.9','en-GB,en;q=0.8','de-DE,de;q=0.9','fr-FR,fr;q=0.9']),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': ua.random,
            'sec-ch-ua': ua.random.strip('"'),
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': random.choice(['"Windows"','"macOS"','"Linux"']),
        }
    return {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': random.choice(['en-US,en;q=0.9','en-GB,en;q=0.8','de-DE,de;q=0.9']),
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': 'https://kick.com/',
        'Origin': 'https://kick.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': ua.random,
        'sec-ch-ua': ua.random.strip('"'),
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': random.choice(['"Windows"','"macOS"','"Linux"']),
    }

# ──────────────────────── API FUNCTIONS ────────────────────────

def clean_channel_name(channel_input):
    if "kick.com/" in channel_input:
        parts = channel_input.split("kick.com/")
        return parts[1].split("/")[0].split("?")[0].lower()
    return channel_input.lower()

def get_channel_info(channel_name):
    global channel_id, stream_id
    try:
        s = tls_client.Session(client_identifier=random_fingerprint(), random_tls_extension_order=True)
        s.headers.update(random_headers())
        try:
            r = s.get(f'https://kick.com/api/v2/channels/{channel_name}')
            if r.status_code == 200:
                d = r.json()
                channel_id = d.get("id")
                if d.get('livestream'):
                    stream_id = d['livestream'].get('id')
                return channel_id
        except:
            pass
        try:
            r = s.get(f'https://kick.com/{channel_name}')
            if r.status_code == 200:
                for pat in [r'"id":(\d+).*?"slug":"'+re.escape(channel_name)+r'"', r'"channel_id":(\d+)', r'channelId["\']:\s*(\d+)']:
                    m = re.search(pat, r.text, re.IGNORECASE)
                    if m:
                        channel_id = int(m.group(1))
                        break
                for pat in [r'"livestream":\s*\{[^}]*"id":(\d+)', r'livestream.*?"id":(\d+)']:
                    m = re.search(pat, r.text, re.IGNORECASE|re.DOTALL)
                    if m:
                        stream_id = int(m.group(1))
                        break
                if channel_id:
                    return channel_id
        except:
            pass
        print(f"[-] Failed to get info for: {channel_name}")
        return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None
    finally:
        if channel_id: print(f"[+] Channel ID: {channel_id}")
        if stream_id: print(f"[+] Stream ID: {stream_id}")

def get_token():
    for _ in range(3):
        try:
            s = tls_client.Session(client_identifier=random_fingerprint(), random_tls_extension_order=True)
            s.headers.update(random_headers(is_websocket_token=True))
            proxy = get_next_proxy()
            if proxy:
                try: s.proxies = {"http": proxy, "https": proxy}
                except: pass
            try: s.get("https://kick.com", timeout=15)
            except: pass
            s.headers["X-CLIENT-TOKEN"] = CLIENT_TOKEN
            r = s.get('https://websockets.kick.com/viewer/v1/token', timeout=15)
            if r.status_code == 200:
                d = r.json()
                token = d.get("data",{}).get("token") or d.get("token")
                if token:
                    if proxy:
                        with proxy_lock: proxy_working += 1
                    return token
        except:
            if proxy:
                with proxy_lock: proxy_failed += 1
            time.sleep(random.uniform(1,3))
    return None

def get_viewer_count():
    global viewers, last_check
    if not stream_id: return 0
    try:
        s = tls_client.Session(client_identifier="chrome_120", random_tls_extension_order=True)
        s.headers.update({'Accept': 'application/json', 'Referer': 'https://kick.com/', 'User-Agent': ua.random})
        r = s.get(f"https://kick.com/api/v2/channels/{channel}/livestream", timeout=10)
        if r.status_code == 200:
            viewers = r.json().get('viewer_count', 0)
            last_check = time.time()
            return viewers
    except: pass
    return 0

# ──────────────────────── STATS DISPLAY ────────────────────────

def draw_progress_bar(value, max_val, width=20):
    if max_val == 0: return "[" + "·" * width + "]"
    filled = int((value / max_val) * width)
    return "[" + "█" * filled + "░" * (width - filled) + "]"

def show_stats():
    global stop, start_time, connections, attempts, successful, pings
    global heartbeats, viewers, last_check, disconnects, proxy_working, proxy_failed
    print("\n\n\n\n\n\n\n")
    os.system('cls' if os.name == 'nt' else 'clear')
    while not stop:
        try:
            now = time.time()
            if now - last_check >= 5: get_viewer_count()
            with lock:
                dur_s = int((datetime.datetime.now() - start_time).total_seconds()) if start_time else 0
                h, m, s_ = dur_s // 3600, (dur_s % 3600) // 60, dur_s % 60
                duration = f"{h:02d}:{m:02d}:{s_:02d}"
                c, a, suc = connections, attempts, successful
                pi, he = pings, heartbeats
                disc, act = disconnects, active
                vd = viewers if viewers else '?'
                rate = suc / dur_s if dur_s > 0 else 0
                pw, pf = proxy_working, proxy_failed
                tp = len(proxy_list)
            lines = [
                "\033[H" + "═"*60,
                f"  KICK VIEWER BOT  ─  Channel: \033[36m{channel}\033[0m  ─  By: \033[35mMariann\033[0m",
                "═"*60,
                f"  \033[33mConnections\033[0m  {draw_progress_bar(c, max_threads)}  {c}/{max_threads}",
                f"  \033[33mAttempts\033[0m     {a:<6}  \033[32mOK\033[0m {suc:<6}  \033[31mFAIL\033[0m {a-suc:<6}",
                f"  \033[33mActive Thrs\033[0m  {act:<6}  \033[33mRate\033[0m {rate:<.2f}/s  \033[33mDisc\033[0m {disc}",
                f"  \033[33mPings\033[0m       {pi:<6}  \033[33mHeartbeats\033[0m {he:<6}  \033[33mDuration\033[0m {duration}",
                f"  \033[33mViewers\033[0m     {vd:<6}  \033[33mStream\033[0m {stream_id if stream_id else 'N/A':<10}  \033[33mChecked\033[0m {time.strftime('%H:%M:%S',time.localtime(last_check))}",
            ]
            if tp > 0:
                pb = draw_progress_bar(pw, pw+pf if pw+pf>0 else 1)
                lines.append(f"  \033[33mProxies\033[0m    {pb}  \033[32mOK\033[0m {pw:<4}  \033[31mFAIL\033[0m {pf:<4}  Pool: {tp}")
            else:
                lines.append(f"  \033[33mProxies\033[0m    \033[90mNot configured\033[0m")
            if session_durations:
                avg_s = sum(session_durations)/len(session_durations)
                lines.append(f"  \033[33mSessions\033[0m    Avg: {avg_s:.1f}s  Max: {max(session_durations):.1f}s  Sampled: {len(session_durations)}")
            lines.append("═"*60)
            lines.append("  \033[90mPress Ctrl+C to stop\033[0m")
            print("\033[" + str(len(lines)+1) + "A", end="")
            for line in lines:
                print("\033[2K" + line)
            sys.stdout.flush()
            time.sleep(1)
        except:
            time.sleep(1)

# ──────────────────────── WEBSOCKET ────────────────────────

async def websocket_handler(token):
    global connections, stop, channel_id, heartbeats, pings, successful, disconnects, session_durations
    connected = False
    session_start = time.time()
    try:
        url = f"wss://websockets.kick.com/viewer/v1/connect?token={token}"
        async with websockets.connect(url, ping_interval=None, ping_timeout=None, max_size=2**20, close_timeout=5) as ws:
            with lock: connections += 1; successful += 1
            connected = True
            await ws.send(json.dumps({"type":"channel_handshake","data":{"message":{"channelId":channel_id}}}))
            with lock: heartbeats += 1
            await asyncio.sleep(random.uniform(2,8))
            max_pings = random.randint(5,25)
            for _ in range(max_pings):
                if stop: break
                await ws.send(json.dumps({"type":"ping"}))
                with lock: pings += 1
                await asyncio.sleep(random.uniform(10,30) if random.random()>=0.1 else random.uniform(45,90))
            if random.random()<0.2:
                try: await ws.send(json.dumps({"type":"viewer_leave"}))
                except: pass
    except: pass
    finally:
        if connected:
            with lock: connections -= 1; disconnects += 1
            session_durations.append(time.time()-session_start)

def send_connection():
    global active, attempts, channel_id
    with lock: attempts += 1
    loop = None
    try:
        time.sleep(random.uniform(0,2.5))
        token = get_token()
        if not token: return
        if not channel_id:
            channel_id = get_channel_info(channel)
            if not channel_id: return
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(websocket_handler(token))
    except:
        pass
    finally:
        if loop is not None:
            try: loop.close()
            except: pass

def connect():
    global active
    with lock: active += 1
    try: send_connection()
    finally:
        with lock: active -= 1
        thread_limit.release()

# ──────────────────────── MAIN ────────────────────────

def run(thread_count, channel_name):
    global max_threads, channel, start_time, threads, thread_limit, channel_id, stop
    max_threads = int(thread_count)
    channel = clean_channel_name(channel_name)
    thread_limit = Semaphore(max_threads)
    start_time = datetime.datetime.now()
    channel_id = get_channel_info(channel)
    threads = []
    load_proxies()
    stats_thread = Thread(target=show_stats, daemon=True)
    stats_thread.start()
    steps = min(max_threads, 20)
    per_step = max(1, max_threads // steps)
    delay = 30.0 / steps
    print(f"[+] Ramping up {max_threads} connections over ~30s...")
    try:
        launched = 0
        while launched < max_threads and not stop:
            for _ in range(min(per_step, max_threads-launched)):
                if stop: break
                if thread_limit.acquire(timeout=1):
                    t = Thread(target=connect)
                    threads.append(t); t.daemon = True; t.start()
                    launched += 1; time.sleep(random.uniform(0.1,0.5))
            if launched < max_threads: time.sleep(delay)
        print("[+] Ramp-up complete. Monitoring...")
        while not stop:
            time.sleep(5)
            with lock: cur = connections
            if cur < max_threads*0.8 and not stop:
                for _ in range(min(max_threads-cur,5)):
                    if stop: break
                    if thread_limit.acquire(timeout=1):
                        t = Thread(target=connect)
                        threads.append(t); t.daemon = True; t.start()
                        time.sleep(random.uniform(0.5,1.5))
    except KeyboardInterrupt:
        stop = True
    print("\n[+] Cleanup...")
    for _ in range(max_threads*2):
        try: thread_limit.release()
        except: pass
    for t in threads: t.join(timeout=2)
    print(f"[+] Done. Total threads: {len(threads)}")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
        ci = input("Enter channel name or URL: ").strip()
        if not ci: print("Channel name needed."); sys.exit(1)
        while True:
            try:
                ti = int(input("Enter target viewer count: ").strip())
                if ti > 0: break
                else: print("Must be > 0")
            except ValueError: print("Enter a valid number")
        run(ti, ci)
    except KeyboardInterrupt:
        stop = True; print("\nStopping..."); sys.exit(0)
