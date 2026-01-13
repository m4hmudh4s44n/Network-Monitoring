import psutil
import requests
import time

# --- CONFIGURATION ---
VT_API_KEY = "YOUR_API_KEY_HERE"  # <--- Put your key here
checked_ips = {}
checked_vt = {}

def get_country(ip):
    if ip in checked_ips: return checked_ips[ip]
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        country = response.get('country', 'Unknown')
        checked_ips[ip] = country
        return country
    except: return "Error"

def get_vt_score(ip):
    if ip in checked_vt: return checked_vt[ip]
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            res = "MALICIOUS" if malicious > 0 else "CLEAN"
            checked_vt[ip] = f"{res} ({malicious})"
            return checked_vt[ip]
        return "Error"
    except: return "Timeout"

def monitor_network():
    # Adjusted header for the new column
    print(f"{'PID':<8} {'PName':<18} {'Remote Address':<22} {'Country':<15} {'VT Result':<12}")
    print("-" * 85)
    
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED' and conn.raddr:
            pid = conn.pid
            try: p_name = psutil.Process(pid).name()
            except: p_name = "Unknown"
            
            ip = conn.raddr.ip
            country = get_country(ip)
            
            # VirusTotal Check (only if it's not a local IP)
            vt_result = "N/A"
            if not ip.startswith(("127.", "192.168.", "10.")):
                vt_result = get_vt_score(ip)
                # Keep the 15s delay ONLY if we actually hit the API
                # to stay under the 4-per-minute limit
                time.sleep(15) 

            r_addr = f"{ip}:{conn.raddr.port}"
            print(f"{pid:<8} {p_name:<18} {r_addr:<22} {country:<15} {vt_result:<12}")

if __name__ == "__main__":
    monitor_network()