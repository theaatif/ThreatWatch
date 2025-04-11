import pyshark
import re
import signal
import sys
import time
import requests
from datetime import datetime
from plyer import notification
from pyshark.tshark.tshark import get_tshark_interfaces

VT_API_KEY = ""  # Add your VirusTotal API key here

is_running = True
domain_cache = {}

def normalize_domain(domain):
    domain = domain.lower()
    domain = re.sub(r'^www\d*\.', '', domain)
    domain = re.sub(r':\d+$', '', domain)
    return domain

def notify(title, message):
    try:
        notification.notify(
            title=title,
            message=message,
            timeout=5,
            app_name="Network Threat Monitor"
        )
    except Exception as e:
        print(f"❌ Notification error: {e}")

def log_traffic(timestamp, protocol, alert_type, domain):
    try:
        with open("traffic_log.txt", "a", encoding="utf-8") as log_file:
            log_file.write(f"[{timestamp}] [{protocol}] {alert_type} {domain}\n")
    except Exception as e:
        print(f"❌ Logging error: {e}")

def check_virustotal(domain):
    if domain in domain_cache:
        return domain_cache[domain]

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            domain_cache[domain] = malicious_count > 0
            return malicious_count > 0
    except Exception as e:
        print(f"❌ VirusTotal error for {domain}: {e}")

    return False

def packet_callback(packet):
    if not is_running:
        return

    try:
        protocol = "UNKNOWN"
        host = None

        if hasattr(packet, 'http'):
            host = packet.http.host
            protocol = "HTTP"
        elif hasattr(packet, 'tls') and hasattr(packet.tls, 'handshake_extensions_server_name'):
            host = packet.tls.handshake_extensions_server_name
            protocol = "HTTPS"

        if not host:
            return

        domain = normalize_domain(host)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        is_malicious = check_virustotal(domain)

        if is_malicious:
            alert_type = "⚠ VT DETECTED"
            print(f"[{timestamp}] [{protocol}] [{alert_type}] {domain}")
            log_traffic(timestamp, protocol, alert_type, domain)
            notify("⚠ VirusTotal Threat Detected", f"{protocol}: {domain} flagged as malicious!")
        else:
            print(f"[{timestamp}] [{protocol}] [✔ SAFE] {domain}")
            log_traffic(timestamp, protocol, "✔ SAFE", domain)

    except Exception as e:
        print(f"❌ Packet error: {e}")

def choose_interface():
    print("🌐 Detecting interfaces...")
    try:
        interfaces = get_tshark_interfaces()
        for idx, iface in enumerate(interfaces, 1):
            print(f"{idx}. {iface}")
        choice = int(input("\n👉 Enter the interface number to monitor: "))
        return interfaces[choice - 1]
    except Exception as e:
        print(f"❌ Interface error: {e}")
        sys.exit(1)

def handle_exit(sig, frame):
    global is_running
    print("\n✅ Stopping monitoring...")
    is_running = False
    time.sleep(1)
    print("👋 Exited gracefully.")
    sys.exit(0)

def main():
    global is_running
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    print("📡 Starting HTTP/HTTPS Packet Monitor with VirusTotal Integration...")
    interface = choose_interface()

    capture = pyshark.LiveCapture(interface=interface, display_filter="http or tls")

    try:
        capture.apply_on_packets(packet_callback)
    except KeyboardInterrupt:
        handle_exit(None, None)
    except Exception as e:
        print(f"❌ Capture error: {e}")
        handle_exit(None, None)

if __name__ == "__main__":
    main()
