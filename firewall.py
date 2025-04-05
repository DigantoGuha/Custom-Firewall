from scapy.all import sniff, TCP, UDP, IP, IPv6
from datetime import datetime
import logging
import socket

# Setup logging to a file
logging.basicConfig(
    filename="firewall_log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# Get local machine IPs to help detect outgoing/incoming
local_ips = [socket.gethostbyname(socket.gethostname()), "127.0.0.1", "::1"]

# Firewall rules (customize as needed)
firewall_rules = [
    {"action": "BLOCK", "protocol": "TCP", "port": 22},   # SSH
    {"action": "ALLOW", "protocol": "TCP", "port": 80},   # HTTP
    {"action": "ALLOW", "protocol": "TCP", "port": 443},  # HTTPS
    {"action": "ALLOW", "protocol": "UDP", "port": 53},   # DNS
]

def log_packet(action, src_ip, dst_port, proto):
    now = datetime.now().strftime('%H:%M:%S')
    direction = "OUTGOING" if src_ip in local_ips else "INCOMING"
    msg = f"[{now}] [{action}] {direction} {proto} packet from {src_ip} to port {dst_port}"
    print(msg)
    logging.info(msg)

def monitor(packet):
    print("[🐍] Got a packet")

    proto = None
    dst_port = None
    src_ip = None

    if packet.haslayer(IP):
        src_ip = packet[IP].src
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src

    # TCP
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        proto = "TCP"
    # UDP
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport
        proto = "UDP"

    if src_ip and dst_port and proto:
        matched = False
        for rule in firewall_rules:
            if rule["protocol"] == proto and rule["port"] == dst_port:
                matched = True
                log_packet("❌ BLOCKED" if rule["action"] == "BLOCK" else "✅ ALLOWED", src_ip, dst_port, proto)
                return
        if not matched:
            log_packet("⚠️ UNFILTERED", src_ip, dst_port, proto)

# Start sniffing
print("🔒 Starting custom firewall... (Press Ctrl+C to stop)")
sniff(filter="ip or ip6", prn=monitor, store=False)
