# 🔥 Custom Python Firewall

A lightweight firewall built in Python using Scapy. It monitors incoming TCP packets and allows/block traffic based on custom rules.

## 🚀 Features

- Block or allow traffic by port
- Logs every TCP packet with source IP and port
- Supports both IPv4 and IPv6
- Easy to extend with new rules

## 📄 Example Output

[🐍] Got a packet [✅ ALLOWED] Packet from 127.0.0.1 to port 80 [❌ BLOCKED] Packet from 192.168.1.1 to port 22 [⚠️ UNFILTERED] Packet from 10.0.0.2 to port 3000 (no rule)


## 📦 Installation

```bash
git clone https://github.com/DigantoGuha/Custom-Firewall.git
cd custom-firewall
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


📈 Future Plans

Live dashboard to visualize packets
Rule config via JSON
Blocking IPs dynamically


## 📝 License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for details.

