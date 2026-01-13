# 🛡️ Live Network & Reputation Monitor

NetSentinel is a lightweight Python-based security tool that monitors established network connections in real-time. It automatically identifies the geographic location of remote IPs and checks their reputation using the **VirusTotal API** to detect potential threats.

## ✨ Features
- **Real-time Monitoring:** Tracks all active `ESTABLISHED` network connections.
- **Geolocation:** Identifies the country of origin for every remote IP.
- **Threat Intelligence:** Automatically scans "Unknown" processes or "Foreign" connections via VirusTotal.
- **Smart Logging:** Saves all session data into a clean `network_log.csv` file for later analysis.
- **API Protection:** Built-in rate limiting (15s cooldown) to stay within the VirusTotal Free API limits.

## 🚀 Getting Started

### 1. Prerequisites
Ensure you have Python 3.x installed. You will also need a **VirusTotal API Key**. You can get one for free at [VirusTotal](https://www.virustotal.com/).

### 2. Installation
Clone this repository or download the script, then install the required libraries:

```bash
pip install psutil requests

```

### 3. Configuration

Open `netstat.py` and replace the placeholder with your actual VirusTotal API key:

```python
VT_API_KEY = "your_api_key_here"

```

### 4. Running the Monitor

Run the script from your terminal:

```bash
python netstat.py

```

## 📊 Output Example

The terminal will display a live table of your connections:
| PID | PName | Remote Address | Country | VT Result |
| :--- | :--- | :--- | :--- | :--- |
| 17020 | msedge.exe | 172.188.155.25:443 | Singapore | CLEAN (0) |
| 6244 | MsMpEng.exe | 57.155.141.117:443 | Singapore | CLEAN (0) |

## 📁 Logging

All data is logged to `network_log.csv` in the following format:
`Timestamp, PID, Process Name, IP Address, Country, VT Result`

## ⚠️ Important: Rate Limiting

The VirusTotal Free API allows **4 requests per minute**. To protect your API key from being blocked, this script includes a **15-second pause** after every new scan. The monitor will continue after the scan is complete.

## 📜 License

This project is for educational purposes. Use it responsibly and only on systems you own or have permission to monitor.
