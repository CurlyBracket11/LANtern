# LANtern — LAN Network Monitoring System

A lightweight LAN monitoring dashboard built with Python, Flask, and SQLite for a Computer Networks practical project.

## Features
- Register devices by name, IP address and (optionally) a TCP port
- Check reachability using ICMP ping (real RTT parsed from ping output)
- Check a TCP service (3-way handshake) – device counts as Online if ICMP *or* the TCP port responds
- Concurrent checks (thread pool), so many devices don't slow the cycle
- Uptime % per device, live-refreshing device table and history
- Subnet discovery: ping-sweep of your own /24 (private addresses only)
- Export monitoring history as CSV
- Store monitoring history in SQLite

## Requirements
- Python 3.10 or newer
- Windows, Linux, or macOS
- `ping` command available on the system

## Run on Windows (PowerShell)

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

If PowerShell blocks activation, run the install and app commands using `py -m pip install -r requirements.txt` and `py app.py` without activating the environment.

Open **http://127.0.0.1:5000** in your browser.

## How to use
1. Start the application.
2. Add a device name and its IP address.
3. The monitor checks registered devices every 10 seconds.
4. View current status, latency estimate, last-seen time, and recent checks.
5. Remove a device using the × button.

## Demo on multiple machines
```powershell
$env:LANTERN_HOST="0.0.0.0"; py app.py     # then open http://<your-LAN-IP>:5000 from another device
```
(Allow Python through the Windows firewall when prompted.)

## Notes
- Use this application only for devices on your own LAN or devices you are authorized to monitor.
- A device may appear Offline if its firewall blocks ICMP ping, even when it is otherwise working.
- The latency shown is an approximate round-trip measurement including command execution overhead.
- The dashboard binds to `127.0.0.1` by default, so it is accessible only from the computer running it.

## Project details
**Project:** LANtern — LAN Network Monitoring System  
**Subject:** Computer Networks  
**Program:** B.Tech, Computer Science & Technology  
**Semester:** V
