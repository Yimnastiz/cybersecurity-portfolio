# CyberScope Packet Analyzer

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Version](https://img.shields.io/badge/version-1.0.0-success)
![Status](https://img.shields.io/badge/status-Stable-brightgreen)

A lightweight Packet Analyzer written in Python for learning Cyber Security, Network Programming, and Packet Analysis.

---

# Project Overview

CyberScope is a packet analyzer developed to understand how network analyzers work internally by using raw sockets and manually parsing network packets without external packet analysis libraries.

The analyzer can:

- Capture live network packets
- Parse Ethernet Frames
- Parse IPv4 Packets
- Analyze TCP / UDP / ICMP
- Detect common network services
- Display TCP Flags
- Detect TCP Connection States
- Display Payload in Hex + ASCII
- Filter packets using CLI arguments
- Export captured output to a text report

---

# Features

- Live Packet Capture
- Ethernet Frame Parsing
- IPv4 Packet Parsing
- TCP Analysis
- UDP Analysis
- ICMP Analysis
- TCP Flag Detection
- TCP Connection State Detection
- Service Detection
- Payload Hex Dump
- Colored Terminal Output
- CLI Filters
- Export Report (.txt)
- Capture Statistics

---

# Technologies

- Python 3
- socket
- struct
- argparse
- datetime
- colorama
- re

---

# Project Structure

```text
04-CyberScope/
│
├── cyberscope.py
├── README.md
├── capture.txt
└── images/
    ├── startup_v1.0.0.png
    ├── tcp_packet_v1.0.0.png
    ├── udp_packet_v1.0.0.png
    ├── payload_v1.0.0.png
    └── statistics_v1.0.0.png
```

---

# Screenshots

## Program Startup

![Startup](screenshots/startup_v1.0.0.png)

## TCP Packet

![TCP](screenshots/tcp_packet_v1.0.0.png)

## UDP Packet

![UDP](screenshots/udp_packet_v1.0.0.png)

## Payload

![Payload](screenshots/payload_v1.0.0.png)

## Statistics

![Statistics](screenshots/statistics_v1.0.0.png)

---

# Installation

Clone the repository

```bash
git clone https://github.com/Yimnastiz/cybersecurity-portfolio.git
```

Go to the project

```bash
cd cybersecurity-portfolio/03-cyberscope-packet-analyzer
```

Install dependency

```bash
pip install colorama
```

---

# Usage

Capture all packets

```bash
sudo python cyberscope.py
```

Capture TCP packets only

```bash
sudo python cyberscope.py --tcp
```

Capture UDP packets only

```bash
sudo python cyberscope.py --udp
```

Capture ICMP packets only

```bash
sudo python cyberscope.py --icmp
```

Filter by IP

```bash
sudo python cyberscope.py --ip 192.168.254.129
```

Filter by Port

```bash
sudo python cyberscope.py --port 22
```

Save capture

```bash
sudo python cyberscope.py --save capture.txt
```

---

# Example Output

```text
==================================================
CyberScope v1.0.0
==================================================

Packet #52

Timestamp : 2026-07-07 14:32:18

Ethernet
--------------------
Source MAC : 00:0C:29:35:AE:98
Dest MAC   : 00:50:56:C0:00:08

IPv4
--------------------
Protocol : TCP
Source IP : 192.168.254.129
Dest IP   : 192.168.254.1

[TCP] 192.168.254.129:22 -> 192.168.254.1:58861 [ACK,PSH]

TCP
--------------------
Source Port : 22
Dest Port   : 58861
Source Service : SSH
Dest Service   : Unknown
State : Connection Established

Payload
--------------------
0000  A0 F5 22 E4 9D C1 ...
```

---

# Command Line Arguments

| Argument | Description |
|----------|-------------|
| `--tcp` | Capture TCP packets only |
| `--udp` | Capture UDP packets only |
| `--icmp` | Capture ICMP packets only |
| `--ip` | Filter packets by IP address |
| `--port` | Filter packets by port |
| `--save` | Save output to a text file |

---

# Development Timeline

### v0.1

- Raw Socket Capture

### v0.2

- Ethernet Parser

### v0.3

- IPv4 Parser

### v0.4

- TCP Parser

### v0.5

- UDP & ICMP Support

### v0.6

- Command Line Filters

### v0.7

- Service Detection

### v0.8

- TCP State Detection

### v0.9

- Payload Hex Dump
- Colored Output
- Export Report (.txt)

### v1.0.0

- Code Refactoring
- Packet Summary
- Capture Statistics
- Stable Release

---

# Skills Learned

- Raw Socket Programming
- Network Packet Analysis
- Ethernet Frame Parsing
- IPv4 Packet Parsing
- TCP Protocol
- UDP Protocol
- ICMP Protocol
- Binary Data Parsing
- Command Line Interface Development
- File Handling
- Clean Code Structure

---

# Future Roadmap

### v1.1

- JSON Export

### v1.2

- DNS Packet Parsing

### v1.3

- HTTP Request Detection

### v1.4

- ARP Packet Support

### v2.0

- PCAP Export
- Network Flow Statistics
- Interactive Terminal Dashboard

---

# Author

**Punnawit**

Cyber Security Student

GitHub

https://github.com/Yimnastiz