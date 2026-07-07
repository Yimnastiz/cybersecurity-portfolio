CyberScope Packet Analyzer

A lightweight Packet Analyzer written in Python for learning Cyber Security, Network Programming, and Packet Analysis. CyberScope captures live network traffic using raw sockets and displays detailed Ethernet, IPv4, TCP, UDP, and ICMP information directly in the terminal.


Project Overview
CyberScope was developed as a learning project to understand how packet analyzers such as Wireshark work internally.

Instead of relying on existing libraries like Scapy, this project manually parses packet headers using Python's built-in modules.

The analyzer can:

Capture live network packets

Decode Ethernet Frames

Decode IPv4 Packets

Analyze TCP / UDP / ICMP

Detect common network services

Display TCP Flags and Connection States

Show Payload in Hex + ASCII

Filter traffic from the command line

Export captured output to a text report


Features
Live Packet Capture

Ethernet Frame Parsing

IPv4 Header Parsing

TCP Packet Analysis

UDP Packet Analysis

ICMP Packet Analysis

TCP Flag Detection

TCP Connection State Detection

Service Name Detection

Hex + ASCII Payload Dump

Colored Terminal Output

CLI Filters

Export Capture Report (.txt)

Capture Statistics


Technologies
Python 3

socket

struct

argparse

datetime

colorama

regular expressions (re)


Project Structure
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


Installation
Clone repository

git clone https://github.com/Yimnastiz/cybersecurity-portfolio.git

Go to project

cd cybersecurity-portfolio/04-CyberScope

Install dependency

pip install colorama


Usage
Capture all packets

sudo python cyberscope.py

Capture only TCP

sudo python cyberscope.py --tcp

Capture only UDP

sudo python cyberscope.py --udp

Capture only ICMP

sudo python cyberscope.py --icmp

Filter by Port

sudo python cyberscope.py --port 80

Filter by IP

sudo python cyberscope.py --ip 192.168.254.129

Save capture

sudo python cyberscope.py --save capture.txt


Example Output

==================================================
Packet #112

Timestamp : 2026-07-07 14:35:28

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
State : Connection Established

Payload
--------------------
0000  A0 F5 22 E4 ...


Command Line Options

| Option   | Description                         |
| -------- | ----------------------------------- |
| `--tcp`  | Capture TCP packets only            |
| `--udp`  | Capture UDP packets only            |
| `--icmp` | Capture ICMP packets only           |
| `--ip`   | Filter by IP address                |
| `--port` | Filter by port number               |
| `--save` | Save captured output to a text file |


Development Timeline
v0.1
Raw Socket Packet Capture

v0.2
Ethernet Frame Parser

v0.3
IPv4 Packet Parser

v0.4
TCP Packet Parser

v0.5
UDP & ICMP Support

v0.6
CLI Filters

v0.7
Service Detection

v0.8
TCP Connection State Detection

v0.9
Payload Hex Dump

Colored Terminal Output

Export Report (.txt)

v1.0.0
Code Refactoring

Better Project Structure

Packet Summary

Capture Statistics

Stable Release

Skills Learned
Raw Socket Programming

Network Packet Analysis

Ethernet Frame Structure

IPv4 Header Parsing

TCP Header Parsing

UDP Protocol

ICMP Protocol

Binary Data Parsing (struct)

Command Line Interface Development

File Export

Clean Code Organization

Network Troubleshooting


Future Roadmap
v1.1
JSON Export

v1.2
DNS Parser

v1.3
HTTP Request Detection

v1.4
HTTPS SNI Detection

v1.5
ARP Packet Analysis

v2.0
PCAP Export

Flow Statistics

Better Filtering Engine

Interactive Terminal Dashboard


Author
Punnawit

Cyber Security Student

GitHub

https://github.com/Yimnastiz