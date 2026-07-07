# CyberScope

Python Raw Socket Packet Analyzer

Features

- Ethernet
- IPv4
- TCP
- UDP
- ICMP
- Packet Summary
- TCP Flags
- Payload Viewer
- Hex Dump
- Save Capture
- Packet Filters


Requirements

Python 3.10+

pip install colorama


Usage

sudo python3 cyberscope.py

sudo python3 cyberscope.py --tcp

sudo python3 cyberscope.py --udp

sudo python3 cyberscope.py --icmp

sudo python3 cyberscope.py --port 80

sudo python3 cyberscope.py --ip 8.8.8.8

sudo python3 cyberscope.py --save capture.txt