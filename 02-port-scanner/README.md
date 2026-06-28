# Python Port Scanner

## Description

A simple TCP port scanner written in Python.

This project scans TCP ports and checks whether ports are open or closed.

## Features

- Scan TCP ports
- Check open ports
- Custom IP target
- Custom port range

## Technologies

- Python
- Socket Library

## Lab Environment

Target:
Ubuntu Server running on VMware

## Usage

Run:

python port_scanner.py

Example:

Target IP:
192.168.254.129

Start Port:
20

End Port:
9000

## Version 0.3 Features

### Banner Detection

The scanner attempts to identify service information from open ports.

Example:

Port 22 OPEN

Banner:
SSH-2.0-OpenSSH