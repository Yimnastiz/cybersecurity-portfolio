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

## Version 0.4 Features

### Service Detection

The scanner maps common ports to known services.

Example:

22  -> SSH

80  -> HTTP

443 -> HTTPS


### Scan Summary

The tool reports the total number of open ports.

## Version 0.5 Features

### Command Line Interface

The scanner supports CLI arguments.

Example:

python port_scanner.py -t TARGET -s START_PORT -e END_PORT


Options:

-t  Target IP

-s  Start Port

-e  End Port

## Version 0.6 Features

- Multithreaded scanning
- Faster port scanning
- Reduced scan time using concurrent workers

# Version 0.7 - Export Scan Report

## New Features

- Export scan results to `scan_report.txt`
- Save scan date and time
- Store open ports and detected services
- Better project structure for portfolio

## Example

```text
Python Port Scanner Report
==========================

Target: 192.168.254.129

Scan Time:
2026-06-30 09:58:18

Open Ports

22 - SSH

# Version 0.8 - Scan Statistics

## New Features

- Measure scan execution time
- Display total scanned ports
- Wait for all threads before finishing
- Improved scan report

## Example Output

```text
--------------------
Scan Complete
--------------------

Target: 192.168.254.129
Ports Scanned: 7991
Open Ports: 2
Elapsed Time: 0.38 seconds

Report saved: scan_report.txt
```

## Report Example

```text
Python Port Scanner Report
==========================

Target: 192.168.254.129
Scan Time: 2026-06-30 10:15:20

Ports Scanned: 7991
Open Ports: 2
Elapsed Time: 0.38 seconds

Open Ports
----------
22 - SSH
8000 - HTTP-ALT
```

## Skills Learned

- Python ThreadPoolExecutor
- Future Objects
- concurrent.futures.wait()
- Performance Measurement
- Execution Time Analysis
- Report Enhancement