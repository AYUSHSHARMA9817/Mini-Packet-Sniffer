# Mini Packet Sniffer

A lightweight, multi-threaded C++ network packet sniffer with a Qt6 graphical interface. This application directly interfaces with the Linux networking stack using raw sockets to capture and parse live network traffic.

## Features
* **Live Capture:** Uses `AF_PACKET` raw sockets to capture live network frames.
* **Multi-threaded GUI:** Background packet capturing runs on a separate `QThread` to ensure the Qt6 UI remains responsive.
* **Protocol Parsing:** Manually extracts and parses headers for Layer 2, 3, and 4 protocols:
  * Ethernet
  * ARP
  * IPv4
  * TCP
  * UDP
  * ICMP
* **Payload Inspector:** Click on any packet to view its payload in both Hexadecimal and human-readable ASCII formats.
* **Export Data:** Save captured network packets and their parsed details to a `.txt` file for later analysis.

## Prerequisites
This application requires a Linux environment (Native Linux or Windows Subsystem for Linux) because it relies on Linux-specific raw sockets.

Install the required dependencies (Ubuntu/Debian):
```bash
sudo apt update
sudo apt install build-essential cmake ninja-build qt6-base-dev qt6-base-dev-tools
```
## Build Instructions
Clone the repository and build the project using CMake and Ninja:

``` Bash
git clone [https://github.com/AYUSHSHARMA9817/Mini-Packet-Sniffer.git](https://github.com/AYUSHSHARMA9817/Mini-Packet-Sniffer.git)
cd Mini-Packet-Sniffer
mkdir build && cd build
cmake -G "Ninja" ..
ninja
```
## Usage
Because the application opens raw network sockets, it requires administrator (root) privileges to run.
``` Bash
sudo ./QtPacketSniffer
```
* Select your network interface (e.g., eth0) from the dropdown.
* Click Start Capture.
* Select any packet in the table to view its raw hex dump and ASCII text data.
