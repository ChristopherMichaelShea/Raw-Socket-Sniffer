# Raw-Socket-Sniffer

## Description

This program is a simple network packet sniffer. It records IP header information from packets on an open RAW socket using C/Linux on a specified network interface and displays information about them, including the source and destination IP addresses, the protocol, and the packet count.

## Installation

To install and run this program:

1. Clone the repository
2. Compile the program using gcc: `gcc -o sniffer sniffer.c`
3. Run the program as root: `sudo ./sniffer`

## Usage

To use this program, run it as root and specify the network interface you want to listen on. For example:

`sudo ./sniffer eth0`

The program will display information about each packet it captures.

## Code Details

This program uses raw sockets to capture packets directly from a network interface. It parses the IP and TCP/UDP headers of each packet to extract the source and destination IP addresses, the protocol, and the packet count.
