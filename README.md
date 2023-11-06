# Packet Capture Program in C

This is a simple packet capture program written in C for Linux. It allows you to capture network packets and analyze their contents. This program uses the popular libpcap library to capture packets and provides a basic command-line interface for interacting with program. 

## Features

- Capture network packets on a specified network interface. (To be implemented, currently only default interface)
- Add network filter to the capture. See [tcpdump filters](https://www.tcpdump.org/manpages/pcap-filter.7.html). 
- Specify number of packets to capture. 
- Parse packet details such as source and destination IP addresses, protocols, etc. 
- Save captured packets to a log file for later analysis.

## Prerequisites

Before using this program, ensure you have the following prerequisites installed:
- Linux OS
- C Compiler (e.g., GCC)
- libpcap library

## Installation

1. Clone this repository to your local machine:
SSH:  `git@github.com:r-karunathilake/packet_sniffer.git`
HTTPS:  `https://github.com/r-karunathilake/packet_sniffer.git`


2. Compile the program using your C compiler:
e.g. `gcc packet_capture.c -o packet_capture -lpcap`

## Usage

You can run the packet capture program by executing the following command:
`./packet_capture [options]`

Replace `[options]` with the following:

- `-i <interface>`: (Optional) Specify the network interface to capture packets (e.g., eth0). If not provided, the default interface is selected. (To be implemented soon)

- `-f <filename>`: (Optional) Specify the output file to save captured packets (in text format). (To be implemented soon)

- `-h`: Display help and usage information. (To be implemented soon)

Example usage:
    `./packet_capture -i eth0 -f captured_packets.txt`

## License
This packet capture program is open-source and available under the [MIT License](https://opensource.org/license/mit/).

## Author
    Ravindu Karunathilake 
    Email: karunath@ualberta.ca
    GitHub: https://github.com/r-karunathilake

## References 

1. [Programming with PCAP ](https://www.tcpdump.org/pcap.html) by Tim Carstens
2. [Packet Sniffer in C](https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/)
3. [The Sniffer's Guide to Raw Traffic](http://yuba.stanford.edu/~casado/pcap/section1.html)

