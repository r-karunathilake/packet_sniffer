# Packet Capture Program in C

This is a simple packet capture program written in C for Linux. It allows you to capture network packets and analyze their contents. This program uses the popular libpcap library to capture packets and provides a basic command-line interface for interacting with the program. 

## Features

- Capture network packets on a specified network interface.
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
- SSH:  `git@github.com:r-karunathilake/packet_sniffer.git`
- HTTPS:  `https://github.com/r-karunathilake/packet_sniffer.git`


2. Compile the program using your C compiler:
e.g. `gcc packet_capture.c -o packet_capture -lpcap`

## Usage

You can run the packet capture program by executing the following command:
`./packet_capture [options]`

Replace `[options]` with the following:

- `-l <log_file>`: (Optional) Specify the output file to save captured packets (in text format). Default is a "log.txt" file in the current working directory.  

- `-n <num_packets>`: (Optional) Specify the maximum number of packets to capture. Default is continuous capture until program is terminated. 

- `-i <interface>`: (Optional) Specify the network interface to capture packets (e.g., eth0). If not provided, the default interface is selected. 

- `-f <filter_pattern>`: (Optional) Specify packet filter string based on [TCPDump format](https://www.tcpdump.org/manpages/pcap-filter.7.html). 

- `-t <time>`: (Optional) Specify the time to run the capture in milliseconds. Default is 10 seconds. Note: this option overrides the number of packets. 

- `-h`: Display help and usage information. 

Example usage:
    `sudo ./packet_sniffer -i eth0 -n 20 -f "tcp or udp or icmp" -t 5000 -l captured_packets.txt`

This command shows a capture instance on `eth0` interface for `20` packets for `5 seconds`. Additionally, `tcp or udp or icmp` filter is configured. Finally, the captured output is logged to [`captured_packets.txt`](./captured_packets.txt). 

> Note: require super user privileges to run the program. 

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

