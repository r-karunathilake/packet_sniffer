/*
  This is a packet sniffer program created using the libpcap
  library for low-level network access. The program is written and
  tested in Ubuntu.

	Ubuntu version:         22.04.3 LTS
	lippcap version:        1.10.1
	C/C++ compiler version: GCC 11.4.0
	Linux kernel version:   5.15.90.1-microsoft-standard-WSL2

  Author: Ravindu Karunathilake
  Date: 2023/10/31
*/

#include <stdio.h>
#include <string.h>		   // For strcpy() and memset() 
#include <pcap.h>		   // Access copies of packets off the wire.
#include <stdlib.h>		   // For exit()
#include <netinet/in.h>	   // 'in_addr' structure declaration used by 'inet_ntoa()'
#include <netinet/ether.h> // Provides 'ether_nota()' and 'ether_addr()'
#include <arpa/inet.h>	   // Provides 'inet_ntoa()' declaration
#include <net/ethernet.h>  // Provides ethernet header declaration
#include <netinet/ip.h>	   // Provides IP header declaration

FILE *logFile = NULL;
// Count the number of packets
static int total = 0;
static int icmp_count = 0;
static int igmp_count = 0;
static int tcp_count = 0;
static int udp_count = 0;
static int other_count = 0;
static int invalid_count = 0;

// Function prototypes
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void log_ethernet_header(u_char *, const u_char *);
void log_ip_header(u_char *, const u_char *);
void log_icmp_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int get_ip_protocol(u_char *, const struct pcap_pkthdr *, const u_char *);
u_int16_t get_eth_protocol(u_char *, const u_char *);

int main(int argc, char *argv[])
{
	pcap_t *pHandle;					// Session handle
	pcap_if_t *pAllDevices = NULL;		// List of network interfaces
	pcap_if_t *pDevice = NULL;			// A network interface
	char *pDeviceName = NULL;			// The network interface name to be sniffed
	char errorBuffer[PCAP_ERRBUF_SIZE]; // Error string of size 256
	const char *ip_addr = NULL;		    // Dot notation IP address
	const char *mask_addr = NULL;		// Dot notation mask address
	bpf_u_int32 mask;					// Interface network mask
	bpf_u_int32 ip;						// Interface IP
	struct bpf_program filter;			// Compiled filter structure
	u_char *callbackArgs;				// Arguments for 'process_packet()'

	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <maximum_packets_to_capture> <optional: filter>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	// Get a list of all available devices
	printf("Finding available devices ... ");
	if (pcap_findalldevs(&pAllDevices, errorBuffer))
	{
		fprintf(stderr, "Encountered an error in finding devices : %s", errorBuffer);
		exit(EXIT_FAILURE);
	}
	printf("Done\n");

	printf("Found following devices:\n");
	int deviceNum = 1;
	for (pDevice = pAllDevices; pDevice != NULL; pDevice = pDevice->next)
	{
		// Select the default interface (first in the list)
		if (deviceNum == 1)
		{
			pDeviceName = pDevice->name;
		}
		printf("  %d. %s - %s\n", deviceNum, pDevice->name, pDevice->description);
		deviceNum++;
	}

	printf("\nSelecting default device ... \n");
	// Get the device IP and mask in byte order
	if (pcap_lookupnet(pDeviceName, &ip, &mask, errorBuffer) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", pDeviceName,
				errorBuffer);
		ip = 0;
		mask = 0;
	}
	printf("  Device: %s\n", pDeviceName);

	// Convert the IP and mask from bytes to IPv4 dotted-decimal notation
	struct in_addr addr; // IPv4 address conversion structure
	addr.s_addr = ip;

	char writeBuffer[INET_ADDRSTRLEN];
	ip_addr = inet_ntop(AF_INET, &addr, writeBuffer, INET_ADDRSTRLEN);
	if (ip_addr == NULL)
	{
		perror("inet_ntop()");
		exit(EXIT_FAILURE);
	}
	printf("  IP: %s\n", ip_addr);

	addr.s_addr = mask;
	mask_addr = inet_ntop(AF_INET, &addr, writeBuffer, INET_ADDRSTRLEN);
	if (mask_addr == NULL)
	{
		perror("inet_ntop()");
		exit(EXIT_FAILURE);
	}
	printf("  Mask: %s\n", mask_addr);

	// Sniffing in promiscuous mode
	printf("\nOpening device '%s' for sniffing ... ", pDeviceName);
	pHandle = pcap_open_live(pDeviceName, BUFSIZ, 1, 10000, errorBuffer);
	if (pHandle == NULL)
	{
		fprintf(stderr, "Couldn't open device '%s': %s\n", pDeviceName, errorBuffer);
		exit(EXIT_FAILURE);
	}
	printf("Done\n");

	// Open a log file handler for traffic parsing output
	logFile = fopen("log.txt", "w");
	if (logFile == NULL)
	{
		printf("WARNING: Unsuccessful in creating log file!");
	}

	if (argc > 2)
	{
		// Compile and apply packet filter
		if (pcap_compile(pHandle, &filter, argv[2], 0, mask) == -1)
		{
			fprintf(stderr, "Error compiling packet filter: %s\n", argv[2]);
			exit(EXIT_FAILURE);
		}
		if (pcap_setfilter(pHandle, &filter) == -1)
		{
			fprintf(stderr, "Unable to set requested packet filter: %s\n", argv[2]);
			exit(EXIT_FAILURE);
		}
	}

	/* Put the selected device in a packet capture loop with callback function
	'process_packet()' */
	pcap_loop(pHandle, atoi(argv[1]), process_packet, callbackArgs);

	// Free all the devices from memory
	printf("Freeing all network devices and closing session ... ");
	pcap_freealldevs(pAllDevices);
	pcap_close(pHandle); // Close session
	printf("Done\n");

	printf("\n\nICMP: %d  IGMP: %d  TCP: %d  UDP: %d  Other: %d  Total: %d\n",
		   icmp_count, igmp_count, tcp_count, udp_count, other_count, total);
	exit(EXIT_SUCCESS);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header,
					const u_char *packet)
{
	// Get the ethernet protocol type
	u_int16_t packetType = get_eth_protocol(args, packet);

	// Parse IP packet
	if (packetType == ETHERTYPE_IP)
	{
		int ipProtocol = get_ip_protocol(args, header, packet);
		switch (ipProtocol) // See RFC 790 for protocol-value mapping
		{
		case 1: // ICMP protocol
			++icmp_count;
			log_icmp_packet(args, header, packet);
			break;

		case 2: // IGMP protocol
			++igmp_count;
			printf("Received IGMP packet!\n");
			break;

		case 6: // TCP protocol
			++tcp_count;
			printf("Received TCP packet!\n");
			break;

		case 17: // UDP protocol
			++udp_count;
			printf("Received UDP packet!\n");
			break;

		case -1: // Invalid packet
			++invalid_count;
			printf("Received Invalid packet! Dumping raw data to log");
			break;

		default: // Another protocol like Telnet
			++other_count;
			printf("Received other packet!\n");
			break;
		}
	}
	else if (packetType == ETHERTYPE_ARP)
	{
		// Handle ARP packet
	}
	else if (packetType == ETHERTYPE_REVARP)
	{
		// Handle reverse ARP packet
	}
}

uint16_t get_eth_protocol(u_char *args, const u_char *packet)
{
	struct ether_header *pEthernetHeader; // Declared in 'net/ethernet.h'
	pEthernetHeader = (struct ether_header *)packet;

	return ntohs(pEthernetHeader->ether_type);
}

int get_ip_protocol(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct iphdr *pIPHeader = (struct iphdr *)(packet + sizeof(struct ether_header));
	u_int size = header->len;
	if (size < sizeof(struct iphdr))
	{
		fprintf(stderr, "Warning: * Truncated IP packet detected (expected %lu bytes got %d bytes)", sizeof(struct iphdr), size);
		return -1; // Invalid protocol
	}

	// IP header has no fixed length; its length is given in 4-byte words
	u_int ipHeaderLength = pIPHeader->ihl * 4;
	if (ipHeaderLength < 20)
	{
		printf("Warning: * Invalid IP header length: %u bytes (expected minimum 20 bytes)\n", ipHeaderLength);
		return -1;
	}

	++total; // Valid IP packet detected
	return (int)pIPHeader->protocol;
}

void log_icmp_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	fprintf(logFile, "\n===================================ICMP Packet===================================");
	log_ethernet_header(args, packet);
	log_ip_header(args, packet);

	// fprintf(logFile, "\n*********************************************************************************");
}

void log_ethernet_header(u_char *args, const u_char *packet)
{
	struct ether_header *pEthernetHeader; // Declared in 'net/ethernet.h'
	pEthernetHeader = (struct ether_header *)packet;

	// Convert ethernet address to ASCII
	fprintf(logFile, "\n");
	fprintf(logFile, "Ethernet Header\n");
	fprintf(logFile, "    | Destination MAC: %s \n", ether_ntoa((const struct ether_addr *)pEthernetHeader->ether_shost));
	fprintf(logFile, "    | Source MAC     : %s \n", ether_ntoa((const struct ether_addr *)pEthernetHeader->ether_dhost));

	// Print the ethernet protocol type
	const uint16_t protocol = ntohs(pEthernetHeader->ether_type);
	switch (protocol)
	{
	case ETHERTYPE_IP: // IPv4 type
		fprintf(logFile, "    | Protocol       : IP \n");
		break;

	case ETHERTYPE_ARP:
		fprintf(logFile, "    | Protocol       : ARP \n");
		break;

	case ETHERTYPE_REVARP:
		fprintf(logFile, "    | Protocol       : RARP \n");
		break;

	default: // Some other ethernet protocol. See 'net/ethernet.h'
		fprintf(logFile, "    | Protocol       : ? (%d) \n", protocol);
		break;
	}
}

void log_ip_header(u_char *args, const u_char *packet)
{
	// Parse and log IPv4 header 
	struct iphdr *pIPHeader = (struct iphdr *)(packet + sizeof(struct ether_header));

	// See RFC 791
	fprintf(logFile, "\n");
	fprintf(logFile, "IP Header\n");
	fprintf(logFile, "    | IP Version             : %u \n", pIPHeader->version);
	fprintf(logFile, "    | Header Length          : %u Bytes \n", pIPHeader->ihl * 4);
	fprintf(logFile, "    | Type of Service        : %u \n", pIPHeader->tos);
	fprintf(logFile, "    | Total Length           : %u Bytes \n", ntohs(pIPHeader->tot_len));
	fprintf(logFile, "    | Identification         : %u \n", ntohs(pIPHeader->id));
	fprintf(logFile, "    | Fragment Offset        : %u Bytes \n", ntohs(pIPHeader->frag_off));
	fprintf(logFile, "    | Time to Live           : %u \n", pIPHeader->ttl);
	fprintf(logFile, "    | Transport Protocol     : %u \n", pIPHeader->protocol);
	fprintf(logFile, "    | Checksum               : %u \n", ntohs(pIPHeader->check));

	// Parse the source and destination IP addresses
	char writeBuffer[INET_ADDRSTRLEN];
	struct in_addr sourceAddr;
	struct in_addr destAddr;

	sourceAddr.s_addr = pIPHeader->saddr;
	destAddr.s_addr = pIPHeader->daddr;

	fprintf(logFile, "    | Source IP Address      : %s \n", inet_ntop(AF_INET, &sourceAddr, 
	                                                                   writeBuffer, INET_ADDRSTRLEN));
	fprintf(logFile, "    | Destination IP Address : %s \n", inet_ntop(AF_INET, &destAddr, 
	                                                                   writeBuffer, INET_ADDRSTRLEN));
}


