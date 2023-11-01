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
#include <string.h>       // For strcpy()
#include <pcap.h>         // Access copies of packets off the wire.
#include <stdlib.h>       // For exit()
#include <netinet/in.h>   // 'in_addr' structure declaration used by 'inet_ntoa()'
#include <arpa/inet.h>    // Provides 'inet_ntoa()' declaration
#include <net/ethernet.h> // Provides ethernet header declaration

FILE *logFile = NULL;

// Function prototypes
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(int argc, char *argv[])
{
  pcap_t *pHandle;                    // Session handle
  pcap_if_t *pAllDevices = NULL;      // List of network interfaces
  pcap_if_t *pDevice = NULL;          // A network interface
  char *pDeviceName = NULL;           // The network interface name to be sniffed
  char errorBuffer[PCAP_ERRBUF_SIZE]; // Error string of size 256
  char *ip_addr = NULL;               // Dot notation IP address
  char *mask_addr = NULL;             // Dot notation mask address
  bpf_u_int32 mask;                   // Interface network mask
  bpf_u_int32 ip;                     // Interface IP
  struct bpf_program filter;          // Compiled filter structure 
  u_char *callbackArgs;               // Arguments for 'process_packet()'
 
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
  ip_addr = inet_ntoa(addr);
  if (ip_addr == NULL)
  {
    perror("inet_ntoa()");
    exit(EXIT_FAILURE);
  }
  printf("  IP: %s\n", ip_addr);

  addr.s_addr = mask;
  mask_addr = inet_ntoa(addr);
  if (mask_addr == NULL)
  {
    perror("inet_ntoa()");
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

  if(argc > 2){
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
  fprintf(stdout, "Finished processing packets. Running clean-up ...\n");

  // Free all the devices from memory
  printf("Freeing all network devices and closing session ... ");
  pcap_freealldevs(pAllDevices);
  pcap_close(pHandle); // Close session
  printf("Done\n");
  exit(EXIT_SUCCESS);
}

void process_packet(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet)
{
  static int count = 1;
  fprintf(stdout, "Packet count: %d\n", count);

  fflush(stdout);
  count++;
}
