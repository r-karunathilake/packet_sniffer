/*
  This is a packet sniffer program created using the libpcap
  library for low-level network access. The program is written and
  tested in Ubuntu.

    Ubuntu version:         22.04.3 LTS
    lippcap version:        1.10.1
    C/C++ compiler version: GCC 11.4.0

  Author: Ravindu Karunathilake
  Date: 2023/10/31
*/

#include <stdio.h>
#include <pcap.h>   // Access to low-level network
#include <stdlib.h> // for exit()

FILE *logfile = NULL;

// Function prototypes
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(int argc, char *argv[])
{

  // Setting the correct device for sniffing
  pcap_if_t *pAllDevices = NULL;
  pcap_if_t *pDevice = NULL;
  char errorBuffer[PCAP_ERRBUF_SIZE]; // Size 256

  // Get a list of all available devices
  printf("Finding available devices ... ");
  if (pcap_findalldevs(&pAllDevices, errorBuffer))
  {
    fprintf(stderr, "Encountered an error in finding devices : %s", errorBuffer);
    exit(1);
  }
  printf("Done\n");

  // Print a list of available devices
  printf("Found following devices:\n");
  int deviceNum = 1;
  for (pDevice = pAllDevices; pDevice != NULL; pDevice = pDevice->next)
  {
    printf("%d. %s - %s\n", deviceNum, pDevice->name, pDevice->description);
    deviceNum++;
  }

  // Prompt the user to select an interface for sniffing
  char deviceName[20];
  printf("Enter the name of the interface to sniff: ");
  if (scanf("%s", deviceName) != 1)
  {
    printf("Error: invalid user input\n");
    exit(1);
  }

  // Open the device for sniffing in promiscuous mode
  printf("Opening device '%s' for sniffing ... ", deviceName);
  pcap_t *handle;
  handle = pcap_open_live(deviceName, BUFSIZ, 1, 1000, errorBuffer);
  if (handle == NULL)
  {
    fprintf(stderr, "Couldn't open device '%s': %s\n", deviceName, errorBuffer);
  }
  printf("Done\n");

  // Open a log file handler for traffic parsing output
  logfile = fopen("log.txt", "w");
  if (logfile == NULL)
  {
    printf("Unsuccessful in creating log file!");
  }

  // Put the selected device in a packet capture loop with callback function
  // 'process_packet()'
  pcap_loop(handle, -1, process_packet, NULL);

  // Free all the devices from memory
  pcap_freealldevs(pAllDevices);
  pcap_close(handle); // Close session
  return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet)
{

  printf("Inside 'process_packet()'");
}
