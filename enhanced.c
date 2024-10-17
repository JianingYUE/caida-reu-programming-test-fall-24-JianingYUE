#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int last_octet_counts[256] = {0};
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct ip *ip_header;
    int packet_count = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    // Loop to read each packet from the pcap file
    while ((packet = pcap_next(handle, &header)) != NULL) {
        // Extract the IP header, moving past the Ethernet header size
        ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        // Get the last octet of the destination IP address
        unsigned char last_octet = ip_header->ip_dst.s_addr & 0xFF;

        // Increment the corresponding count for this last octet
        last_octet_counts[last_octet]++;
        packet_count++;
    }

    // Close the pcap file handle
    pcap_close(handle);

    // Output the occurrences of each last octet that appeared at least once
    printf("\nOccurrences of last octet values:\n");
    for (int i = 0; i < 256; i++) {
        if (last_octet_counts[i] > 0) {
            printf("Last octet %d: %d\n", i, last_octet_counts[i]);
        }
    }

    printf("\nTotal packets processed: %d\n", packet_count);

    return 0;
}
