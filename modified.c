#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <net/ethernet.h> //change to MacOS
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct ip *ip_header; 
    int packet_count = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    // Open the pcap file
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    // Loop through each packet in the pcap file
    while ((packet = pcap_next(handle, &header)) != NULL) {

        // Move the pointer past the Ethernet header to reach the IP header
        ip_header = (struct ip*)(packet + sizeof(struct ether_header));

        printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(ip_header->ip_dst));
    }

    // Close the pcap handle
    pcap_close(handle);
    return 0;
}
