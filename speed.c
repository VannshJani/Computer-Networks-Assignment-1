#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>

static int packet_count = 0;
static int total_bytes = 0;
static time_t start_time;
pcap_t *handle = NULL;

void handle_sigint(int sig) {
    if (handle != NULL) {
        pcap_breakloop(handle);
    }
    printf("\nStopping packet capture...\n");
    printf("Total Packets Received: %d\n", packet_count);
    printf("Total Data Transferred: %d bytes\n", total_bytes);

    time_t end_time = time(NULL);
    double duration = difftime(end_time, start_time);
    // Print even if duration == 0
    double pps  = (duration > 0) ? (packet_count / duration) : 0;
    double mbps = (duration > 0) ? ((total_bytes * 8.0) / (duration * 1000000.0)) : 0;

    printf("Capture Duration: %.2f seconds\n", duration);
    printf("Speed: %.2f packets per second (pps)\n", pps);
    printf("Speed: %.2f Mbps\n", mbps);

    exit(0);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    packet_count++;
    total_bytes += header->caplen;
    printf("Packet %d received, Size: %d bytes\n", packet_count, header->caplen);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <network_interface>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *device = argv[1];
    char error_buffer[PCAP_ERRBUF_SIZE];
    signal(SIGINT, handle_sigint);

    handle = pcap_open_live(device, 65535, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return EXIT_FAILURE;
    }

    printf("Sniffing on device: %s\n", device);
    start_time = time(NULL);
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    return EXIT_SUCCESS;
}
