#include <pcap.h>    // Provides the pcap functions and data structures for packet capture
#include <stdio.h>    // Standard I/O library for printing and error handling
#include <stdlib.h>    // Standard library for general purpose functions (exit, etc.)
#include <string.h>    // String handling fns
#include <signal.h>    // For handling signals (e.g., SIGINT)
#include <arpa/inet.h>    // Provides definitions for internet operations (e.g., htons, inet_ntoa)
#include <ctype.h>    // Character type fns (e.g., isprint)
#include <netinet/ip.h>    // Structures for IPv4 headers
#include <netinet/tcp.h>    // Structures for TCP headers
#include <netinet/udp.h>    // Structures for UDP headers
#include <limits.h>    // Limits for integral types
#include <unistd.h>    // UNIX standard fn defns
#include <time.h>    // For time-related fns

// Global counters to track number of packets and total bytes captured
static int packet_count = 0;
static int total_bytes = 0;

// To measure the capture duration, store the start time
static time_t start_time;

// Global pcap handle
pcap_t *handle = NULL;

// Signal handler for CTRL+C (SIGINT): This function breaks out of the pcap_loop() cleanly, prints capture statistics, and then exits the program.
void handle_sigint(int sig) {
    if (handle != NULL) {
        pcap_breakloop(handle);
    }
    printf("\nStopping packet capture...\n");
    printf("Total Packets Received: %d\n", packet_count);
    printf("Total Data Transferred: %d bytes\n", total_bytes);

    // Compute the duration of the capture
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

/**
 * Callback function invoked by pcap for every captured packet.
 @param user    User-defined data (unused here).
 @param header  Packet header containing length and timestamp.
 @param packet  Actual packet data.
 */
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    packet_count++;
    total_bytes += header->caplen;    // Add the size of the current packet to the total byte count
    printf("Packet %d received, Size: %d bytes\n", packet_count, header->caplen);
}

int main(int argc, char *argv[]) {
    // Check for correct usage; at least one argument (the interface) is required
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <network_interface>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *device = argv[1];
    char error_buffer[PCAP_ERRBUF_SIZE];
    signal(SIGINT, handle_sigint);

    /**
     pcap_open_live():
     - device: the network interface
     - 65535: snapshot length (max number of bytes to capture per packet)
     - 1: promiscuous mode (1 = on)
     - 1000: read timeout in milliseconds
     - error_buffer: buffer to store error messages
     */
    handle = pcap_open_live(device, 65535, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return EXIT_FAILURE;
    }

    printf("Sniffing on device: %s\n", device);
    start_time = time(NULL);

    /**
     pcap_loop():
     - handle: the pcap handle
     - -1: capture indefinitely until an error occurs or pcap_breakloop is called
     - packet_handler: callback function to handle each captured packet
     - NULL: no user-defined data passed to the callback
     */
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    return EXIT_SUCCESS;
}
