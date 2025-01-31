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
#include <stddef.h>

// Global variables
static int packet_count = 0;
static int total_bytes = 0;
static int min_packet_size = INT_MAX;
static int max_packet_size = 0;
static int packet_sizes[800000]; // Array to store packet sizes
static int packet_size_count = 0;

pcap_t *handle = NULL; // For access in the signal handler

// Filtering Variables
char *filter_src_ip = NULL;
char *filter_dest_ip = NULL;
int filter_protocol = -1; // -1 means no protocol filter

// Dictionaries for source and destination IP usage
#define MAX_IPS 10000
#define MAX_FLOWS 200000
int flag = 0;
int decode_flag = 0;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int count;
} IPCount;

typedef struct {
    char flow[100];  // To hold source-destination pair (IP:port -> IP:port)
    int bytes;
    int count;
} FlowCount;

struct ether_header {
    u_int8_t ether_dhost[6];
    u_int8_t ether_shost[6];
    u_int16_t ether_type;
};

static IPCount src_ip_counts[MAX_IPS];
static IPCount dest_ip_counts[MAX_IPS];
static int src_ip_count = 0;
static int dest_ip_count = 0;

static FlowCount flow_counts[MAX_FLOWS];
static int flow_count = 0;

// Function prototypes
void add_ip_count(IPCount *ip_counts, int *count, const char *ip);
void print_histogram();
void add_flow_count(const char *src_ip, int src_port, const char *dest_ip, int dest_port, int bytes);
const char *find_most_frequent_ip(IPCount *ip_counts, int count);
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
void display_flow_statistics();
void print_summary();
void write_ip_flow_counts_to_file(); // New function to write IP flow counts

void handle_sigint(int sig) {
    if (handle != NULL) {
        pcap_breakloop(handle);
    }
    printf("\nStopping packet capture...\n");
}

// Helper function to check if a string is a valid IP address
int is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

void add_ip_count(IPCount *ip_counts, int *count, const char *ip) {
    for (int i = 0; i < *count; i++) {
        if (strcmp(ip_counts[i].ip, ip) == 0) {
            ip_counts[i].count++;
            return;
        }
    }
    if (*count < MAX_IPS) {
        strncpy(ip_counts[*count].ip, ip, INET_ADDRSTRLEN);
        ip_counts[*count].count = 1;
        (*count)++;
    }
}

void print_summary() {
    printf("\nTotal Packets: %d\n", packet_count);
    printf("Total Data Transferred: %d bytes\n", total_bytes);
    printf("Minimum Packet Size: %d bytes\n", min_packet_size == INT_MAX ? 0 : min_packet_size);
    printf("Maximum Packet Size: %d bytes\n", max_packet_size);
    printf("Average Packet Size: %.2f bytes\n", packet_count ? (double)total_bytes / packet_count : 0);
    print_histogram();
}

void print_histogram() {
    printf("\nPacket Size Histogram:\n");
    int bins[10] = {0};
    for (int i = 0; i < packet_size_count; i++) {
        int bin = packet_sizes[i] / 100;
        if (bin >= 10) bin = 9;
        bins[bin]++;
    }
    for (int i = 0; i < 10; i++) {
        if (i == 9) {
            printf("  %3d+    bytes: %d\n", i * 100, bins[i]);
        } else {
            printf("  %3d-%3d bytes: %d\n", i * 100, (i + 1) * 100 - 1, bins[i]);
        }
    }
}

void print_full_http_payload(const u_char *payload, int payload_size) {
    if (payload_size <= 0){
        printf("No HTTP payload found\n");
        return;
    } 

    printf("[HTTP PAYLOAD]\n");

    // Loop through the payload and print it as a readable string
    for (int i = 0; i < payload_size; i++) {
        char c = payload[i];

        // Print only printable characters, otherwise use a dot
        if (isprint(c)) {
            printf("%c", c);
        } else {
            printf(".");
        }
    }
    printf("\n");
}

void add_flow_count(const char *src_ip, int src_port, const char *dest_ip, int dest_port, int bytes) {
    char flow_key[100];
    snprintf(flow_key, sizeof(flow_key), "%s:%d -> %s:%d", src_ip, src_port, dest_ip, dest_port);

    for (int i = 0; i < flow_count; i++) {
        if (strcmp(flow_counts[i].flow, flow_key) == 0) {
            flow_counts[i].bytes += bytes;
            flow_counts[i].count++;
            return;
        }
    }

    if (flow_count < MAX_FLOWS) {
        strncpy(flow_counts[flow_count].flow, flow_key, sizeof(flow_counts[flow_count].flow));
        flow_counts[flow_count].bytes = bytes;
        flow_counts[flow_count].count = 1;
        flow_count++;
    }
}

void display_flow_statistics() {
    int most_common_count = 0;
    int most_data_flow = 0;
    char most_common_flow[100];
    char most_data_flow_key[100];

    // Open the file for writing (this will overwrite the file if it already exists)
    FILE *file = fopen("flow_statistics.txt", "w");
    if (file == NULL) {
        fprintf(stderr, "Error opening file for writing.\n");
        return;
    }

    // Print to both console and file
    fprintf(file, "\nUnique Source-Destination Flows:\n");
    printf("\nUnique Source-Destination Flows:\n");
    
    for (int i = 0; i < flow_count; i++) {
        // Print each flow to console and file
        fprintf(file, "  %s -> %d bytes\n", flow_counts[i].flow, flow_counts[i].bytes);
        printf("  %s -> %d bytes\n", flow_counts[i].flow, flow_counts[i].bytes);

        // Track most common flow
        if (flow_counts[i].count > most_common_count) {
            most_common_count = flow_counts[i].count;
            strncpy(most_common_flow, flow_counts[i].flow, sizeof(most_common_flow));
        }

        // Track flow with most data
        if (flow_counts[i].bytes > most_data_flow) {
            most_data_flow = flow_counts[i].bytes;
            strncpy(most_data_flow_key, flow_counts[i].flow, sizeof(most_data_flow_key));
        }
    }


    fprintf(file, "\nMost common flow: %s with %d packets\n", most_common_flow, most_common_count);
    fprintf(file, "Flow with most data transferred: %s with %d bytes\n", most_data_flow_key, most_data_flow);

    printf("\nMost common flow: %s with %d packets\n", most_common_flow, most_common_count);
    printf("Flow with most data transferred: %s with %d bytes\n", most_data_flow_key, most_data_flow);

    fclose(file);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ip *ip_header = (struct ip *)(packet + 14); // IP header is after Ethernet header
    char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip_header->ip_src, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->ip_dst, dest_ip, INET_ADDRSTRLEN);

    // Count flows for source IP
    add_ip_count(src_ip_counts, &src_ip_count, src_ip);

    // Count flows for destination IP
    add_ip_count(dest_ip_counts, &dest_ip_count, dest_ip);

    // Handle TCP/UDP packets as before...
    if ((filter_src_ip == NULL || strcmp(src_ip, filter_src_ip) == 0) &&
        (filter_dest_ip == NULL || strcmp(dest_ip, filter_dest_ip) == 0) &&
        (filter_protocol == -1 || ip_header->ip_p == filter_protocol)) {
        
        // TCP Handling
        if (ip_header->ip_p == IPPROTO_TCP) {
            const struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
            int ip_header_len = ip_header->ip_hl * 4;
            int tcp_header_len = tcp_header->th_off * 4;
            int payload_size = header->caplen - (14 + ip_header_len + tcp_header_len);
            const u_char *payload = packet + 14 + ip_header_len + tcp_header_len;

            if (payload_size >= 0 && decode_flag == 1) {
                printf("Client Source Port: %d\n", ntohs(tcp_header->th_sport));
                printf("Total Payload Length: %d bytes\n", payload_size);
                print_full_http_payload(payload, payload_size);
            }

            add_flow_count(src_ip, ntohs(tcp_header->th_sport), dest_ip, ntohs(tcp_header->th_dport), header->caplen);
        }
        // UDP Handling
        else if (ip_header->ip_p == IPPROTO_UDP) {
            const struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
            add_flow_count(src_ip, ntohs(udp_header->uh_sport), dest_ip, ntohs(udp_header->uh_dport), header->caplen);
            int payload_size = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
            if (payload_size >= 0 && decode_flag == 1) {
                printf("Client Source Port: %d\n", ntohs(udp_header->uh_sport));
                printf("Total Payload Length: %d bytes\n", payload_size);
            }
        }
        printf("Packet no. %d received\n", packet_count + 1);
        printf("Source IP: %s\n", src_ip);
        printf("Destination IP: %s\n", dest_ip);
        printf("Packet Length: %d bytes\n", header->caplen);
        printf("\n");

        packet_count++;
        total_bytes += header->caplen;
        if (header->caplen < min_packet_size) min_packet_size = header->caplen;
        if (header->caplen > max_packet_size) max_packet_size = header->caplen;
        if (packet_size_count < 800000) packet_sizes[packet_size_count++] = header->caplen;
    }
}

// New function to write source and destination IP flow counts to a file
void write_ip_flow_counts_to_file() {
    FILE *file = fopen("ip_flow_counts.txt", "w");
    if (file == NULL) {
        fprintf(stderr, "Error opening file for writing.\n");
        return;
    }

    fprintf(file, "Source IP Flow Counts:\n");
    for (int i = 0; i < src_ip_count; i++) {
        fprintf(file, "  %s: %d flows\n", src_ip_counts[i].ip, src_ip_counts[i].count);
    }

    fprintf(file, "\nDestination IP Flow Counts:\n");
    for (int i = 0; i < dest_ip_count; i++) {
        fprintf(file, "  %s: %d flows\n", dest_ip_counts[i].ip, dest_ip_counts[i].count);
    }

    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <network_interface> [--src-ip <src_ip>] [--dest-ip <dest_ip>] [--protocol <TCP|UDP>]\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *device = argv[1];

    // Parse command-line arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--src-ip") == 0 && i + 1 < argc) {
            filter_src_ip = argv[i + 1];
            if (!is_valid_ip(filter_src_ip)) {
                fprintf(stderr, "Invalid source IP: %s\n", filter_src_ip);
                return EXIT_FAILURE;
            }
            printf("Filtering packets from source IP: %s\n", filter_src_ip);
            i++; // Skip the next argument (the IP)
        } else if (strcmp(argv[i], "--dest-ip") == 0 && i + 1 < argc) {
            filter_dest_ip = argv[i + 1];
            if (!is_valid_ip(filter_dest_ip)) {
                fprintf(stderr, "Invalid destination IP: %s\n", filter_dest_ip);
                return EXIT_FAILURE;
            }
            printf("Filtering packets to destination IP: %s\n", filter_dest_ip);
            i++; // Skip the next argument (the IP)
        } else if (strcmp(argv[i], "--protocol") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "TCP") == 0) {
                filter_protocol = IPPROTO_TCP;
                printf("Filtering packets with TCP protocol\n");
            } else if (strcmp(argv[i + 1], "UDP") == 0) {
                filter_protocol = IPPROTO_UDP;
                printf("Filtering packets with UDP protocol\n");
            } else {
                fprintf(stderr, "Invalid protocol: %s\n", argv[i + 1]);
                return EXIT_FAILURE;
            }
            i++; // Skip the next argument (the protocol)
        } else if (strcmp(argv[i],"--v")==0){
            flag = 1;
        } else if (strcmp(argv[i],"--d")==0){
            decode_flag = 1;
        }
    }

    // Open the network interface for packet capture
    char error_buffer[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(device, 65535, 1, 800, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        return EXIT_FAILURE;
    }
    signal(SIGINT, handle_sigint);

    printf("Sniffing on device: %s\n", device);

    // Start packet capture
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);

    print_summary();
    if (flag==1){
        write_ip_flow_counts_to_file();
        display_flow_statistics();
    }
    

    return EXIT_SUCCESS;
}
