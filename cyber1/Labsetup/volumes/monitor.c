#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 128

void ping_server(const char *server_ip, const char *output_file) {
    FILE *fp;
    char buffer[BUFFER_SIZE];
    char command[256];
    char *rtt;

    FILE *file = fopen(output_file, "w");  // open file
    if (file == NULL) {
        perror("Error opening output file");
        exit(EXIT_FAILURE);
    }

    while (1) {
        snprintf(command, sizeof(command), "ping -c 1 %s", server_ip); // ping command

        fp = popen(command, "r");
        if (fp == NULL) {   // check if worked
            fprintf(file, "Ping failed!\n");
            fflush(file);
            continue;
        }
        while (fgets(buffer, BUFFER_SIZE, fp) != NULL) {
            if (strstr(buffer, "time=") != NULL) {
                rtt = strstr(buffer, "time=");
                if (rtt != NULL) {
                    fprintf(file, "Ping RTT: %s\n", rtt);  // write to file
                }
                break;
            }
        }
        if (rtt == NULL) {  // check if worked
            fprintf(file, "Ping failed!\n");
            printf("Ping failed!\n");
        }
        fflush(file); // Clean
        pclose(fp);   // Close ping process
        sleep(5);
    }
    fclose(file);
}

int main() {
    const char *server_ip = "10.9.0.4"; 
    const char *output_file = "pings_results_p.txt"; // Output file to store results

    printf("Pinging server %s every 5 seconds...\n", server_ip);
    ping_server(server_ip, output_file);

    return 0;
}
