/*
Code written by Camron Bartlow
for CS 4133 Data Networks

Acts as a client to receive ICMP packets from a client
*/

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <arpa/inet.h>

int main(int argc, char** argv) {
    int s;
    unsigned short port;
    struct sockaddr_in server;
    char buf[32];

    /* argv[1] is internet address of server argv[2] is port of server.
    * Convert the port from ascii to integer and then from host byte
    * order to network byte order.
    */
    if(argc != 3) {
        printf("Usage: %s <host address> <port> \n",argv[0]);
        exit(1);
    }
    port = htons(atoi(argv[2]));

    /* Create a datagram socket in the internet domain and use the
    * default protocol (UDP).
    */
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("socket()");
        exit(1);
    }

    /* Set up the server name */
    server.sin_family      = AF_INET;            /* Internet Domain    */
    server.sin_port        = port;               /* Server Port        */
    server.sin_addr.s_addr = inet_addr(argv[1]); /* Server's Address   */

    printf ("Enter a file to be sent: ");
    fgets(buf, sizeof(buf), stdin);
    buf[strlen(buf)-1] = '\0';

    /* Check if file can be opened */
    FILE* f;
    f = fopen(buf, "r");
    if (f == NULL) {
        printf("Unable to open file %s for reading", buf);
        exit(2);
    }
    fclose(f);

    // PCAP Error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    int returnval;
    // Open file and parse as PCAP
    pcap_t * pcap_ds = pcap_open_offline(buf, errbuf);
    // PCAP header
    struct pcap_pkthdr *header;
    // Data in PCAP frame
    const u_int8_t *data;


    while ((returnval = pcap_next_ex(pcap_ds, &header, &data)) >= 0) {
        /* Send the message in buf to the server */
        if (sendto(s, data, (header->len), 0,
                        (struct sockaddr *)&server, sizeof(server)) < 0)
        {
            printf("sendto()");
            exit(3);
        }
    
    }
    if (returnval == 0) {
        printf("%s", errbuf);
    }

    /* Deallocate the socket */
    close(s);
    return 0;
}
