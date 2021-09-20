/*
Code written by Camron Bartlow
for CS 4133 Data Networks

Acts as a server to receive ICMP packets from a client
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/ether.h> /* to parse Ethernet headers */
#include <netinet/ip.h> /* to parse IP headers */
#include <netinet/tcp.h> /* to parse TCP headers */

#define BUF_SIZE 256
#define RADIOTAP_HEADER_SIZE 22
#define IEEE_HEADER_SIZE 24
#define IPV4_HEADER_SIZE 20

struct radiotapHeader {
    u_int8_t revision;
    u_int8_t padding;
    u_int16_t length;
    u_int32_t present_flags;
    u_int64_t mac_timestamp;
    u_int8_t flags;
    u_int8_t data_rate;
    u_int16_t channel_freq;
    u_int16_t channel_flags;
};

struct ieee_header {
    u_int16_t ctrl_field;
    u_int16_t duration;
    u_int8_t recv_addr[6];
    u_int8_t trans_addr[6];
    u_int8_t dest_addr[6];
    u_int16_t fragment;
};

/*
* Prints information stored in the Radiotap Header of the received packet
* Prints info to file if specified, otherwise stdout
*/
void radioHeader(struct radiotapHeader* header, FILE* fp = stdout);
/*
* Prints information stored in the 802.11 Data Header of the received packet
* Prints info to file if specified, otherwise stdout
*/
void IEEEHeaderInfo(struct ieee_header* header, FILE* fp = stdout);
/*
* Prints information stored in the IP Header of the received packet
* Prints info to file if specified, otherwise stdout
*/
void IPHeaderInfo(struct iphdr* header, FILE* fp = stdout);
void packetDataInfo(u_int8_t* data, int data_len, FILE* fp = stdout);

/*
* Prints information stored in the Radiotap Header of the received packet
* Prints info to file if specified, otherwise stdout
*/
void radioHeader(struct radiotapHeader* header, FILE* fp) {
    fprintf(fp, "Radiotap: -----Radiotap Header-----\n");
    fprintf(fp, "\tRadiotap: \n");
    fprintf(fp, "\tRadiotap: Header revision = %d\n", header->revision);
    fprintf(fp, "\tRadiotap: Header pad = %d\n", header->padding);
    fprintf(fp, "\tRadiotap: Header length = %d\n", header->length);
    fprintf(fp, "\tRadiotap: Present flags word = %x\n", header->present_flags);
    fprintf(fp, "\tRadiotap: Mac Timestamp = %ld\n", header->mac_timestamp);
    fprintf(fp, "\tRadiotap: Flag = %x\n", header->flags);
    fprintf(fp, "\tRadiotap: Data Rate = %0.1f Mb/s\n", (float) header->data_rate * 0.5);
    fprintf(fp, "\tRadiotap: Channel frequency = %d\n", header->channel_freq);
    fprintf(fp, "\tRadiotap: Channel flags = %02x\n", header->channel_flags);

    // Free the header
    free(header);
}

/*
* Prints information stored in the 802.11 Data Header of the received packet
* Prints info to file if specified, otherwise stdout
*/
void IEEEHeaderInfo(struct ieee_header* header, FILE* fp) {
    fprintf(fp, "Header: ----- 802.11 Header -----\n");
    fprintf(fp, "\tHeader: \n");
    fprintf(fp, "\tHeader: Frame Control Fied = 0x%04x\n", ntohs(header->ctrl_field));
    fprintf(fp, "\tHeader: Duration = %.0f microseconds\n", (float) header->duration);
    fprintf(fp, "\tHeader: Receiver Address = %02x:%02x:%02x:%02x:%02x:%02x\n",
        header->recv_addr[0], header->recv_addr[1], header->recv_addr[2],
        header->recv_addr[3], header->recv_addr[4], header->recv_addr[5]);
    fprintf(fp, "\tHeader: Transmitter Address = %02x:%02x:%02x:%02x:%02x:%02x\n",
        header->trans_addr[0], header->trans_addr[1], header->trans_addr[2],
        header->trans_addr[3], header->trans_addr[4], header->trans_addr[5]);
    fprintf(fp, "\tHeader: Fragment number = %hx\n", header->fragment);

    // Free the header
    free(header);
}

/*
* Prints information stored in the IP Header of the received packet
* Prints info to file if specified, otherwise stdout
*/
void IPHeaderInfo(struct iphdr* header, FILE* fp) {
    fprintf(fp, "IP: ----- IP Header -----\n");
    fprintf(fp, "\tIP: \n");
    fprintf(fp, "\tIP: Version = %d\n", header->version);
    fprintf(fp, "\tIP: Header length = %d bytes\n", header->ihl * 4);
    fprintf(fp, "\tIP: Total length = %hu\n", ntohs(header->tot_len));
    fprintf(fp, "\tIP: Flags = %#x\n", ntohs(header->frag_off) >> 12);
    fprintf(fp, "\tIP: \t%d... .... .... .... = Reserved bit: %s\n",
        ntohs(header->frag_off) >> 15,
        (ntohs(header->frag_off) >> 15) ? "Set" : "Not set");
    fprintf(fp, "\tIP: \t.%d.. .... .... .... = Don't fragment: %s\n",
        (ntohs(header->frag_off) >> 14) & 0x1,
        ((ntohs(header->frag_off) >> 14) & 0x1) ? "Set" : "Not set");
    fprintf(fp, "\tIP: \t..%d. .... .... .... = More fragments: %s\n",
        (ntohs(header->frag_off) >> 13) & 0x1,
        ((ntohs(header->frag_off) >> 13) & 0x1) ? "Set" : "Not set");
    fprintf(fp, "\tIP: Fragment offset = %d bytes\n",
        ntohs(header->frag_off) & 0x1FFF);
    fprintf(fp, "\tIP: Time to live = %d seconds/hop\n", header->ttl);
    fprintf(fp, "\tIP: Protocol = %d (ICMP)\n", header->protocol);
    fprintf(fp, "\tIP: Header checksum = %x\n", ntohs(header->check));
    fprintf(fp, "\tIP: Source address = %s\n", 
        inet_ntoa(*(struct in_addr*)&header->saddr));
    fprintf(fp, "\tIP: Destination address = %s\n",
        inet_ntoa(*(struct in_addr*)&header->daddr));

    // Free the header
    free(header);
}

/*
* Prints data information stored in the sent packet
* Will first print the bytes and their corresponding
* ASCII representation if they have an alphanumeric
* representation
* 
* Prints info to file if specified, otherwise stdout
*/
void packetDataInfo(u_int8_t* data, int data_len, FILE* fp) {
    fprintf(fp, "ICMP: ----- Packet Data -----\n");
    for (int i = 0; i < data_len/16; i++) {
        // Print hex line
        fprintf(fp, "%04d\t", i*10);

        // Print byte value
        for (int j = 0; j < 16 && i*16 + j != data_len; j++) {
            fprintf(fp, "%02x ", data[i*16 + j]);
        }

        // Print ASCII representation
        for (int j = 0; j < 16 && i*16 +j != data_len; j++) {
            fprintf(fp, "%c", ((data[i*16 + j] > 0x1f) && (data[i*16 + j] < 0x7f)) ? data[i*16 + j] : '.');
            if ((i*16 + j + 1) % 8 == 0)
                fprintf(fp, " ");
        }
        
        fprintf(fp, "\n");
    }

    // Free data stored
    free(data);
}

int main() {
    int s, namelen, client_address_size;
    struct sockaddr_in client, server;

    /* Buffer used to store packets */
    unsigned char buf[BUF_SIZE] = {0};

    /*
    * Create a datagram socket in the internet domain and use the
    * default protocol (UDP).
    */
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("socket()");
        exit(1);
    }

    /*
    * Bind my name to this socket so that clients on the network can
    * send me messages. (This allows the operating system to demultiplex
    * messages and get them to the correct server)
    *
    * Set up the server name. The internet address is specified as the
    * wildcard INADDR_ANY so that the server can get messages from any
    * of the physical internet connections on this host. (Otherwise we
    * would limit the server to messages from only one network
    * interface.)
    */
    server.sin_family      = AF_INET;  /* Server is in Internet Domain */
    server.sin_port        = 0;         /* Use any available port      */
    server.sin_addr.s_addr = INADDR_ANY;/* Server's Internet Address   */

    if (bind(s, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("bind()");
        exit(2);
    }

    /* Find out what port was really assigned and print it */
    namelen = sizeof(server);
    if (getsockname(s, (struct sockaddr *) &server, (socklen_t *) &namelen) < 0) {
        printf("getsockname()");
        exit(3);
    }

    printf ("Server is running at this IP address %s\n and on port %d\n", 
            inet_ntoa(server.sin_addr), ntohs(server.sin_port));

    /*
    * Receive a message on socket s in buf  of maximum size 255
    * from a client. 
    */
    client_address_size = sizeof(client);

    while (true) {
        /* Zero out buffer before next use */
        for (int i = 0; i < BUF_SIZE; i++) {
            buf[i] = 0;
        }

        if(recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *) &client,
                (socklen_t *) &client_address_size) <0)
        {
            printf("recvfrom()");
            exit(4);
        }

        // Prints Received message bytes from client 
        /*printf("\nReceived message:\n");
        for (int i = 0; i < sizeof(buf); i++) {
            printf("0x%02x ", buf[i]);
            if ((i+1) % 16 == 0)
                printf("\n");
        }*/

        // Create memory space for headers
        struct iphdr* ip_h = new iphdr();
        struct ieee_header* ieee_h = new ieee_header();
        struct radiotapHeader* radiotap_h = new radiotapHeader();

        // Copy header information into header variables
        // The location to start copying bytes from is
        // determined by header sizes
        memcpy(radiotap_h,
            buf,
            RADIOTAP_HEADER_SIZE);
        memcpy(ieee_h,
            buf + RADIOTAP_HEADER_SIZE,
            IEEE_HEADER_SIZE);
        memcpy(ip_h,
            buf + RADIOTAP_HEADER_SIZE + IEEE_HEADER_SIZE + 8,
            IPV4_HEADER_SIZE);

        // Find length of data message from ip header
        int data_len = ntohs(ip_h->tot_len) - ip_h->ihl*4;

        // Create memory space for the length of the data message
        u_int8_t* data_msg = (u_int8_t*) calloc(data_len, 1);

        // Copy data message from buffer into data message variable
        // Length of the message is found in the ip header
        memcpy(data_msg,
            buf + RADIOTAP_HEADER_SIZE + IEEE_HEADER_SIZE + 8 + IPV4_HEADER_SIZE,
            data_len);

        // Print header information for each type and data info
        radioHeader(radiotap_h);
        IEEEHeaderInfo(ieee_h);
        IPHeaderInfo(ip_h);
        packetDataInfo(data_msg, data_len);

        // Says where the packet is sent from
        printf("from domain %s port %d internet address %s\n\n",
            (client.sin_family == AF_INET?"AF_INET":"UNKNOWN"),
            ntohs(client.sin_port),
            inet_ntoa(client.sin_addr));
    }

    // Free the buffer used to store each frame
    free(buf);

    /*
    * Deallocate the socket.
    */

    close(s);

    return 0;
}