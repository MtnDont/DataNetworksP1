#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h> /* to parse Ethernet headers */
#include <netinet/ip.h> /* to parse IP headers */
#include <netinet/tcp.h> /* to parse TCP headers */

#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h> 

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
    u_int16_t fragment;
};

void radioHeader(int fp);
void IEEEHeaderInfo(int fp);
void IPHeaderInfo(int fp);
void packetDataInfo(int fp, int data_len);

void radioHeader(int fp) {
    struct radiotapHeader* header = calloc(22, 1);
    //unsigned char* buf = calloc(22, 1);
    lseek(fp, 40, SEEK_SET);
    read(fp, header, 22);
    /*for (int i = 0; i < 22; i++) {
        printf("0x%02x ", (unsigned int) buf[i]);
        if ((i+1) % 10 == 0)
            printf("\n");
    }*/
    printf("Radiotop: -----Radiotop Header-----\n");
    printf("\tRadiotop: \n");
    printf("\tRadiotop: Header revision = %d\n", header->revision);
    printf("\tRadiotop: Header pad = %d\n", header->padding);
    printf("\tRadiotop: Header length = %d\n", header->length);
    printf("\tRadiotop: Present flags word = %x\n", header->present_flags);
    printf("\tRadiotop: Mac Timestamp = %ld\n", header->mac_timestamp);
    printf("\tRadiotop: Flag = %x\n", header->flags);
    printf("\tRadiotop: Data Rate = %0.1f Mb/s\n", (float) header->data_rate * 0.5);
    printf("\tRadiotop: Channel frequency = %d\n", header->channel_freq);
    printf("\tRadiotop: Channel flags = %02x\n", header->channel_flags);

    free(header);
}

void IEEEHeaderInfo(int fp) {
    struct ieee_header* header = calloc(24, 1);
    lseek(fp, 62, SEEK_SET);
    read(fp, header, 24);

    printf("Header: ----- 802.11 Header -----\n");
    printf("\tHeader: \n");
    printf("\tHeader: Frame Control Fied = 0x%04x\n", ntohs(header->ctrl_field));
    printf("\tHeader: Duration = %.0f microseconds\n", (float) header->duration);
    printf("\tHeader: Receiver Address = %02x:%02x:%02x:%02x:%02x:%02x\n",
        header->recv_addr[0], header->recv_addr[1], header->recv_addr[2],
        header->recv_addr[3], header->recv_addr[4], header->recv_addr[5]);
    printf("\tHeader: Transmitter Address = %02x:%02x:%02x:%02x:%02x:%02x\n",
        header->trans_addr[0], header->trans_addr[1], header->trans_addr[2],
        header->trans_addr[3], header->trans_addr[4], header->trans_addr[5]);
    printf("\tHeader: Fragment number = %d\n", header->fragment);

    free(header);
}

void IPHeaderInfo(int fp) {
    struct iphdr* header = calloc(20, 1);
    lseek(fp, 94, SEEK_SET);
    read(fp, header, 20);

    //char** data = calloc(ntohs(header->tot_len), 1);
    //read(fp, data, ntohs(header->tot_len));

    printf("IP: ----- IP Header -----\n");
    printf("\tIP: \n");
    printf("\tIP: Version = %d\n", header->version);
    printf("\tIP: Header length = %d bytes\n", header->ihl * 4);
    printf("\tIP: Total length = %hu\n", ntohs(header->tot_len));
    printf("\tIP: Flags = %#x\n", ntohs(header->frag_off) >> 12);
    printf("\tIP: \t%d... .... .... .... = Reserved bit: %s\n",
        ntohs(header->frag_off) >> 15,
        (ntohs(header->frag_off) >> 15) ? "Set" : "Not set");
    printf("\tIP: \t.%d.. .... .... .... = Don't fragment: %s\n",
        (ntohs(header->frag_off) >> 14) & 0x1,
        ((ntohs(header->frag_off) >> 14) & 0x1) ? "Set" : "Not set");
    printf("\tIP: \t..%d. .... .... .... = More fragments: %s\n",
        (ntohs(header->frag_off) >> 13) & 0x1,
        ((ntohs(header->frag_off) >> 13) & 0x1) ? "Set" : "Not set");
    printf("\tIP: Fragment offset = %d bytes\n",
        ntohs(header->frag_off) & 0x1FFF);
    printf("\tIP: Time to live = %d seconds/hop\n", header->ttl);
    printf("\tIP: Protocol = %d (ICMP)\n", header->protocol);
    printf("\tIP: Header checksum = %x\n", ntohs(header->check));
    printf("\tIP: Source address = %s\n", 
        inet_ntoa(*(struct in_addr*)&header->saddr));
    printf("\tIP: Destination address = %s\n",
        inet_ntoa(*(struct in_addr*)&header->daddr));

    int data_len = ntohs(header->tot_len) - header->ihl*4;
    packetDataInfo(fp, data_len);

    free(header);
}

void packetDataInfo(int fp, int data_len) {
    unsigned char* data = calloc(data_len, 1);
    read(fp, data, data_len);

    printf("ICMP: ----- Packet Data -----\n");
    for (int i = 0; i < data_len/16; i++) {
        printf("%04d\t", i*10);
        for (int j = 0; j < 16 && i*16 + j != data_len; j++) {
            printf("%02x ", data[i*16 + j]);
        }
        for (int j = 0; j < 16 && i*16 +j != data_len; j++) {
            printf("%c", ((data[i*16 + j] > 0x1f) && (data[i*16 + j] < 0x7f)) ? data[i*16 + j] : '.');
            if ((i*16 + j + 1) % 8 == 0)
                printf(" ");
        }

        
        printf("\n");
    }

    free(data);
}

int main(int argc, char** argv) {
    int fp;
    
    if (argc != 2) {
        printf("Usage: %s [filename]\n", argv[0]);
        return 1;
    }
    else if (argc == 2 && !(fp = open(argv[1], 0)) ) {
        printf("Unable to open file %s for reading\n", argv[1]);
        return 2;
    }

    radioHeader(fp);
    IEEEHeaderInfo(fp);
    IPHeaderInfo(fp);

    close(fp);

    return 0;
}