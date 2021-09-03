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

struct ip_header {
    #if BYTE_ORDER == LITTLE_ENDIAN
	u_int8_t	ip_hl:4,		    /* header length */
		        ip_v:4;			    /* version */
    #endif
    #if BYTE_ORDER == BIG_ENDIAN
	u_int8_t    ip_v:4,			    /* version */
		        ip_hl:4;		    /* header length */
    #endif
    u_int8_t    tos;
    u_int16_t   data_len;
    u_int16_t   id;

    #if BYTE_ORDER == LITTLE_ENDIAN
    u_int16_t   flags:3,            /* first 3 bits */
                fragment_offset:13; /* last 13 bits */
    #endif
    #if BYTE_ORDER == BIG_ENDIAN
    u_int16_t   fragment_offset:13, /* first 13 bits */
                flags:3;            /* last 3 bits */
    #endif
    u_int8_t    time_to_live;
    u_int8_t    protocol;
    u_int16_t   checksum;
    u_int8_t    source_addr[4];
    u_int8_t    dest_addr[4];
};

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
    printf("\tIP: Header length = %d bytes\n", header->ihl);
    printf("\tIP: Total length = %hu\n", ntohs(header->tot_len));
    printf("\tIP: Flags = %#x\n", ntohs(header->frag_off));
    printf("\tIP: \n");
    printf("\tIP: \n");
    printf("\tIP: \n");
    printf("\tIP: Fragment offset = %d bytes\n", ntohs(header->frag_off) & 0x1FFF);
    printf("\tIP: Time to live = %d seconds/hop\n", header->ttl);
    printf("\tIP: Protocol = %d (ICMP)\n", header->protocol);
    printf("\tIP: Header checksum = %x\n", header->check);
    printf("\tIP: Source address = %s\n", 
        inet_ntoa(*(struct in_addr*)&header->saddr));
    printf("\tIP: Destination address = %s\n",
        inet_ntoa(*(struct in_addr*)&header->daddr));

    /*for (int i = 0;;i++) {
        printf("%04d ", 10*i);
        for (int j = 0; j < 16; j++) {
            printf(" %02x", data[i*j + j]);
        }
    }*/

    free(header);
}

void packetDataInfo(int fp) {

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