#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
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

#define out_f "out.txt"
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
    u_int16_t fragment;
};

void radioHeader(struct radiotapHeader* header, FILE* fp);
void IEEEHeaderInfo(struct ieee_header* header, FILE* fp);
void IPHeaderInfo(struct iphdr* header, FILE* fp);
void packetDataInfo(u_int8_t* data, int data_len, FILE* fp);

void radioHeader(struct radiotapHeader* header, FILE* fp) {
    fprintf(fp, "Radiotop: -----Radiotop Header-----\n");
    fprintf(fp, "\tRadiotop: \n");
    fprintf(fp, "\tRadiotop: Header revision = %d\n", header->revision);
    fprintf(fp, "\tRadiotop: Header pad = %d\n", header->padding);
    fprintf(fp, "\tRadiotop: Header length = %d\n", header->length);
    fprintf(fp, "\tRadiotop: Present flags word = %x\n", header->present_flags);
    fprintf(fp, "\tRadiotop: Mac Timestamp = %ld\n", header->mac_timestamp);
    fprintf(fp, "\tRadiotop: Flag = %x\n", header->flags);
    fprintf(fp, "\tRadiotop: Data Rate = %0.1f Mb/s\n", (float) header->data_rate * 0.5);
    fprintf(fp, "\tRadiotop: Channel frequency = %d\n", header->channel_freq);
    fprintf(fp, "\tRadiotop: Channel flags = %02x\n", header->channel_flags);

    free(header);
}

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
    fprintf(fp, "\tHeader: Fragment number = %d\n", header->fragment);

    free(header);
}

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

    //int data_len = ntohs(header->tot_len) - header->ihl*4;
    //packetDataInfo(fp, data_len);
    //packetDataInfo(fp, ntohs(header->tot_len) - header->ihl*4);

    free(header);
}

void packetDataInfo(u_int8_t* data, int data_len, FILE* fp) {
    fprintf(fp, "ICMP: ----- Packet Data -----\n");
    for (int i = 0; i < data_len/16; i++) {
        fprintf(fp, "%04d\t", i*10);
        for (int j = 0; j < 16 && i*16 + j != data_len; j++) {
            fprintf(fp, "%02x ", data[i*16 + j]);
        }
        for (int j = 0; j < 16 && i*16 +j != data_len; j++) {
            fprintf(fp, "%c", ((data[i*16 + j] > 0x1f) && (data[i*16 + j] < 0x7f)) ? data[i*16 + j] : '.');
            if ((i*16 + j + 1) % 8 == 0)
                fprintf(fp, " ");
        }
        
        fprintf(fp, "\n");
    }

    free(data);
}

void packetTests(char* fname_r, FILE* fd_w) {
    char* errbuf = calloc(PCAP_ERRBUF_SIZE, 1);
    pcap_t * pcap_ds = pcap_open_offline(fname_r, errbuf);
    struct pcap_pkthdr *header;
    const u_int8_t *data;

    int returnValue;
    while ((returnValue = pcap_next_ex(pcap_ds, &header, &data)) >= 0) {
        //fprintf(fp, "%d\n", returnValue);

        // Print hex data from file         
        /*for (int i = 0; i < header->len; i++) {
            if (i % 16 == 0)
                fprintf(fp, "%04d ", (i/16)*10);

            fprintf(fp, "0x%02x ", data[i]);

            if ((i+1) % 16 == 0 || i == header->len - 1)
                fprintf(fp, "\n");
        }*/

        struct iphdr* ip_h = calloc(IPV4_HEADER_SIZE, 1);
        struct ieee_header* ieee_h = calloc(IEEE_HEADER_SIZE, 1);
        struct radiotapHeader* radiotap_h = calloc(RADIOTAP_HEADER_SIZE, 1);
        memcpy(radiotap_h,
            data,
            RADIOTAP_HEADER_SIZE);
        memcpy(ieee_h,
            data + RADIOTAP_HEADER_SIZE,
            IEEE_HEADER_SIZE);
        memcpy(ip_h,
            data + RADIOTAP_HEADER_SIZE + IEEE_HEADER_SIZE + 8,
            IPV4_HEADER_SIZE);

        u_int8_t* data_msg = calloc(ntohs(ip_h->tot_len) - ip_h->ihl*4, 1);
        //fprintf(fp, "Len: %d\n", ntohs(ip_h->tot_len) - ip_h->ihl*4);
        memcpy(data_msg,
            data + RADIOTAP_HEADER_SIZE + IEEE_HEADER_SIZE + 8 + IPV4_HEADER_SIZE,
            ntohs(ip_h->tot_len) - ip_h->ihl*4);
        int data_len = ntohs(ip_h->tot_len) - ip_h->ihl*4;
        //fprintf(fp, "Data len: %d\n", data_len);

        radioHeader(radiotap_h, fd_w);
        IEEEHeaderInfo(ieee_h, fd_w);
        IPHeaderInfo(ip_h, fd_w);
        packetDataInfo(data_msg, data_len, fd_w);

    }
    //fprintf(fp, "\nReturn %d: %s\n", returnValue, errbuf);
}

int main(int argc, char** argv) {
    FILE* fd_r;
    FILE* fd_w;
    
    if (argc != 3) {
        printf("Usage: %s [input file] [output file]\n", argv[0]);
        return 1;
    }
    else if (argc == 3) {
        if (!(fd_r = fopen(argv[1], "r")) ) {
            printf("Unable to open file %s for reading\n", argv[1]);
            return 2;
        }
        if (!(fd_w = fopen(argv[2], "w")) ) {
            printf("Unable to open file %s for writing\n", argv[2]);
            return 3;
        }
    }

    //open(argv[2], O_CREAT | O_WRONLY | O_TRUNC);

    packetTests(argv[1], fd_w);

    fclose(fd_r);
    fclose(fd_w);

    return 0;
}