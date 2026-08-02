#include "network.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <net/if.h>

using namespace std;

typedef struct __attribute__((packed)){
    unsigned char dest[6];
    unsigned char src[6];
    uint16_t ethtype;
}Eth_Packet;

typedef struct __attribute__((packed)){
    uint8_t ihl:4;
    uint8_t version:4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flag_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t hchecksum;
    uint8_t source_add[4];
    uint8_t dest_add[4];
}IPv4_Packet;

typedef struct __attribute__((packed)){
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_number;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t upt;
}TCP_Packet;

typedef struct __attribute__((packed)){
    uint16_t hwtype;
    uint16_t prototype;
    uint8_t hwlen;
    uint8_t protolen;
    uint16_t opr;
    uint8_t senderadd[6];
    uint8_t senderprotoadd[4];
    uint8_t targetadd[6];
    uint8_t targetprotoadd[4];
}ARP_Packet;

typedef struct __attribute__((packed)){
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t checksum;
}UDP_Packet;

typedef struct __attribute__((packed)){
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
}ICMP_Packet;

enum class NetworkProtocol {
    NONE,
    IPv4,
    ARP,
    IPv6
};

enum class TransportProtocol {
    NONE,
    TCP,
    UDP,
    ICMP
};

typedef struct{
    Eth_Packet ethernet;

    NetworkProtocol network = NetworkProtocol::NONE;
    TransportProtocol transport = TransportProtocol::NONE;

    ARP_Packet arp;
    IPv4_Packet ipv4;
    TCP_Packet tcp;
    UDP_Packet udp;
    ICMP_Packet icmp;
    unsigned char payload[1500];
    uint16_t payload_len;
}Packet;

Packet Packets[1000];
int Packet_count = 0;

void store_data(unsigned char* buff, uint16_t szip, uint16_t sz, uint16_t total_len /*, FILE *fp */){
    unsigned char *data = (buff + sizeof(Eth_Packet) + szip + sz);
    int payload_len = (int)total_len - szip - sz;

    // Bounds checking to prevent buffer overflow in Packets[].payload[1500]
    if(payload_len < 0) payload_len = 0;
    if(payload_len > 1500) payload_len = 1500;
    memcpy(Packets[Packet_count].payload, data, payload_len);
    Packets[Packet_count].payload_len = payload_len;
}

void parse_tcp(unsigned char* buff, uint16_t szip, uint16_t total_len /*, FILE *fp */){
    TCP_Packet *tcpk = (TCP_Packet *)(buff + sizeof(Eth_Packet) + szip);
    
    // Set Enum
    Packets[Packet_count].transport = TransportProtocol::TCP;
    Packets[Packet_count].tcp = *tcpk;

    // Extract payload for all TCP Packets (Shifted by 4 to get the actual 4-bit data offset)
    uint16_t sztcp = ((tcpk->data_offset_reserved >> 4) * 4);
    store_data(buff, szip, sztcp, total_len);
}

void parse_udp(unsigned char* buff, uint16_t szip, uint16_t total_len /*, FILE *fp */){
    UDP_Packet *udpk = (UDP_Packet *)(buff + sizeof(Eth_Packet) + szip);
    
    // Set Enum
    Packets[Packet_count].transport = TransportProtocol::UDP;
    Packets[Packet_count].udp = *udpk;
    
    store_data(buff, szip, sizeof(UDP_Packet), total_len);
}

void parse_icmp(unsigned char* buff, uint16_t szip, uint16_t total_len /*, FILE *fp */){
    ICMP_Packet *icmpk = (ICMP_Packet *)(buff + sizeof(Eth_Packet) + szip);
    
    // Set Enum
    Packets[Packet_count].transport = TransportProtocol::ICMP;
    Packets[Packet_count].icmp = *icmpk;
    
    store_data(buff,szip,sizeof(ICMP_Packet),total_len);
}

void parse_IPv4_head(unsigned char* buff /*, FILE *fp */){
    IPv4_Packet *ipv4k = (IPv4_Packet*) (buff + sizeof(Eth_Packet));
    
    // Set Enum
    Packets[Packet_count].network = NetworkProtocol::IPv4;
    Packets[Packet_count].ipv4 = *ipv4k;

    uint16_t sz = (ipv4k->ihl * 4);
    uint16_t total_len = ntohs(ipv4k->total_len);
    switch(ipv4k->protocol){
        case 6:
            parse_tcp(buff, sz, total_len);
            break;
        case 17:
            parse_udp(buff,sz,total_len);
            break;
        case 1:
            parse_icmp(buff,sz,total_len);
            break;
    }
}

void parse_arp_head(unsigned char * buff){
    ARP_Packet *arpk = (ARP_Packet *)(buff + sizeof(Eth_Packet));
    
    // Set Enum
    Packets[Packet_count].network = NetworkProtocol::ARP;
    Packets[Packet_count].arp = *arpk;
}

void parse_eth_frame(unsigned char* buff /*, FILE *fp */){
    Eth_Packet *eth = (Eth_Packet *)buff;
    Packets[Packet_count].ethernet = *eth;

    uint16_t ether_type = ntohs(eth->ethtype);
    switch(ether_type) {
            case 0x0800:
                parse_IPv4_head(buff);
                break;
            case 0x0806:
                parse_arp_head(buff);
                break;
            case 0x86DD:
                Packets[Packet_count].network = NetworkProtocol::IPv6;
                break;
            default:
                break;
    }
}

char *interface_find() {
    static char interfaces[100][IFNAMSIZ];
    int cnt = 0;
    struct ifaddrs *ifaddr, *ifa;

    getifaddrs(&ifaddr);

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL)
            continue;

        bool found = false;
        for(int j = 0; j < cnt; j++)
            if(strcmp(interfaces[j], ifa->ifa_name) == 0)
                found = true;

        if(!found)
            strcpy(interfaces[cnt++], ifa->ifa_name);
    }

    freeifaddrs(ifaddr);

    printf("Choose Interface:\n");
    for(int i = 0; i < cnt; i++)
        printf("%d) %s\n", i + 1, interfaces[i]);

    int ind = 0;
    scanf("%d", &ind);
    if(ind < 1 || ind > cnt){
        printf("Invalid interface\n");
        return NULL;
    }

    return interfaces[ind - 1];
}

void Raw_Packet_data(){
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if(fd < 0){
        perror("socket error");
        return;
    }

    char *interface = interface_find();
    if(interface == NULL){
        close(fd);
        return;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0){
        perror("ioctl");
        close(fd);
        return;
    }
    printf("Created interface: %s\n", ifr.ifr_name);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    int bd = bind(fd, (struct sockaddr*)&sll, sizeof(sll));
    if(bd < 0){
        perror("binding error");
        close(fd);
        return;
    }

    unsigned char buff[2000];

    while(1){
        int n = read(fd, buff, sizeof(buff));
        if(n < (int)sizeof(Eth_Packet)){
            printf("Frame too short\n");
            close(fd);
            return;
        }

        // Zero-out the current Packet struct to ensure clean data
        memset(&Packets[Packet_count],0,sizeof(Packet));
        
        // Re-initialize default enums for C++ correctness since memset clears them to 0 (which luckily corresponds to NONE)
        Packets[Packet_count].network = NetworkProtocol::NONE;
        Packets[Packet_count].transport = TransportProtocol::NONE;

        parse_eth_frame(buff);

        // Increment Packet counter and prevent array overflow
        Packet_count++;
        if(Packet_count >= 1000){
            printf("Captured maximum limit of 1000 Packets. Stopping capture.\n");
            break;
        }
    }
    close(fd);
}

int main(){
    Raw_Packet_data();
    return 0;
}