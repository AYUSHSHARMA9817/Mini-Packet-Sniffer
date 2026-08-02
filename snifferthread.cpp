#include "snifferthread.h"
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
#include <poll.h>
#include <linux/if_packet.h>

Packet Packets[1000];
int Packet_count = 0;

SnifferThread::SnifferThread(QObject *parent) : QThread(parent), m_running(false) {}

SnifferThread::~SnifferThread() {
    stop();
    wait();
}

QStringList SnifferThread::getAvailableInterfaces() {
    QStringList interfaces;
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return interfaces;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name != NULL && !interfaces.contains(ifa->ifa_name)) {
            interfaces.append(ifa->ifa_name);
        }
    }
    freeifaddrs(ifaddr);
    return interfaces;
}

void SnifferThread::setInterface(const QString& iface) {
    m_interface = iface;
}

void SnifferThread::stop() {
    m_running = false;
}

void SnifferThread::run() {
    m_running = true;
    Packet_count = 0; // Reset on start

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(fd < 0){
        emit errorOccurred("Socket Error: Are you running as root/sudo?");
        return;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, m_interface.toStdString().c_str(), IFNAMSIZ - 1);

    if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0){
        emit errorOccurred("Failed to bind to interface.");
        close(fd);
        return;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if(bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0){
        emit errorOccurred("Binding error.");
        close(fd);
        return;
    }

    unsigned char buff[2000];
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;

    while (m_running && Packet_count < 1000) {
        // Wait up to 100ms for data. This allows the loop to check m_running gracefully.
        int ret = poll(&pfd, 1, 100);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            int n = read(fd, buff, sizeof(buff));
            if (n >= (int)sizeof(Eth_Packet)) {
                memset(&Packets[Packet_count], 0, sizeof(Packet));
                Packets[Packet_count].network = NetworkProtocol::NONE;
                Packets[Packet_count].transport = TransportProtocol::NONE;

                parse_eth_frame(buff);

                emit packetCaptured(Packet_count);
                Packet_count++;
            }
        }
    }
    close(fd);
}

void SnifferThread::store_data(unsigned char* buff, uint16_t szip, uint16_t sz, uint16_t total_len) {
    unsigned char *data = (buff + sizeof(Eth_Packet) + szip + sz);
    int payload_len = (int)total_len - szip - sz;
    if(payload_len < 0) payload_len = 0;
    if(payload_len > 1500) payload_len = 1500;
    memcpy(Packets[Packet_count].payload, data, payload_len);
    Packets[Packet_count].payload_len = payload_len;
}

void SnifferThread::parse_tcp(unsigned char* buff, uint16_t szip, uint16_t total_len) {
    TCP_Packet *tcpk = (TCP_Packet *)(buff + sizeof(Eth_Packet) + szip);
    Packets[Packet_count].transport = TransportProtocol::TCP;
    Packets[Packet_count].tcp = *tcpk;
    uint16_t sztcp = ((tcpk->data_offset_reserved >> 4) * 4);
    store_data(buff, szip, sztcp, total_len);
}

void SnifferThread::parse_udp(unsigned char* buff, uint16_t szip, uint16_t total_len) {
    UDP_Packet *udpk = (UDP_Packet *)(buff + sizeof(Eth_Packet) + szip);
    Packets[Packet_count].transport = TransportProtocol::UDP;
    Packets[Packet_count].udp = *udpk;
    store_data(buff, szip, sizeof(UDP_Packet), total_len);
}

void SnifferThread::parse_icmp(unsigned char* buff, uint16_t szip, uint16_t total_len) {
    ICMP_Packet *icmpk = (ICMP_Packet *)(buff + sizeof(Eth_Packet) + szip);
    Packets[Packet_count].transport = TransportProtocol::ICMP;
    Packets[Packet_count].icmp = *icmpk;
    store_data(buff, szip, sizeof(ICMP_Packet), total_len);
}

void SnifferThread::parse_IPv4_head(unsigned char* buff) {
    IPv4_Packet *ipv4k = (IPv4_Packet*)(buff + sizeof(Eth_Packet));
    Packets[Packet_count].network = NetworkProtocol::IPv4;
    Packets[Packet_count].ipv4 = *ipv4k;

    uint16_t sz = (ipv4k->ihl * 4);
    uint16_t total_len = ntohs(ipv4k->total_len);
    switch(ipv4k->protocol){
        case 6:  parse_tcp(buff, sz, total_len); break;
        case 17: parse_udp(buff, sz, total_len); break;
        case 1:  parse_icmp(buff, sz, total_len); break;
    }
}

void SnifferThread::parse_arp_head(unsigned char * buff) {
    ARP_Packet *arpk = (ARP_Packet *)(buff + sizeof(Eth_Packet));
    Packets[Packet_count].network = NetworkProtocol::ARP;
    Packets[Packet_count].arp = *arpk;
}

void SnifferThread::parse_eth_frame(unsigned char* buff) {
    Eth_Packet *eth = (Eth_Packet *)buff;
    Packets[Packet_count].ethernet = *eth;

    uint16_t ether_type = ntohs(eth->ethtype);
    switch(ether_type) {
        case 0x0800: parse_IPv4_head(buff); break;
        case 0x0806: parse_arp_head(buff); break;
        case 0x86DD: Packets[Packet_count].network = NetworkProtocol::IPv6; break;
    }
}