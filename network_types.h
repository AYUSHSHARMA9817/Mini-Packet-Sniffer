#ifndef NETWORK_TYPES_H
#define NETWORK_TYPES_H

#include <cstdint>

typedef struct __attribute__((packed)){
    unsigned char dest[6];
    unsigned char src[6];
    uint16_t ethtype;
} Eth_Packet;

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
} IPv4_Packet;

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
} TCP_Packet;

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
} ARP_Packet;

typedef struct __attribute__((packed)){
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t checksum;
} UDP_Packet;

typedef struct __attribute__((packed)){
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
} ICMP_Packet;

enum class NetworkProtocol { NONE, IPv4, ARP, IPv6 };
enum class TransportProtocol { NONE, TCP, UDP, ICMP };

typedef struct {
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
} Packet;

// Global array and counter (same as your original code)
extern Packet Packets[1000];
extern int Packet_count;

#endif // NETWORK_TYPES_H