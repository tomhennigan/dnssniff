
#ifndef __DNSSNIFF_H_INCLUDE
#define __DNSSNIFF_H_INCLUDE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <regex.h>
#include <mysql.h>

/* 4 bytes IP address */
typedef struct _ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

// IPv4 Header
typedef struct _ip_header {
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
} ip_header;

// http://www.codeproject.com/KB/IP/dns_query.aspx
typedef struct __dns_header { 
    unsigned short id;       // identification number 
    unsigned char rd :1;     // recursion desired 
    unsigned char tc :1;     // truncated message 
    unsigned char aa :1;     // authoritive answer 
    unsigned char opcode :4; // purpose of message 
    unsigned char qr :1;     // query/response flag 
    unsigned char rcode :4;  // response code 
    unsigned char cd :1;     // checking disabled 
    unsigned char ad :1;     // authenticated data 
    unsigned char z :1;      // its z! reserved 
    unsigned char ra :1;     // recursion available 
    unsigned short q_count;  // number of question entries
    unsigned short ans_count; // number of answer entries 
    unsigned short auth_count; // number of authority entries 
    unsigned short add_count; // number of resource entries
} dns_header;

typedef struct __dns_question {
    unsigned short qtype;
    unsigned short qclass;
} dns_question;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *packet);

char * format_ip_address(ip_address addr);

#endif
