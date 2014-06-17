#ifndef TYPEDEF_H_INCLUDE
#define TYPEDEF_H_INCLUDE

#define IP_CODE 0x0800
#define ARP_CODE 0x0806
#define ICMP_CODE 0x01
#define TCP_CODE 0x06
#define UDP_CODE 0x11

#define IP_LEN 4
#define MAC_LEN 6

enum AnalysisRoot
{
	ENTER = 0,
	ARP = 1,
	IP = 2,
	ICMP = 3,
	TCP = 4,
	UDP = 5
};

#endif

