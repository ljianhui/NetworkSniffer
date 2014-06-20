#ifndef TYPEDEF_H_INCLUDE
#define TYPEDEF_H_INCLUDE

#include <vector>
#include <list>

#define BUF_SIZE 200

struct Buffer
{
	unsigned char buf[BUF_SIZE];
};

#define ETHER_CODE 0x0
#define IP_CODE 0x0800
#define ARP_CODE 0x0806
#define ICMP_CODE 0x01
#define TCP_CODE 0x06
#define UDP_CODE 0x11

#define IP_LEN 4
#define MAC_LEN 6

class Analysis;
typedef std::vector<Analysis*> ProtocolStack;
typedef std::list<Buffer> BufList;
typedef std::list<Buffer>::iterator BufListIt;

#endif

