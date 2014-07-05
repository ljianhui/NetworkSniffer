#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <strings.h>
#include <string.h>
#include "rawsocket.h"

RawSocket::RawSocket():
	_sockfd(-1)
{
	bzero((void*)&_addr, sizeof(_addr));
	bzero((void*)&_ifr, sizeof(_ifr));
}

RawSocket::~RawSocket()
{
	close(_sockfd);
}

bool RawSocket::createSocket()
{
	//create the raw socket that catch all network packet
	_sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(_sockfd == -1)
		return false;
	return true;
}

bool RawSocket::bindInterface(const char *interface)
{
	bzero((void*)&_addr, sizeof(_addr));
	bzero((void*)&_ifr, sizeof(_ifr));

	//set the interface name
	strcpy(_ifr.ifr_name, interface);
	
	//get the index of interface
	int ret = ioctl(_sockfd, SIOCGIFINDEX, &_ifr);
	if(ret == -1)
		return false;
	_addr.sll_ifindex = _ifr.ifr_ifindex;
	
	//get the mac addr of interface
	ret = ioctl(_sockfd, SIOCGIFHWADDR, &_ifr);
	if(ret == -1)
		return false;
	memcpy(_addr.sll_addr, _ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	_addr.sll_family = PF_PACKET;//set protocol stack
	_addr.sll_protocol = htons(ETH_P_ALL);//set upper layer protocol
	_addr.sll_hatype = ARPHRD_ETHER;//set arp hardware type
	_addr.sll_pkttype = PACKET_HOST;//set packet type
	_addr.sll_halen = ETH_ALEN;//set mac addr length
	
	//bind the network interface
	ret = bind(_sockfd, (struct sockaddr*)&_addr, sizeof(_addr));
	if(ret == -1)
		return false;
	return true;
}

int RawSocket::recvPacket(unsigned char *buffer, size_t bufsize)
{
	//receive the packet, and write to the buffer
	if(buffer == NULL)
		return -1;
	bzero(buffer, bufsize);
	return recvfrom(_sockfd, buffer, bufsize, 0, NULL, NULL);
}

