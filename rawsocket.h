#ifndef RAWSOCKET_H_INCLUDE
#define RAWSOCKET_H_INCLUDE

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if.h>
#include <netpacket/packet.h>

class RawSocket
{
	public:
		RawSocket();
		~RawSocket();

		bool createArpSocket();
		bool createIpSocket();
		bool createTcpSocket();
		bool createUdpSocket();
		bool createIcmpSocket();

		int recvPacket(unsigned char *buffer, size_t bufsize);
		int bind(const char *interface);

	private://function
		RawSocket(const RawSocket &rs){}
		RawSocket& operator=(const RawSocket &rs){return *this}

	private://data
		int sockfd;
		struct sockaddr_ll _addr;
		struct ifreq _ifr;
};

#endif
