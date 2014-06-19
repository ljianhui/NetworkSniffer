#ifndef RAWSOCKET_H_INCLUDE
#define RAWSOCKET_H_INCLUDE

#include <netinet/in.h>
#include <net/if.h>
#include <netpacket/packet.h>

class RawSocket
{
	public:
		RawSocket();
		~RawSocket();

		bool createSocket();
		bool bindInterface(const char *interface);
		int recvPacket(unsigned char *buffer, size_t bufsize);

	private://function
		RawSocket(const RawSocket &rs){}
		RawSocket& operator=(const RawSocket &rs){return *this;}

	private://data
		int _sockfd;
		struct sockaddr_ll _addr;
		struct ifreq _ifr;
};

#endif
