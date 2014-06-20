#include <stdio.h>
#include <strings.h>
#include <memory.h>
#include <netinet/in.h>
#include "udpanalysis.h"

UdpAnalysis::UdpAnalysis():
	Analysis("udp", UDP_CODE)
{
	bzero(&_udphdr, sizeof(_udphdr));
}

UdpAnalysis::~UdpAnalysis()
{
}

void UdpAnalysis::analyzeProtocol(ProtocolStack &pstack, size_t *bytes)
{
	if(_bufsize < sizeof(_udphdr))
	{
		bzero(&_udphdr, sizeof(_udphdr));
		return;
	}
	
	memcpy(&_udphdr, _buffer, sizeof(_udphdr));
	_udphdr.source = ntohs(_udphdr.source);
	_udphdr.dest = ntohs(_udphdr.dest);
	_udphdr.len = ntohs(_udphdr.len);
	_udphdr.check = ntohs(_udphdr.check);

	if(bytes != NULL)
		*bytes += _udphdr.len;
	pstack.push_back(this);

	int port = _udphdr.source < _udphdr.dest ? _udphdr.source:_udphdr.dest;
	Analysis *child = _getChild(port);
	if(child != NULL)
	{
		child->setBuffer(_buffer + 8, _bufsize - 8);
		child->analyzeProtocol(pstack, NULL);
	}
}

void UdpAnalysis::printResult()
{
	printf("UDP:\n");
	printf("\tSource port: %u, Destination port: %u\n",
		_udphdr.source, _udphdr.dest);
	printf("\tUdp len: %u, Check sum: 0x%x\n", 
		_udphdr.len, _udphdr.check);

	/*
	unsigned short port = _src_port < _dst_port ? _src_port:_dst_port;
	Analysis *child = _getChild(port);
	if(child != NULL)
	{
		child->printResult();
	}
	*/
}

unsigned short UdpAnalysis::getSrcPort()const
{
	return _udphdr.source;
}

unsigned short UdpAnalysis::getDstPort()const
{
	return _udphdr.dest;
}

unsigned short UdpAnalysis::getUdpLen()const
{
	return _udphdr.len;
}

unsigned short UdpAnalysis::getCheckSum()const
{
	return _udphdr.check;
}

