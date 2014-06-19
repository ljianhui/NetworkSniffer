#include <stdio.h>
#include <strings.h>
#include <memory.h>
#include "udpanalysis.h"

UdpAnalysis::UdpAnalysis():
	Analysis("udp", UDP_CODE),
	_src_port(0),
	_dst_port(0),
	_udp_len(0),
	_check_sum(0)
{
}

UdpAnalysis::~UdpAnalysis()
{
}

void UdpAnalysis::analyzeProtocol(ProtocolStack &pstack, size_t *bytes)
{
	unsigned short *ushort_ptr = (unsigned short*)_buffer;
	_src_port = *ushort_ptr;
	++ushort_ptr;

	_dst_port = *ushort_ptr;
	++ushort_ptr;

	_udp_len = *ushort_ptr;
	++ushort_ptr;

	_check_sum = *ushort_ptr;
	++ushort_ptr;

	if(bytes != NULL)
		*bytes += _udp_len;
	pstack.push_back(this);

	int port = _src_port < _dst_port ? _src_port:_dst_port;
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
		_src_port, _dst_port);
	printf("\tUdp len: %u, Check sum: %x\n", 
		_udp_len, _check_sum);

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
	return _src_port;
}

unsigned short UdpAnalysis::getDstPort()const
{
	return _dst_port;
}

unsigned short UdpAnalysis::getUdpLen()const
{
	return _udp_len;
}

unsigned short UdpAnalysis::getCheckSum()const
{
	return _check_sum;
}

