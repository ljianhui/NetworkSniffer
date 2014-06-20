#include <stdio.h>
#include <memory.h>
#include <strings.h>
#include <netinet/in.h>
#include "ethernetanalysis.h"

EthernetAnalysis::EthernetAnalysis():
	Analysis("ethernet", ETHER_CODE)
{
	bzero((void*)&_etherhdr, sizeof(_etherhdr));
}

EthernetAnalysis::~EthernetAnalysis()
{
}

void EthernetAnalysis::analyzeProtocol(ProtocolStack &pstack, size_t *bytes)
{
	if(_bufsize < sizeof(_etherhdr))
	{
		bzero(&_etherhdr, sizeof(_etherhdr));
		return;
	}

	memcpy(&_etherhdr, _buffer, sizeof(_etherhdr));
	_etherhdr.ether_type = ntohs(_etherhdr.ether_type);

	pstack.push_back(this);
	if(bytes != NULL)
		*bytes += sizeof(_etherhdr);

	Analysis *child = _getChild(_etherhdr.ether_type);
	if(child != NULL)
	{
		child->setBuffer(_buffer + sizeof(_etherhdr), 
				_bufsize - sizeof(_etherhdr));
		child->analyzeProtocol(pstack, bytes);
	}
}

void EthernetAnalysis::printResult()
{
	char dst_buf[18] = {0};
	char src_buf[18] = {0};
	printf("Ethernet:\n");
	printf("\tDestination MAC: %s\n", 
		_macAddrToString(_etherhdr.ether_dhost, dst_buf, 
				sizeof(dst_buf)));
	printf("\tSource MAC: %s\n", 
		_macAddrToString(_etherhdr.ether_shost, src_buf,
				sizeof(src_buf)));
	printf("\tType: 0x%x\n", _etherhdr.ether_type);
	/*
	Analysis *child = _getChild(_type);
	if(child != NULL)
	{
		child->printResult();
	}
	*/
}

const unsigned char* EthernetAnalysis::getDstAddr()const
{
	return _etherhdr.ether_dhost;
}

const unsigned char* EthernetAnalysis::getSrcAddr()const
{
	return _etherhdr.ether_shost;
}

unsigned short EthernetAnalysis::getType()const
{
	return _etherhdr.ether_type;
}
