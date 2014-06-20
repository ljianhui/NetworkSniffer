#include <stdio.h>
#include <strings.h>
#include <memory.h>
#include <netinet/in.h>
#include "ipanalysis.h"

IpAnalysis::IpAnalysis():
	Analysis("ip", 0x0800)
{
	bzero(&_iphdr, sizeof(_iphdr));
}

IpAnalysis::~IpAnalysis()
{
}

void IpAnalysis::analyzeProtocol(ProtocolStack &pstack, size_t *bytes)
{
	if(_bufsize < sizeof(_iphdr))
	{
		bzero(&_iphdr, sizeof(_iphdr));
		return;
	}

	memcpy(&_iphdr, _buffer, sizeof(_iphdr));

	_iphdr.tot_len = ntohs(_iphdr.tot_len);
	_iphdr.check = ntohs(_iphdr.check);

	if(bytes != NULL)
		*bytes += _iphdr.tot_len;
	pstack.push_back(this);

	Analysis *child = _getChild(_iphdr.protocol);
	if(child != NULL)
	{
		child->setBuffer(_buffer + getHeaderLen(), 
				_bufsize - getHeaderLen());
		child->analyzeProtocol(pstack, NULL);
	}

}

void IpAnalysis::printResult()
{
	printf("IP:\n");
	printf("\tVersion: %u, Header len: %u, Total len: %u\n",
		_iphdr.version, _iphdr.ihl*4, _iphdr.tot_len);
	printf("\tTTL: %u, Protocol: %u, Check sum: 0x%x\n",
		_iphdr.ttl, _iphdr.protocol, _iphdr.check);

	char ipsrc[16] = {0};
	char ipdst[16] = {0};
	printf("\tSoruce IP addr: %s, Destination IP addr: %s\n",
		_ipAddrToString(_iphdr.saddr, ipsrc, sizeof(ipsrc)),
		_ipAddrToString(_iphdr.daddr, ipdst, sizeof(ipdst)));

	/*
	Analysis *child = _getChild(_protocol)
	if(child != NULL)
	{
		child->printResult();
	}
	*/
}

unsigned char IpAnalysis::getVersion()const
{
	return _iphdr.version;
}

unsigned char IpAnalysis::getHeaderLen()const
{
	return _iphdr.ihl * 4;
}

size_t IpAnalysis::getDstIp()const
{
	return _iphdr.saddr;
}

size_t IpAnalysis::getSrcIp()const
{
	return _iphdr.daddr;
}

unsigned short IpAnalysis::getIpPackageLen()const
{
	return _iphdr.tot_len;
}

unsigned char IpAnalysis::getTTL()const
{
	return _iphdr.ttl;
}

unsigned char IpAnalysis::getProtocol()const
{
	return _iphdr.protocol;
}

unsigned short IpAnalysis::getCheckSum()const
{
	return _iphdr.check;
}

