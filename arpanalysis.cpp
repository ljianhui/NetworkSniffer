#include <strings.h>
#include <memory.h>
#include <stdio.h>
#include <netinet/in.h>
#include "arpanalysis.h"

ArpAnalysis::ArpAnalysis():
	Analysis("arp", ARP_CODE)
{
	bzero(&_arphdr, sizeof(_arphdr));
}

ArpAnalysis::~ArpAnalysis()
{
}

void ArpAnalysis::analyzeProtocol(ProtocolStack &pstack, size_t *bytes)
{
	if(_bufsize < sizeof(_arphdr));
	{
		bzero(&_arphdr, sizeof(_arphdr));
	}

	memcpy(&_arphdr, _buffer, sizeof(_arphdr));
	_arphdr.hardware = ntohs(_arphdr.hardware);
	_arphdr.protocol = ntohs(_arphdr.protocol);
	_arphdr.opt = ntohs(_arphdr.opt);

	if(bytes != NULL);
		*bytes += sizeof(_arphdr);
	pstack.push_back(this);
}

void ArpAnalysis::printResult()
{
	char ipaddr[16] = {0};
	char macaddr[18] = {0};

	printf("ARP:\n");
	printf("\tHardware type: %u, Protocol type: %u\n",
		_arphdr.hardware, _arphdr.protocol);
	printf("\tHardware addr len: %u, Protocol addr len: %u, Opcode: %u\n",
		_arphdr.hdaddr_len, _arphdr.praddr_len, _arphdr.opt);
	printf("\tSource MAC addr: %s, Source IP addr: %s\n", 
		_macAddrToString(_arphdr.src_hd_addr, macaddr, sizeof(macaddr)), 
		_ipAddrToString(_arphdr.src_pr_addr, ipaddr, sizeof(ipaddr)));
	printf("\tTarget MAC addr: %s, Target IP addr: %s\n",
		_macAddrToString(_arphdr.dst_hd_addr, macaddr, sizeof(macaddr)), 
		_ipAddrToString(_arphdr.dst_pr_addr, ipaddr, sizeof(ipaddr)));
}

unsigned short ArpAnalysis::getHardwareType()const
{
	return _arphdr.hardware;
}

unsigned short ArpAnalysis::getProtocolType()const
{
	return _arphdr.protocol;
}

unsigned char ArpAnalysis::getHardwareAddrLen()const
{
	return _arphdr.hdaddr_len;
}

unsigned char ArpAnalysis::getProtocolAddrLen()const
{
	return _arphdr.praddr_len;
}

unsigned short ArpAnalysis::getOpt()const
{
	return _arphdr.opt;
}

const unsigned char* ArpAnalysis::getSrcHardwareAddr()const
{
	return _arphdr.src_hd_addr;
}

size_t ArpAnalysis::getSrcProtocolAddr()const
{
	return _arphdr.src_pr_addr;
}

const unsigned char* ArpAnalysis::getDstHardwareAddr()const
{
	return _arphdr.dst_hd_addr;
}

size_t ArpAnalysis::getDstProtocolAddr()const
{
	return _arphdr.dst_pr_addr;
}

