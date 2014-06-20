#include <stdio.h>
#include <memory.h>
#include <netinet/in.h>
#include "icmpanalysis.h"

IcmpAnalysis::IcmpAnalysis():
	Analysis("icmp", ICMP_CODE)
{
}

IcmpAnalysis::~IcmpAnalysis()
{
}

void IcmpAnalysis::analyzeProtocol(ProtocolStack &pstack, size_t *bytes)
{
	if(_bufsize < sizeof(_icmphdr))
	{
		bzero(&_icmphdr, sizeof(_icmphdr));
		return;
	}

	memcpy(&_icmphdr, _buffer, sizeof(_icmphdr));

	_icmphdr.checksum = ntohs(_icmphdr.checksum);

	if(bytes != NULL)
		*bytes += 4;
	pstack.push_back(this);
}

void IcmpAnalysis::printResult()
{
	printf("ICMP:\n");
	printf("\tType: %u, Code: %u, Check sum: 0x%x\n",
		_icmphdr.type, _icmphdr.code, _icmphdr.checksum);
}

unsigned char IcmpAnalysis::getType()const
{
	return _icmphdr.type;
}

unsigned char IcmpAnalysis::getCode()const
{
	return _icmphdr.code;
}

unsigned short IcmpAnalysis::getCheckSum()const
{
	return _icmphdr.checksum;
}

