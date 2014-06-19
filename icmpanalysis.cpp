#include <stdio.h>
#include <netinet/in.h>
#include "icmpanalysis.h"

IcmpAnalysis::IcmpAnalysis():
	Analysis("icmp", ICMP_CODE),
	_type(0),
	_code(0),
	_check_sum(0)
{
}

IcmpAnalysis::~IcmpAnalysis()
{
}

void IcmpAnalysis::analyzeProtocol(ProtocolStack &pstack, size_t *bytes)
{
	unsigned char *uchar_ptr = _buffer;
	_type = *uchar_ptr;
	++uchar_ptr;

	_code = *uchar_ptr;
	++uchar_ptr;

	unsigned short *ushort_ptr = (unsigned short*)uchar_ptr;
	_check_sum = ntohs(*ushort_ptr);
	++ushort_ptr;

	if(bytes != NULL)
		*bytes += 4;
	pstack.push_back(this);
}

void IcmpAnalysis::printResult()
{
	printf("ICMP:\n");
	printf("\tType: %u, Code: %u, Check sum: 0x%x\n",
		_type, _code, _check_sum);
}

unsigned char IcmpAnalysis::getType()const
{
	return _type;
}

unsigned char IcmpAnalysis::getCode()const
{
	return _code;
}

unsigned short IcmpAnalysis::getCheckSum()const
{
	return _check_sum;
}

