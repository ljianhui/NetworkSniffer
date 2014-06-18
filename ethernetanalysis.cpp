#include "ethernetanalysis.h"
#include <stdio.h>
#include <strings.h>

EthernetAnalysis::EthernetAnalysis():
	Analysis("Ethernet", ETHER_CODE),
	_type(0)
{
	bzero(_dst, sizeof(_dst_addr));
	bzero(_src, sizeof(_src_addr));
}

EthernetAnalysis::~EthernetAnalysis()
{
}

const unsigned char* EthernetAnalysis::getDstAddr()const
{
	return _dst_addr;
}

const unsigned char* EthernetAnalysis::getSrcAddr()const
{
	return _src_addr;
}

unsigned short EthernetAnalysis::getType()const
{
	return _type;
}

void EthernetAnalysis::analyzeProtocol(size_t *bytes)
{
	if(bytes != NULL)
		*bytes += 14;

	unsigned char *uchar_ptr = _buffer;
	memcpy(_dst_addr, uchar_ptr, sizeof(_dst_addr));
	uchar_ptr += sizeof(_dst_addr);
	memcpy(_src_addr, uchar_ptr, sizeof(_src_addr));
	uchar_ptr += sizeof(_src_addr);

	unsigned short *ushort_ptr = (unsigned short*)uchar_ptr;
	_type = *ushort_ptr;

	Analysis *child = _getChild(_type);
	if(child != NULL)
	{
		child->setBuffer(_buffer + 14, _bufsize - 14);
		child->analyzeprotocol(bytes);
	}
}
