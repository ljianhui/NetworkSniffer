#include <stdio.h>
#include <strings.h>
#include <memory.h>
#include "ipanalysis.h"

IpAnalysis::IpAnalysis():
	Analysis("ip", IP_CODE),
	_version(4),
	_header_len(0),
	_ip_package_len(0),
	_ttl(0),
	_protocol(0),
	_check_sum(0)
{
	bzero(_dst_addr, sizeof(_dst_addr));
	bzero(_src_addr, sizeof(_src_addr));
}

IpAnalysis::~IpAnalysis()
{
}

unsigned char IpAnalysis::getVersion()const
{
	return _version;
}

unsigned char IpAnalysis::getHeaderLen()const
{
	return _header_len;
}

const unsigned char* IpAnalysis::getDstIp()const
{
	return _dst_addr;
}

const unsigned char* IpAnalysis::getSrcIp()const
{
	return _src_addr;
}

unsigned short IpAnalysis::getIpPackageLen()const
{
	return _ip_package_len;
}

unsigned char IpAnalysis::getTTL()const
{
	return _ttl;
}

unsigned char IpAnalysis::getProtocol()const
{
	return _protocol;
}

unsigned short IpAnalysis::getCheckSum()const
{
	return _check_sum;
}

void IpAnalysis::analyzeProtocol(ProtocolStack &pstack, size_t *bytes)
{
	unsigned char *uchar_ptr = _buffer;
	_version = *uchar_ptr;
	_version = _version >> 4;
	
	_header_len = *uchar_ptr;
	_header_len &= 0x0f;
	++uchar_ptr;
	++uchar_ptr;

	unsigned short *ushort_ptr = (unsigned short*)uchar_ptr;
	_ip_package_len = *ushort_ptr;
	++ushort_ptr;
	
	uchar_ptr = (unsigned char*)ushort_ptr;
	_ttl = *uchar_ptr;
	++uchar_ptr;

	_protocol = *uchar_ptr;
	++uchar_ptr;

	ushort_ptr = (unsigned short*)uchar_ptr;
	_check_sum = *ushort_ptr;
	++ushort_ptr;

	uchar_ptr = (unsigned char*)ushort_ptr;
	memcpy(_src_addr, uchar_ptr, sizeof(_src_addr));
	uchar_ptr += sizeof(_src_addr);

	memcpy(_dst_addr, uchar_ptr, sizeof(_dst_addr));
	uchar_ptr += sizeof(_dst_addr);

	if(bytes != NULL)
		*bytes += _ip_package_len;
	pstack.push_back(this);

	Analysis *child = _getChild(_protocol);
	if(child != NULL)
	{
		child->setBuffer(_buffer + _header_len, 
				_bufsize - _header_len);
		child->analyzeProtocol(pstack, NULL);
	}

}

void IpAnalysis::printResult()
{
	printf("IP:\n");
	printf("\tVersion: %u, Header len: %u, Total len: %u\n",
		_version, _header_len, _ip_package_len);
	printf("\tTTL: %u, Protocol: %u, Check sum: %x",
		_ttl, _protocol, _check_sum);
	printf("\tSoruce IP addr: %s, Destination IP addr: %s\n",
		_ipAddrToString(_src_addr), _ipAddrToString(_dst_addr));

	/*
	Analysis *child = _getChild(_protocol)
	if(child != NULL)
	{
		child->printResult();
	}
	*/
}

