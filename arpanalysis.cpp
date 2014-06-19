#include "arpanalysis.h"
#include <strings.h>
#include <memory.h>
#include <stdio.h>

ArpAnalysis::ArpAnalysis():
	Analysis("arp", ARP_CODE),
	_hardware(0),
	_protocol(0),
	_hdaddr_len(0),
	_praddr_len(0),
	_opt(0)
{
	bzero(_src_hd_addr, sizeof(_src_hd_addr));
	bzero(_src_pr_addr, sizeof(_src_pr_addr));
	bzero(_dst_hd_addr, sizeof(_dst_hd_addr));
	bzero(_dst_pr_addr, sizeof(_dst_pr_addr));
}

ArpAnalysis::~ArpAnalysis()
{
}

unsigned short ArpAnalysis::getHardwareType()const
{
	return _hardware;
}

unsigned short ArpAnalysis::getProtocolType()const
{
	return _protocol;
}

unsigned char ArpAnalysis::getHardwareAddrLen()const
{
	return _hdaddr_len;
}

unsigned char ArpAnalysis::getProtocolAddrLen()const
{
	return _praddr_len;
}

unsigned short ArpAnalysis::getOpt()const
{
	return _opt;
}

const unsigned char* ArpAnalysis::getSrcHardwareAddr()const
{
	return _src_hd_addr;
}

const unsigned char* ArpAnalysis::getSrcProtocolAddr()const
{
	return _src_pr_addr;
}

const unsigned char* ArpAnalysis::getDstHardwareAddr()const
{
	return _dst_hd_addr;
}

const unsigned char* ArpAnalysis::getDstProtocolAddr()const
{
	return _dst_pr_addr;
}

void ArpAnalysis::analyzeProtocol(ProtocolStack &pstack, size_t *bytes)
{
	unsigned short *ushort_ptr = (unsigned short*)_buffer;
	unsigned char *uchar_ptr = _buffer;

	_hardware = *ushort_ptr;
	++ushort_ptr;

	_protocol = *ushort_ptr;
	++ushort_ptr;
	
	uchar_ptr = (unsigned char*)ushort_ptr;
	_hdaddr_len = *uchar_ptr;
	++uchar_ptr;
	_praddr_len = *uchar_ptr;
	++uchar_ptr;

	ushort_ptr = (unsigned short*)uchar_ptr;
	_opt = *ushort_ptr;
	++ushort_ptr;
	
	uchar_ptr = (unsigned char*)ushort_ptr;
	memcpy(_src_hd_addr, uchar_ptr, sizeof(_src_hd_addr));
	uchar_ptr += sizeof(_src_hd_addr);

	memcpy(_src_pr_addr, uchar_ptr, sizeof(_src_pr_addr));
	uchar_ptr += sizeof(_src_pr_addr);

	memcpy(_dst_hd_addr, uchar_ptr, sizeof(_dst_hd_addr));
	uchar_ptr += sizeof(_dst_hd_addr);

	memcpy(_dst_pr_addr, uchar_ptr, sizeof(_dst_pr_addr));
	uchar_ptr += sizeof(_dst_pr_addr);
	
	if(bytes != NULL);
		*bytes += (uchar_ptr - _buffer);
	pstack.push_back(this);
}

void ArpAnalysis::printResult()
{
	printf("ARP:\n");
	printf("\tHardware type: %u, Protocol type: %u\n",
		_hardware, _protocol);
	printf("\tHardware addr len: %u, Protocol addr len: %u, Opcode: %u",
		_hdaddr_len, _praddr_len, _opt);
	printf("\tSource MAC addr: %s, Source IP addr: %s\n", 
		_macAddrToString(_src_hd_addr), _ipAddrToString(_src_pr_addr));
	printf("\tTarget MAC addr: %s, Target IP addr: %s\n",
		_macAddrToString(_dst_hd_addr), _ipAddrToString(_dst_pr_addr));
}

