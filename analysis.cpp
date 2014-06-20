#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "analysis.h"

Analysis::Analysis(const std::string &pname, int pcode):
	_buffer(NULL),
	_bufsize(0),
	_protocol_name(pname),
	_pcode(pcode)
{
}

Analysis::~Analysis()
{
}

void Analysis::addChild(Analysis *child)
{
	_childern.push_back(child);
}

void Analysis::setBuffer(const unsigned char *buffer, size_t bufsize)
{
	_buffer = buffer;
	_bufsize = bufsize;
}

std::string Analysis::getProtocolName()const
{
	return _protocol_name;
}

unsigned short Analysis::getPCode()const
{
	return _pcode;
}

Analysis* Analysis::_getChild(int code)
{
	std::list<Analysis*>::iterator it = _childern.begin();
	for(; it != _childern.end(); ++it)
	{
		if((*it)->_pcode == code)
			return *it;
	}
	return NULL;
}

const char* Analysis::_macAddrToString(const unsigned char *macaddr,
			char *buffer, size_t bufsize)
{
	if(buffer == NULL || bufsize < 18)
		return NULL;
	
	sprintf(buffer, "%x:%x:%x:%x:%x:%x", 
		macaddr[0], macaddr[1], macaddr[2], 
		macaddr[3], macaddr[4], macaddr[5]);
	return buffer;
	
	/*
	return ether_ntoa((struct ether_addr*)macaddr);
	*/
}

const char* Analysis::_ipAddrToString(size_t ipaddr, 
			char *buffer, size_t bufsize)
{
	in_addr addr;
	addr.s_addr = ipaddr;
	return inet_ntop(AF_INET, &addr, buffer, bufsize);
}
