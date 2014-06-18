#include "analysis.h"
#include "stdio.h"

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

void Analysis::setBuffer(unsigned char *buffer, size_t bufsize)
{
	_buffer = buffer;
	bufsize = bufsize;
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

const char* _Analysis::_macAddrToString(unsigned char *macaddr)
{
	sprintf(_mac_str, "%x:%x:%x:%x:%x:%x", 
		macaddr[0], macaddr[1], macaddr[2], 
		macaddr[3], macaddr[4], macaddr[5]);
	return _mac_str;
}

const char* _ipAddrToString(unsigned char *ipaddr)
{
	sprintf(_ip_str, "%d.%d.%d.%d",
		ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
	return _ip_str;
}
