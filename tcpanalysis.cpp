#include <stdio.h>
#include <memory.h>
#include <strings.h>
#include <netinet/in.h>
#include "tcpanalysis.h"

TcpAnalysis::TcpAnalysis():
	Analysis("tcp", TCP_CODE)
{
}

TcpAnalysis::~TcpAnalysis()
{
}

void TcpAnalysis::analyzeProtocol(ProtocolStack &pstack, size_t *bytes)
{
	if(_bufsize < sizeof(_tcphdr))
	{
		bzero(&_tcphdr, sizeof(_tcphdr));
		return;
	}
	
	memcpy(&_tcphdr, _buffer, sizeof(_tcphdr));
	_tcphdr.source = ntohs(_tcphdr.source);
	_tcphdr.dest = ntohs(_tcphdr.dest);
	_tcphdr.window = ntohs(_tcphdr.window);
	_tcphdr.check = ntohs(_tcphdr.check);
	_tcphdr.urg_ptr = ntohs(_tcphdr.urg_ptr);

	if(bytes != NULL)
		bytes += (_tcphdr.doff * 4);
	pstack.push_back(this);

	int port = _tcphdr.source < _tcphdr.dest ? 
			_tcphdr.source : _tcphdr.dest;
	Analysis *child = _getChild(port);
	if(child != NULL)
	{
		child->setBuffer(_buffer + _tcphdr.doff * 4, 
				_bufsize - _tcphdr.doff * 4);
		child->analyzeProtocol(pstack, bytes);
	}
}

void TcpAnalysis::printResult()
{
	printf("TCP:\n");
	printf("\tSource port: %u, Destination port: %u\n",
		_tcphdr.source, _tcphdr.dest);
	printf("\tSequence number: %u, Ack number: %u\n",
		_tcphdr.seq, _tcphdr.ack_seq);
	printf("\tHeader len: %u, ACK: %u, SYN: %u, FIN: %u\n",
		_tcphdr.doff * 4, hasAckFlag(), hasSynFlag(), hasFinFlag());
	printf("\tWindow size: %u, Check sum: 0x%x\n",
		_tcphdr.window, _tcphdr.check);

	/*
	int port = _src_port < _dst_port ? _src_port : _dst_port;
	Analysis *child = _getChild(port);
	if(child != NULL)
	{
		child->printResult();
	}
	*/
}

unsigned short TcpAnalysis::getSrcPort()const
{
	return _tcphdr.source;
}

unsigned short TcpAnalysis::getDstPort()const
{
	return _tcphdr.dest;
}

size_t TcpAnalysis::getSequenceNumber()const
{
	return _tcphdr.seq;
}

size_t TcpAnalysis::getAckNumber()const
{
	return _tcphdr.ack_seq;
}

unsigned char TcpAnalysis::getHeaderLen()const
{
	return _tcphdr.doff * 4;
}

unsigned short TcpAnalysis::getWindow()const
{
	return _tcphdr.window;
}

unsigned short TcpAnalysis::getCheckSum()const
{
	return _tcphdr.check;
}

size_t TcpAnalysis::hasAckFlag()const
{
	return _tcphdr.ack;
}

size_t TcpAnalysis::hasSynFlag()const
{
	return _tcphdr.syn;
}

size_t TcpAnalysis::hasFinFlag()const
{
	return _tcphdr.fin;
}

size_t TcpAnalysis::hasRstFlag()const
{
	return _tcphdr.rst;
}

