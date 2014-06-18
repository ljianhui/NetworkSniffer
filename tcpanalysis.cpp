#include <stdio.h>
#include <memory.h>
#include <strings.h>
#include "tcpanalysis.h"

TcpAnalysis::TcpAnalysis():
	Analysis("tcp", TCP_CODE),
	_src_port(0),
	_dst_port(0),
	_seq(0),
	_ack(0),
	_header_len(0),
	_flags(0x00),
	_window(0),
	_check_sum(0)
{
}

TcpAnalysis::~TcpAnalysis()
{
}

void TcpAnalysis::analyzeProtocol(size_t *bytes)
{
	unsigned short *ushort_ptr = _buffer;
	_src_port = *ushort_ptr;
	++ushort_ptr;

	_dst_port = *ushort_ptr;
	++ushort_ptr;

	size_t *uint_ptr = (size_t*)ushort_ptr;
	_seq = *uint_ptr;
	++uint_ptr;

	_ack = *uint_ptr;
	++uint_ptr;

	unsigned char *uchar_ptr = (unsigned char*)uint_ptr;
	_header_len = *uchar_ptr;
	_header_len = _header_len >> 4;
	++uchar_ptr;

	_flags = *uchar_ptr;
	_flags &= 0x3f;
	++uchar_ptr;

	ushort_ptr = (unsigned short*)uchar_ptr;
	_window = *ushort_ptr;
	++ushort_ptr;

	_check_sum = *ushort_ptr;
	++ushort_ptr;
	
	if(bytes != NULL)
		*bytes += _header_len;
	
	int port = _src_port < _dst_port ? _src_port : _dst_port;
	Analysis *child = _getChild(port);
	if(child != NULL)
	{
		child->setBuffer(_buffer + _header_len, 
				_bufsize - _header_len);
		child->analyzeProtocol(bytes);
	}
}

void TcpAnalysis::printResult()
{
	printf("TCP:\n");
	printf("\tSource port: %u, Destination port: %u\n",
		_src_port, _dst_port);
	printf("\tSequence number: %u, Ack number: %u\n",
		_seq, _ack);
	printf("\tHeader len: %u, ACK: %u, SYN: %u, FIN: %u\n",
		_head_len, hasAckFlag(), hasSynFlag(), hasFinFlag());
	printf("\tWindow size: %u, Check sum: %x",
		_window, _check_sum);
	
	int port = _src_port < _dst_port ? _src_port : _dst_port;
	Analysis *child = _getChild(port);
	if(child != NULL)
	{
		child->printResult();
	}
}

unsigned short TcpAnalysis::getSrcPort()const
{
	return _src_port;
}

unsigned short TcpAnalysis::getDstPort()const
{
	return _dst_port;
}

size_t TcpAnalysis::getSequenceNumber()const
{
	return _seq;
}

size_t gTcpAnalysis::etAckNumber()const
{
	return _ack;
}

unsigned char TcpAnalysis::getHeaderLen()const
{
	return _header_len;
}

unsigned short TcpAnalysis::getWindow()const
{
	return _window;
}

unsigned short TcpAnalysis::getCheckSum()const
{
	return _check_sum;
}

size_t TcpAnalysis::hasAckFlag()const
{
	if(_flags & (0x1 << 4))
		return 1;
	return 0;
}

size_t TcpAnalysis::hasSynFlag()const
{
	if(_flags & (0x1 << 1))
		return 1;
	return 0;
}

size_t TcpAnalysis::hasFinFlag()const
{
	if(_flags & (0x1 << 0))
		return 1;
	return 0;
}

size_t TcpAnalysis::hasRstFlag()const
{
	if(_flags & (0x1 << 2))
		return 1;
	return 0;
}

