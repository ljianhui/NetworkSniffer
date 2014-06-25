#include <stdio.h>
#include "analysistree.h"
#include "analysis.h"
#include "ethernetanalysis.h"
#include "arpanalysis.h"
#include "ipanalysis.h"
#include "icmpanalysis.h"
#include "tcpanalysis.h"
#include "udpanalysis.h"

AnalysisTree::AnalysisTree():
	_filter("null")
{
	_node.clear();
	_pstack.clear();
}

AnalysisTree::~AnalysisTree()
{
	releaseAnalysisTree();
}

void AnalysisTree::buildAnalysisTree()
{
	releaseAnalysisTree();

	_node.push_back(new EthernetAnalysis());
	_node.push_back(new ArpAnalysis());
	_node.push_back(new IpAnalysis());
	_node.push_back(new IcmpAnalysis());
	_node.push_back(new TcpAnalysis());
	_node.push_back(new UdpAnalysis());

	_node[ETHER]->addChild(_node[ARP]);
	_node[ETHER]->addChild(_node[IP]);
	_node[IP]->addChild(_node[ICMP]);
	_node[IP]->addChild(_node[TCP]);
	_node[IP]->addChild(_node[UDP]);
}

void AnalysisTree::releaseAnalysisTree()
{
	for(int i = 0; i < _node.size(); ++i)
	{
		delete _node[i];
	}
	_node.clear();
}

void AnalysisTree::setProtocolFilter(const std::string &filter)
{
	_filter = filter;

	int dist = 'a' - 'A';
	for(int i = 0; i < _filter.length(); ++i)
	{
		if(_filter[i] >= 'A' && _filter[i] <= 'Z')
			_filter[i] += dist;
	}
}

void AnalysisTree::setProtocolFilter(const char *filter)
{
	if(filter == NULL)
		return;
	std::string tmp(filter);
	setProtocolFilter(tmp);
}

void AnalysisTree::analyzeAndPrint(unsigned char *buffer, size_t bufsize)
{
	size_t bytes = 0;
	_pstack.clear();

	_node[0]->setBuffer(buffer, bufsize);
	_node[0]->analyzeProtocol(_pstack, &bytes);
	if(_existInProtocolStack())
	{
		_printProtocolStack();
		printf("--------total bytes: %u--------\n\n",
			bytes);
	}
}

bool AnalysisTree::_existInProtocolStack()
{
	if(_filter == "null")
		return true;

	for(int i = 0; i < _pstack.size(); ++i)
	{
		if(_pstack[i]->getProtocolName() == _filter)
			return true;
	}
	return false;
}

void AnalysisTree::_printProtocolStack()
{
	for(int i = 0; i < _pstack.size(); ++i)
	{
		_pstack[i]->printResult();
	}
}
