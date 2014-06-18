#include "analysistree.h"
#include "analysis.h"
#include "ethernetanalysis.h"
#include "arpanalysis.h"
#include "ipanalysis.h"
#include "icmpanalysis.h"
#include "tcpanalysis.h"
#include "udpanalysis.h"

AnalysisTree::AnalysisTree():
	_filter("null"),
	_buffer(NULL),
	_bufsize(0)
{
}

AnalysisTree::~AnalysisTree()
{
	for(int i = 0; i < _node.size(); ++i)
	{
		delete _node[i];
	}
	_node.clean();
}

void AnalysisTree::buildAnalysisTree()
{
	_node.push_back(new EthernetAnalysis());
	_node.push_back(new ArpAnalysis());
	_node.push_back(new IpAnalysis());
	_node.push_back(new IcmpAnalysis());
	_node.push_back(new TcpAnalysis());
	_node.push_back(new UdpAnalysis());
}

void AnalysisTree::setProtocolFilter(const std::string &filter)
{
	_filter = filter;
}

void AnalysisTree::analyzeAndPrint(unsigned char *buffer, size_t bufsize)
{
	size_t bytes = 0;
	_node[0]->setBuffer(buffer, bufsize);
	_node[0]->analyzeProtocol(&bytes);
	_node[0]->printResult();
	printf("--------total bytes package: %u--------\n\n",
		bytes);
}
