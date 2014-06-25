#ifndef ANALYSISTREE_H_INCLUDE
#define ANALYSISTREE_H_INCLUDE

#include <vector>
#include <string>
#include "typedef.h"

class Analysis;

class AnalysisTree
{
	public://type
		enum Root
		{
			ETHER = 0,
			ARP = 1,
			IP = 2,
			ICMP = 3,
			TCP = 4,
			UDP = 5
		};
	public:
		AnalysisTree();
		~AnalysisTree();

		void buildAnalysisTree();
		void releaseAnalysisTree();
		void setProtocolFilter(const std::string &filter);
		void setProtocolFilter(const char *filter);
		void analyzeAndPrint(unsigned char *buffer, size_t bufsize);

	private://function
		bool _existInProtocolStack();
		void _printProtocolStack();

	private://data
		std::vector<Analysis*> _node;
		std::string _filter;
		ProtocolStack _pstack;
};

#endif
