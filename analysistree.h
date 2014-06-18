#ifndef ANALYSISTREE_H_INCLUDE
#define ANALYSISTREE_H_INCLUDE

#include <vector>
#include <string>

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
		void setProtocolFilter(const std::string &filter);
		void analyzeAndPrint(unsigned char *buffer, size_t bufsize);
	private:
		std::vector<Analysis*> _node;
		std::string _filter;
		unsigned char *_buffer;
		size_t _bufsize;
};

#endif
