#ifndef ANALYSISTREE_H_INCLUDE
#define ANALYSISTREE_H_INCLUDE

#include <vector>

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
			IP = 5
		};
	public:
		AnalysisTree();
		~AnalysisTree();

		void buildAnalysisTree();
		void setRoot(Root root);
		void setBuffer(unsigned char *buffer, size_t bufsize);
		void analyzeAndPrint();
	private:
		std::vector<Analysis*> _node;
		Analysis *_root;
		unsigned char *_buffer;
		size_t _bufsize;
};

#endif
