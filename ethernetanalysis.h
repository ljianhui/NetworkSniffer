#ifndef ETHERNETANALYSIS_H_INCLUDE
#define ETHERNETANALYSIS_H_INCLUDE

#include <net/ethernet.h>
#include "analysis.h"

class EthernetAnalysis : public Analysis
{
	public:
		EthernetAnalysis();
		virtual ~EthernetAnalysis();
		
		const unsigned char* getDstAddr()const;
		const unsigned char* getSrcAddr()const;
		unsigned short getType()const;
		
		virtual void analyzeProtocol(ProtocolStack &pstack,
						size_t *bytes = NULL);
		virtual void printResult();
	private:
		ether_header _etherhdr;
};

#endif
