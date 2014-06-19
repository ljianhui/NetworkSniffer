#ifndef ETHERNETANALYSIS_H_INCLUDE
#define ETHERNETANALYSIS_H_INCLUDE

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
		unsigned char _dst_addr[MAC_LEN];
		unsigned char _src_addr[MAC_LEN];
		unsigned short _type;
};

#endif
