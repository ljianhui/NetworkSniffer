#ifndef ETHERNETANALYSIS_H_INCLUDE
#define ETHERNETANALYSIS_H_INCLUDE

#include "analysis.h"

#define MAC_LEN 6

class EthernetAnalysis : public Analysis
{
	public:
		EthernetAnalysis();
		virtual ~EthernetAnalysis();
		
		virtual void analyzeProtocol(int code);
	private:
		unsigned char _dst[MAC_LEN];
		unsigned char _src[MAC_LEN];
		unsigned short _type;
};

#endif
