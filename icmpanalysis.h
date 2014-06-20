#ifndef ICMPANALYSIS_H_INCLUDE
#define ICMPANALYSIS_H_INCLUDE

#include <netinet/ip_icmp.h>
#include "analysis.h"

class IcmpAnalysis : public Analysis
{
	public:
		IcmpAnalysis();
		virtual ~IcmpAnalysis();

		unsigned char getType()const;
		unsigned char getCode()const;
		unsigned short getCheckSum()const;
		
		virtual void analyzeProtocol(ProtocolStack &pstack,
						size_t *bytes = NULL);
		virtual void printResult();

	private:
		icmphdr _icmphdr;
};

#endif

