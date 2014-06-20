#ifndef UDPANALYSIS_H_INCLUDE
#define UDPANALYSIS_H_INCLUDE

#include <netinet/udp.h>
#include "analysis.h"

class UdpAnalysis : public Analysis
{
	public:
		UdpAnalysis();
		virtual ~UdpAnalysis();

		unsigned short getSrcPort()const;
		unsigned short getDstPort()const;
		unsigned short getUdpLen()const;
		unsigned short getCheckSum()const;

		virtual void analyzeProtocol(ProtocolStack &pstack,
						size_t *bytes = NULL);
		virtual void printResult();

	private:
		udphdr _udphdr;
};

#endif
