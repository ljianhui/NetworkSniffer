#ifndef IPANALYSIS_H_INCLUDE
#define IPANALYSIS_H_INCLUDE

#include <netinet/ip.h>
#include "analysis.h"

class IpAnalysis : public Analysis
{
	public:
		IpAnalysis();
		virtual ~IpAnalysis();

		unsigned char getVersion()const;
		unsigned char getHeaderLen()const;
		size_t getDstIp()const;
		size_t getSrcIp()const;
		unsigned short getIpPackageLen()const;
		unsigned char getTTL()const;
		unsigned char getProtocol()const;
		unsigned short getCheckSum()const;

		virtual void analyzeProtocol(ProtocolStack &pstack,
						size_t *bytes = NULL);
		virtual void printResult();
	private:
		iphdr _iphdr;
};

#endif
