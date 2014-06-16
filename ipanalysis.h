#ifndef IPANALYSIS_H_INCLUDE
#define IPANALYSIS_H_INCLUDE

#include "analysis.h"

#define IP_LEN 4

class IpAnalysis : public Analysis
{
	public:
		IpAnalysis();
		virtual ~IpAnalysis();

		unsigned short getIpPackageLen()const;

		virtual void analyzeProcotol(int level);
	private:
		unsigned char _dst[IP_LEN];
		unsigned char _src[IP_LEN];
		unsigned short _ip_package_len;
		unsigned char _ttl;
		unsigned char _protocol;
};

#endif
