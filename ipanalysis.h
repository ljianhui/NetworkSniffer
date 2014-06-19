#ifndef IPANALYSIS_H_INCLUDE
#define IPANALYSIS_H_INCLUDE

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
		unsigned char _version;
		unsigned char _header_len;
		unsigned short _ip_package_len;
		unsigned char _ttl;
		unsigned char _protocol;
		unsigned short _check_sum;
		size_t _dst_addr;
		size_t _src_addr;
};

#endif
