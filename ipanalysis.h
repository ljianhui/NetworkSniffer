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
		const unsigned char* getDstIp()const;
		const unsigned char* getSrcIp()const;
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
		unsigned char _dst_addr[IP_LEN];
		unsigned char _src_addr[IP_LEN];
};

#endif
