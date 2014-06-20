#ifndef ARPANALYSIS_H_INCLUDE
#define ARPANALYSIS_H_INCLUDE

#include "analysis.h"

struct arp_header
{
	unsigned short hardware;
	unsigned short protocol;
	unsigned char hdaddr_len;
	unsigned char praddr_len;
	unsigned short opt;
	unsigned char src_hd_addr[6];
	size_t src_pr_addr;
	unsigned char dst_hd_addr[6];
	size_t dst_pr_addr;
};

class ArpAnalysis : public Analysis
{
	public:
		ArpAnalysis();
		virtual ~ArpAnalysis();

		unsigned short getHardwareType()const;
		unsigned short getProtocolType()const;
		unsigned char getHardwareAddrLen()const;
		unsigned char getProtocolAddrLen()const;
		unsigned short getOpt()const;
		const unsigned char* getSrcHardwareAddr()const;
		size_t getSrcProtocolAddr()const;
		const unsigned char* getDstHardwareAddr()const;
		size_t getDstProtocolAddr()const;

		virtual void analyzeProtocol(ProtocolStack &pstack,
						size_t *bytes = NULL);
		virtual void printResult();
	private:
		arp_header _arphdr;
};

#endif
