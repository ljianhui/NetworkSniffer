#ifndef ARPANALYSIS_H_INCLUDE
#define ARPANALYSIS_H_INCLUDE

#include "analysis.h"

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
		unsigned short _hardware;
		unsigned short _protocol;
		unsigned char _hdaddr_len;
		unsigned char _praddr_len;
		unsigned short _opt;
		unsigned char _src_hd_addr[6];
		size_t _src_pr_addr;
		unsigned char _dst_hd_addr[6];
		size_t _dst_pr_addr;
};

#endif
