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
		const unsigned char* getSrcProtocolAddr()const;
		const unsigned char* getDstHarewareAddr()const;
		const unsigned char* getDstprotocolAddr()const;

		virtual void analyzeProtocol(size_t *bytes = NULL);
		virtual void printResult();
	private:
		unsigned short _hardware;
		unsigned short _protocol;
		unsigned char _hdaddr_len;
		unsigned char _praddr_len;
		unsigned short _opt;
		unsigned char _src_hd_addr[6];
		unsigned char _src_pr_addr[4];
		unsigned char _dst_hd_addr[6];
		unsigned char _dst_pr_addr[4];
};

#endif
