#ifndef UDPANALYSIS_H_INCLUDE
#define UDPANALYSIS_H_INCLUDE

#include "analysis.h"

class UdpAnalysis : public Analysis
{
	public:
		UdpAnalysis();
		virtual ~UdpAnalysis();

		unsigned short getSrcport()const;
		unsigned short getDstPort()const;
		unsigned short getUdpLen()const;
		unsigned short getCheckSum()const;

		virtual void analyzeProtocol(int code);
		virtual void printResult();

	private:
		unsigned short _src_port;
		unsigned short _dst_port;
		unsigned short _udp_len;
		unsigned short _check_sum;
};

#endif
