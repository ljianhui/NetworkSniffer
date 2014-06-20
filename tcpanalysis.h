#ifndef TCPANALYSIS_H_INCLUDE
#define TCPANALYSIS_H_INCLUDE

#include <netinet/tcp.h>
#include "analysis.h"

class TcpAnalysis : public Analysis
{
	public:
		TcpAnalysis();
		virtual ~TcpAnalysis();
		
		unsigned short getSrcPort()const;
		unsigned short getDstPort()const;
		size_t getSequenceNumber()const;
		size_t getAckNumber()const;
		unsigned char getHeaderLen()const;
		unsigned short getWindow()const;
		unsigned short getCheckSum()const;
		size_t hasAckFlag()const;
		size_t hasSynFlag()const;
		size_t hasFinFlag()const;
		size_t hasRstFlag()const;

		virtual void analyzeProtocol(ProtocolStack &pstack, 
						size_t *bytes = NULL);
		virtual void printResult();

	private:
		tcphdr _tcphdr;
};

#endif
