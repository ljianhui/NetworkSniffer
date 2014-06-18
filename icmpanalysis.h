#ifndef ICMPANALYSIS_H_INCLUDE
#define ICMPANALYSIS_H_INCLUDE

#include "analysis.h"

class IcmpAnalysis : public Analysis
{
	public:
		IcmpAnalysis();
		virtual ~IcmpAnalysis();

		unsigned char getType()const;
		unsigned char getCode()const;
		unsigned short getCheckSum()const;
		
		virtual void analyzeProtocol(size_t *bytes = NULL);
		virtual void printResult();

	private:
		unsigned char _type;
		unsigned char _code;
		unsigned short _check_sum;
};

#endif

