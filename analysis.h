#ifndef ANALYSIS_H_INCLUDE
#define ANALYSIS_H_INCLUDE

#include <string>
#include <stddef.h>
#include <list>
#include "typedef.h"

class Analysis
{
	public:
		Analysis(const std::string &pname = "", int pcode = 0);
		virtual ~Analysis();

		void addChild(Analysis *child);
		void setBuffer(unsigned char *buffer, size_t bufsize);
		
		std::string getProtocolName()const;
		unsigned short getPCode()const;

		virtual void analyzeProtocol(size_t *bytes = NULL) = 0;
		virtual void printResult() = 0;

	protected://function
		Analysis* _getChild(int code);
		const char* _macAddrToString(const unsigned char *macaddr);
		const char* _ipAddrToString(const unsigned char *ipaddr);

	protected://data
		unsigned char *_buffer;
		size_t _bufsize;
		std::string _protocol_name;

		const unsigned short _pcode;

	private:
		std::list<Analysis*> _childern;
		char _addr_str[18];
};

#endif
