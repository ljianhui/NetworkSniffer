#ifndef ANALYSIS_H_INCLUDE
#define ANALYSIS_H_INCLUDE

#include <string>
#include <stddef.h>
#include <list>
#include <vector>
#include "typedef.h"

class Analysis
{
	public:
		Analysis(const std::string &pname = "", int pcode = 0);
		virtual ~Analysis();

		virtual void addChild(Analysis *child);
		void setBuffer(const unsigned char *buffer, size_t bufsize);
		
		std::string getProtocolName()const;
		unsigned short getPCode()const;

		virtual void analyzeProtocol(ProtocolStack &pstack,
						size_t *bytes = NULL) = 0;
		virtual void printResult() = 0;

	protected://function
		Analysis* _getChild(int code);
		const char* _macAddrToString(const unsigned char *macaddr, 
					char *buffer, size_t bufsize);
		const char* _ipAddrToString(size_t ipaddr, 
					char *buffer, size_t bufsize);

	protected://data
		const unsigned char *_buffer;
		size_t _bufsize;
		std::string _protocol_name;

		const unsigned short _pcode;//symbol the protocol

	private:
		std::list<Analysis*> _childern;
};

#endif
