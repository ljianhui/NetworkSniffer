#ifndef ANALYSIS_H_INCLUDE
#define ANALYSIS_H_INCLUDE

#include <string>
#include <stddef.h>
#include <list>

class Analysis
{
	public:
		Analysis(size_t bufsize);
		virtual ~Analysis();

		void addChild(Analysis *child);
		void setBuffer(char *buffer, size_t bufsize);
		
		std::string getProtocolName()const;
		unsigned short getSumLength()const;
		unsigned short getCode()const;

		virtual void analyzeProtocol(int code) = 0;

	protected:
		unsigned char *_buffer;
		size_t _bufsize;
		std::string _protocol_name;
		unsigned short _sum_len;

		const unsigned short _code;

	private:
		std::list<Analysis*> _childern;
};

#endif
