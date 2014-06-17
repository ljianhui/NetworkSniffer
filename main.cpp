#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include "rowsocket.h"
#include "analysis.h"
#include "ethernetanalysis.h"
#include "arpanalysis.h"
#include "ipanalysis.h"
#include "icmpanalysis.h"
#include "tcpanalysis.h"
#include "udpanalysis.h"

struct ThreadArg
{
	unsigned char *buffer;
	size_t buf_row;
	size_t buf_col;
	size_t root;
	int *r_pos;
	int *w_pos;
};

void DoBeforeExit(int sig);
void* AnalysisThread(void *thread_arg);

bool running = true;

int main(int argc, char **argv)
{
	char arg = '\0';
	size_t opt = 0;
	char* optargs[5] = {0};

	//analyze the input arguments
	while((arg = getopt(argc, argv, "p:i:g")) != -1)
	{
		opt = 0;
		switch(arg)
		{
			case 'p':
				opt += 1;
				optargs[0] = optarg;
				break;
			case 'i':
				opt += 2;
				optargs[1] = optarg;
				break;
			case 'g':
				opt += 4;
				break;
			default:
				opt += 8;
				optargs[3] = &opt;
		}
	}

	//control the cmd
	if(opt & (0x1 << 3))
	{
		fprintf(stderr, "unkown arguments: %c\n", *optargs[3]);
		return 0;
	}

	RawSocket rawsock;
	int root = 0;
	if(opt & (0x1))
	{
		root = rawsock.createSocket(optargs[0]);
	}
	if(opt & (0x1 << 2))
	{
		rawsock.bind(optargs[1]);
	}

	const int row = 100;
	const int col = 200;
	unsigned char *buffer = new unsigned char[row * col];

	int r_pos = 0;
	int w_pos = 0;

	ThreadArg thread_arg;
	thread_arg.buffer = buffer;
	thread_arg.buf_row = row;
	thread_arg.buf_col = col;
	thread_arg.root = root;
	thread_arg.r_pos = &r_pos;
	thread_arg.w_pos = &w_pos;

	pthread_t tid = 0;
	void *thread_ret = NULL;
	tid = pthread_create(&tid, NULL, AnalysisThread, &thread_arg);

	single(SIGTERM, DoBeforeExit);
	single(SIGINT, DoBeforeExit);

	while(running)
	{
		unsigned char *buf_begin = buffer + w_pos * col;
		bzero(buf_begin, col);
		rawsock.recvPacket(buf_begin, col);
		w_pos == (row-1) ? 0:++w_pos;
	}
	
	int ret = pthread_join(tid, &thread_ret);
	
	delete[] buffer;
	return 0;
}
