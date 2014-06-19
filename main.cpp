#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <memory.h>
#include "rawsocket.h"
#include "analysistree.h"

struct ThreadArg
{
	unsigned char *buffer;
	size_t buf_row;
	size_t buf_col;
	const char *filter;
	int *r_pos;
	int *w_pos;
};

void DoBeforeExit(int sig);
void* AnalysisThread(void *thread_arg);

bool running = true;

int main(int argc, char **argv)
{
	char arg = '\0';
	char *opts[5] = {0};

	memset(opts, 0, sizeof(opts));

	//analyze the input arguments
	while((arg = getopt(argc, argv, "p:i:g")) != -1)
	{
		switch(arg)
		{
			case 'p':
				opts[0] = optarg;
				break;
			case 'i':
				opts[1] = optarg;
				break;
			case 'g':
				opts[2] = &arg;
				break;
			default:
				opts[3] = &arg;
		}
	}

	//control the cmd
	if(opts[3] != 0)
	{
		fprintf(stderr, "unkown argmemts %c\n", *opts[3]);
		exit(EXIT_FAILURE);
	}
	
	if(opts[2] != NULL)
	{
		int ret = execvp("./NetSnifferGui", argv);
		fprintf(stderr, "Can not find the app NetSnifferGui\n");
		exit(EXIT_FAILURE);
	}

	RawSocket rawsock;
	ThreadArg thread_arg;
	if(rawsock.createSocket())
	{
		fprintf(stderr, "create socket failed\n");
		exit(EXIT_FAILURE);
	}

	if(opts[0] != NULL)
	{
		thread_arg.filter = opts[0];
	}
	if(opts[1] != NULL)
	{
		rawsock.bindInterface(opts[1]);
	}

	const int row = 100;
	const int col = 200;
	unsigned char *buffer = new unsigned char[row * col];

	int r_pos = 0;
	int w_pos = 0;

	thread_arg.buffer = buffer;
	thread_arg.buf_row = row;
	thread_arg.buf_col = col;
	thread_arg.r_pos = &r_pos;
	thread_arg.w_pos = &w_pos;

	pthread_t tid = 0;
	void *thread_ret = NULL;
	tid = pthread_create(&tid, NULL, AnalysisThread, &thread_arg);

	signal(SIGTERM, DoBeforeExit);
	signal(SIGINT, DoBeforeExit);

	while(running)
	{
		unsigned char *buf_begin = buffer + w_pos * col;
		bzero(buf_begin, col);
		rawsock.recvPacket(buf_begin, col);
		if(++w_pos == row)
			w_pos = 0;
	}
	
	int ret = pthread_join(tid, &thread_ret);
	
	delete[] buffer;
	return 0;
}

void DoBeforeExit(int sig)
{
	running = false;
}

void* AnalysisThread(void *arg)
{
	ThreadArg *thread_arg = (ThreadArg*)arg;
	AnalysisTree analy_tree;
	analy_tree.buildAnalysisTree();
	analy_tree.setProtocolFilter(thread_arg->filter);
	while(running)
	{
		if(*(thread_arg->r_pos) != *(thread_arg->w_pos))
		{
			unsigned char *buf_begin = thread_arg->buffer + 
				*(thread_arg->r_pos) * thread_arg->buf_col;
			analy_tree.analyzeAndPrint(buf_begin, thread_arg->buf_col);
			++(*(thread_arg->r_pos));
			if(*(thread_arg->r_pos) == thread_arg->buf_row)
				*(thread_arg->r_pos) = 0;
		}
	}
	pthread_exit(NULL);
}
