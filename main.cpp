#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <memory.h>
#include "rawsocket.h"
#include "analysistree.h"

void DoBeforeExit(int sig);

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
		fprintf(stderr, "Can not find the app ./NetSnifferGui\n");
		exit(EXIT_FAILURE);
	}

	RawSocket rawsock;

	if(rawsock.createSocket() == false)
	{
		fprintf(stderr, "create socket failed\n");
		exit(EXIT_FAILURE);
	}

	if(opts[1] != NULL)
	{
		rawsock.bindInterface(opts[1]);
	}
	
	//set signal controller
	signal(SIGTERM, DoBeforeExit);
	signal(SIGINT, DoBeforeExit);
	
	AnalysisTree analysis_tree;
	analysis_tree.buildAnalysisTree();
	analysis_tree.setProtocolFilter(opts[0]);
	unsigned char buffer[BUF_SIZE];

	while(running)
	{
		bzero(buffer, BUF_SIZE);
		rawsock.recvPacket(buffer, BUF_SIZE);
		analysis_tree.analyzeAndPrint(buffer, BUF_SIZE);
	}
	exit(EXIT_SUCCESS);
}

void DoBeforeExit(int sig)
{
	running = false;
}

