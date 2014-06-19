APPNAME := netsniffer

all: $(APPNAME)

CC := g++

CFLAGS := -lpthread

OBJS := main.o rawsocket.o analysis.o ethernetanalysis.o arpanalysis.o \
        ipanalysis.o icmpanalysis.o tcpanalysis.o udpanalysis.o \
	analysistree.o

$(APPNAME): $(OBJS)
	$(CC) -o $(APPNAME) $(OBJS) $(CFLAGS)

main.o: main.cpp analysistree.h rawsocket.h
	$(CC) -c main.cpp $(CFLAGS)

rawsocket.o: rawsocket.cpp rawsocket.h
	$(CC) -c rawsocket.cpp

analysis.o: typedef.h analysis.h analysis.cpp
	$(CC) -c analysis.cpp

ethernetanalysis.o: analysis.h ethernetanalysis.h ethernetanalysis.cpp
	$(CC) -c ethernetanalysis.cpp

arpanalysis.o: analysis.h arpanalysis.h arpanalysis.cpp
	$(CC) -c arpanalysis.cpp

ipanalysis.o: analysis.h ipanalysis.h ipanalysis.cpp
	$(CC) -c ipanalysis.cpp

icmpanalysis.o: analysis.h icmpanalysis.h icmpanalysis.cpp
	$(CC) -c icmpanalysis.cpp

tcpanalysis.o: analysis.h tcpanalysis.h tcpanalysis.cpp
	$(CC) -c tcpanalysis.cpp

udpanalysis.o: analysis.h udpanalysis.h udpanalysis.cpp
	$(CC) -c udpanalysis.cpp

analysistree.o: analysis.h ethernetanalysis.h arpanalysis.h ipanalysis.h \
                icmpanalysis.h tcpanalysis.h udpanalysis.h analysistree.h \
		typedef.h analysistree.cpp
	$(CC) -c analysistree.cpp

clean:
	rm -f *.o $(APPNAME)

