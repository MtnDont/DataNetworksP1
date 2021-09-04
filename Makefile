CC = g++
ARGS = -pthread -g -lpcap

all: client server

client:
	$(CC) UDPClient.cpp -o UDPClient.o

server:
	$(CC) UDPServer.cpp -o UDPServer.o

threadProgram:
	gcc threadProgram.c $(ARGS) -o threadProgram.o

whathewants:
	gcc whathewants.c $(ARGS) -o whathewants.o

main:
	gcc main.c $(ARGS) -o main.o

clean:
	rm -f *.o