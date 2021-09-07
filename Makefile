CC = g++
ARGS = -pthread -g -lpcap

all: client server

client:
	$(CC) client.cpp $(ARGS) -o client.o

server:
	$(CC) server.cpp $(ARGS) -o server.o

threadProgram:
	gcc threadProgram.c $(ARGS) -o threadProgram.o

whathewants:
	gcc whathewants.c $(ARGS) -o whathewants.o

main:
	gcc main.c $(ARGS) -o main.o

clean:
	rm -f *.o $(OUT)