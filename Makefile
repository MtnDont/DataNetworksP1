CC = g++
ARGS = -g -lpcap

all: client server

client:
	$(CC) client.cpp $(ARGS) -o client.o

server:
	$(CC) server.cpp $(ARGS) -o server.o

clean:
	rm -f *.o $(OUT)