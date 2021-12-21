# ICMP Packet Reader

A project made for CS 4133 Data Networks at the University of Oklahoma

The client program will read in a given pcap file and send it across an address and port via UDP for a server program to parse header information and data from

## Data Extracted

* Radiotap Header
* 802.11 Header
* IP Header
* ICMP Message Data

## Usage

A Makefile is provided to compile a client and server program

### Server

STDOUT:
```
server.o
```
File Output
```
server.o <filename>
```

### Client

```
client.o <host address> <port>
```