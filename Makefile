CC=g++ -std=c++14 -Wall -Wextra -pedantic -I/usr/local/lang/nettle-3.2/include
LD=g++ -std=c++14 -L/usr/local/lang/nettle-3.2/lib64 -Wl,-rpath,/usr/local/lang/nettle-3.2/lib64

all: client server

server:	server.o
	$(LD) $< -o $@ -lnettle -lcurl

client:	client.o
	$(LD) $< -o $@ -lnettle

client.o:	client1.cpp mysocket.hh
	$(CC) -c $< -o $@

server.o:	server1.cpp mysocket.hh
	$(CC) -c $< -o $@

clean:
	rm -f client server *.o

distclean: clean
