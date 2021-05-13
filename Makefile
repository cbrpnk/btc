default:
	gcc -g -W -Wall -o test -lssl -lcrypto net/socket.c net/dns.c net/proto.c net/peer.c net/network.c crypto/crypto.c serial_buffer.c main.c && ./test
