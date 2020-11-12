default:
	gcc -g -W -Wall -o test -lssl -lcrypto debug.c net/socket.c net/dns.c net/proto.c crypto/crypto.c serial_buffer.c peer.c main.c && ./test
