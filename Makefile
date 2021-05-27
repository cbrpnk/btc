default:
	gcc -g -W -Wall -o test net/socket.c net/dns.c net/proto.c net/peer.c net/network.c crypto/sha256.c crypto/crypto.c serial_buffer.c main.c && ./test
