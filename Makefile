default:
	gcc -o test -lssl -lcrypto buffer.c main.c && ./test
