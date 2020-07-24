default:
	gcc -o test -lssl -lcrypto main.c && ./test
