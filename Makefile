default:
	gcc -g -W -Werror -Wall -o test -lssl -lcrypto debug.c crypto.c buffer.c dns.c main.c && ./test
