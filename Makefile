default:
	gcc -g -W -Wall -Werror -o test -lssl -lcrypto debug.c crypto.c serial_buffer.c dns.c main.c && ./test
