#ifndef BC_SOCKET_H
#define BC_SOCKET_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum bc_socket_type {
    BC_SOCKET_UDP,
    BC_SOCKET_TCP,
} bc_socket_type;

typedef struct bc_socket {
    int id;
    bool connected;
} bc_socket;

int bc_socket_init(bc_socket *s, bc_socket_type type);
int bc_socket_connect(bc_socket *s, uint32_t ip, uint16_t port);
int bc_socket_send(bc_socket *s, const void *buffer, unsigned int len);
int bc_socket_recv(bc_socket *s, void *out, unsigned int max_len);
void bc_socket_disconnect(bc_socket *s);

#endif
