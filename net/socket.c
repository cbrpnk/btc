#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "socket.h"

int bc_socket_init(bc_socket *s, bc_socket_type type, uint32_t ip,
                    uint16_t port)
{
    int native_type = 0;
    int protocol = 0;
    
    switch(type) {
    case BC_SOCKET_UDP:
        native_type = SOCK_DGRAM;
        protocol = IPPROTO_UDP;
        break;
    case BC_SOCKET_TCP:
        native_type = SOCK_STREAM;
        protocol = IPPROTO_TCP;
        break;
    }
    
    s->type = type;
    s->ip = ip;
    s->port = port;
    s->saddr_in.sin_family = AF_INET;
    s->saddr_in.sin_port = htons(port);
    memcpy(&s->saddr_in.sin_addr, &ip, sizeof(ip));
    
    if((s->id = socket(AF_INET, native_type, protocol)) < 0) {
        printf("Socket creation error\n");
        return -1;
    }
    
    return 0;
}

void bc_socket_destroy(bc_socket *s)
{
    close(s->id);
    s->connected = false;
}

int bc_socket_connect(bc_socket *s)
{
    if((connect(s->id, (struct sockaddr *) &s->saddr_in,
            sizeof(s->saddr_in))) < 0) {
        printf("Connection Failed\n");
        return -1;
    }
    
    s->connected = true;
    return 0;
}

int bc_socket_send(bc_socket *s, const void *buffer, unsigned int len)
{
    switch(s->type) {
    case BC_SOCKET_UDP:
        sendto(s->id, buffer, len, 0, (struct sockaddr *) &s->saddr_in, sizeof(s->saddr_in));
        break;
    case BC_SOCKET_TCP:
        if(s->connected) {
            return send(s->id, buffer, len, 0);
        }
        break;
    }
    return -1;
}

int bc_socket_recv(bc_socket *s, void *out, unsigned int max_len, int flags)
{
    switch(s->type) {
    case BC_SOCKET_UDP:
        recvfrom(s->id, out, max_len, flags, NULL, NULL);
        break;
    case BC_SOCKET_TCP:
        if(s->connected) {
            return recv(s->id, out, max_len, flags);
        }
        break;
    }
    return 0;
}
