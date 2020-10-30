#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "socket.h"

int bc_socket_connect(bc_socket *s, uint32_t ip, uint16_t port)
{
    if((s->id = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        printf("Socket creation error\n");
        return -1;
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr, &ip, sizeof(ip));
    
    if((connect(s->id, (struct sockaddr *) &server_addr,
            sizeof(server_addr))) < 0) {
        printf("Connection Failed\n");
        return -1;
    }
    
    s->connected = true;
    return 0;
}

void bc_socket_disconnect(bc_socket *s)
{
    close(s->id);
    s->connected = false;
}

int bc_socket_send(bc_socket *s, const void *buffer, unsigned int len)
{
    if(s->connected) {
        return send(s->id, buffer, len, 0);
    }
    return -1;
}

int bc_socket_recv(bc_socket *s, void *out, unsigned int max_len)
{
    if(s->connected) {
        return recv(s->id, out, max_len, 0);
    }
    return 0;
}
