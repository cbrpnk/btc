#ifndef NODE_H
#define NODE_H

#include <stdint.h>
#include <stdbool.h>
#include "socket.h"
#include "proto.h"

typedef struct bc_peer {
    uint32_t ip;
    uint16_t port;
    bc_socket socket;
} bc_peer;

int bc_peer_connect(bc_peer *remote);
int bc_peer_disconnect(bc_peer *remote);
void bc_peer_send(bc_peer *remote, bc_msg *msg);
void bc_peer_recv(bc_peer *remote, bc_msg **out);

#endif
