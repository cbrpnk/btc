#ifndef NODE_H
#define NODE_H

#include <stdint.h>
#include <stdbool.h>
#include "socket.h"

typedef struct bc_peer {
    uint32_t ip;
    uint16_t port;
    bc_socket socket;
} bc_peer;

int bc_peer_connect(bc_peer *remote);
int bc_peer_disconnect(bc_peer *remote);

#endif
