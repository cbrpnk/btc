#ifndef NODE_H
#define NODE_H

#include <stdint.h>
#include <stdbool.h>
#include "net/socket.h"

typedef struct bc_network bc_network;

typedef struct bc_node {
    uint32_t ip;
    uint16_t port;
    bc_socket socket;
} bc_node;

int bc_node_connect(bc_node *remote);
int bc_node_disconnect(bc_node *remote);

#endif
