#ifndef NODE_H
#define NODE_H

#include <stdint.h>
#include <stdbool.h>

typedef struct bc_network bc_network;

typedef struct bc_node {
    uint32_t magic_number;
    uint32_t protocol_version;
    uint32_t ip;
    uint16_t port;
    int socket;
    bool connected;
} bc_node;

int bc_node_connect(bc_node *remote);
int bc_node_disconnect(bc_node *remote);
void bc_node_handshake(bc_node *node);

#endif
