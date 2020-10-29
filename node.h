#ifndef NODE_H
#define NODE_H

#include <stdio.h>
#include <stdbool.h>

typedef struct bc_network bc_network;

typedef struct bc_node {
    bc_network *network;
    uint32_t protocol_version;
    uint32_t ip;
    uint16_t port;
    int socket;
    bool connected;
} bc_node;

int connect_to_remote(bc_node *remote);
int disconnect_from_remote(bc_node *remote);
void handshake(bc_node *node);

#endif
