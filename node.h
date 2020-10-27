#ifndef NODE_H
#define NODE_H

typedef struct bc_network bc_network;

typedef struct bc_node {
    bc_network *network;
    uint32_t protocol_version;
    uint32_t ip;
    uint16_t port;
    int socket;
    bool connected;
} bc_node;

#endif
