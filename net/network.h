#ifndef BC_NETWORK_H
#define BC_NETWORK_H

#include "../config.h"
#include "dns.h"
#include "peer.h"

// bc_network manages a bunch of peers

typedef struct bc_network {
    // TODO address list
    bc_peer *peer;
} bc_network;

bc_network *bc_network_new();
void bc_network_destroy(bc_network *net);
int bc_network_connect(bc_network *net);
void bc_network_disconnect(bc_network *net);
void bc_network_send(bc_network *net, bc_msg *msg);
void bc_network_recv(bc_network *net, bc_msg **msg);

#endif
