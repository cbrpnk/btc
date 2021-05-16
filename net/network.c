#include <stdio.h>
#include <stdlib.h>

#include "network.h"

bc_network *bc_network_new()
{
    bc_network *net = malloc(sizeof(bc_network));
    net->peer = NULL;
    return net;
}

void bc_network_destroy(bc_network *net)
{
    bc_peer_destroy(net->peer);
    free(net);
}

int bc_network_connect(bc_network *net)
{
    // Get a list of ips to populate the peer list
    dns_record_a *a_rec;
    size_t len;
    dns_get_records_a(BC_DNS_SEED, &a_rec, &len);
    
    // TODO Make it sur that you can connect to testnet at runtime
    net->peer = bc_peer_new(a_rec[0].ip, BC_DEFAULT_PORT);
    
    // TODO Free a recs
    free(a_rec);
    
    if(bc_peer_connect(net->peer) < 0) {
        return -1;
    }
    
    return 0;
}

void bc_network_disconnect(bc_network *net)
{
    if(net->peer) {
        bc_peer_disconnect(net->peer);
    }
}

void bc_network_send(bc_network *net, bc_msg *msg)
{
    bc_peer_send(net->peer, msg);
}

void bc_network_recv(bc_network *net, bc_msg **msg)
{
    bc_peer_recv(net->peer, msg);
}
