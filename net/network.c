#include <stdio.h>
#include <stdlib.h>

#include "network.h"

bc_network *bc_network_new()
{
    bc_network *net = malloc(sizeof(bc_network));
    net->address_list = NULL;
    net->address_list_len = 0;
    net->peer = NULL;
    return net;
}

void bc_network_destroy(bc_network *net)
{
    free(net->address_list);
    bc_peer_destroy(net->peer);
    free(net);
}

static void populate_peer_addr(bc_network *net)
{
    // TODO Make it so that you can connect to testnet at runtime
    
    // TODO Try a list of bitcoin seeds
    
    // Get a list of ips to populate the peer list
    dns_record_a *a_rec;
    dns_get_records_a(BC_DNS_SEED, &a_rec, &net->address_list_len);
    
    // Populate address list
    net->address_list = malloc(sizeof(bc_peer_addr) * net->address_list_len);
    for(size_t i=0; i<net->address_list_len; ++i) {
        net->address_list[i].ip = a_rec[i].ip;
        net->address_list[i].port = BC_DEFAULT_PORT;
    }
    
    free(a_rec);
}

int bc_network_connect(bc_network *net)
{
    populate_peer_addr(net);
    
    // Try to connect to a number of peers specified in the config file
    
    net->peer = bc_peer_new(net->address_list[0].ip, net->address_list[0].port);
    
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
