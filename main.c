#include <stddef.h>

#include "net/network.h"

int main()
{
    bc_network *network = bc_network_new();
    bc_network_connect(network);
    
    while(1) {
        bc_msg *msg = NULL;
        
        // TODO Do a poll/select on the socket here 
        bc_network_recv(network, &msg);
        if(msg) {
            bc_msg_destroy(msg);
        }
    }
    
    bc_network_disconnect(network);
    bc_network_destroy(network);
    return 0;
}
