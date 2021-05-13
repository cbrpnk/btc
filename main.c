#include "config.h"
#include "net/dns.h"
#include "net/peer.h"

#include <stdio.h>

int main()
{
    dns_record_a a_rec;
    dns_get_records_a(BC_DNS_SEED, &a_rec);
   
    bc_peer remote = {
        .ip = a_rec.ip,
        .port = BC_DEFAULT_PORT,
    };
    
    if(bc_peer_connect(&remote) < 0) {
        return -1;
    }
    
    while(1) {
        bc_msg *msg;
        bc_peer_recv(&remote, &msg);
        bc_msg_destroy(msg);
    }
    
    bc_peer_disconnect(&remote);
    return 0;
}
