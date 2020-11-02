#include "config.h"
#include "net/dns.h"
#include "node.h"

// Testnet seed dns
// seed.tbtc.petertodd.org
// testnet-seed.bitcoin.jonasschnelli.ch

int main()
{
    // TODO create a global bitcoin object and init it
    // initialization should fetch a bunch of potential client ips 
    // into a list.
    // TODO Try to connect and stay connected 
    // to a specified number of ndoes
    
    // Get a potential ip for a remote node
    dns_record_a a_rec;
    dns_get_records_a("seed.tbtc.petertodd.org", &a_rec);
   
    bc_node remote = {
        .ip = a_rec.ip,
        .port = BC_TESTNET_DEFAULT_PORT,
    };
    
    if(bc_node_connect(&remote) < 0) {
        return -1;
    }
    bc_node_disconnect(&remote);
    return 0;
}
