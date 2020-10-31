#include <stdio.h>

#include "node.h"
#include "proto.h"
#include "crypto.h"
#include "serial_buffer.h"
#include "dns.h"
#include "debug.h"

// Testnet seed dns
// seed.tbtc.petertodd.org
// testnet-seed.bitcoin.jonasschnelli.ch

#define TESTNET_MAGIC_NUMBER 0x0709110b
#define TESTNET_DEFAULT_PORT 18333

const uint32_t protocol_version = 70015;
const char *user_agent = "/test:0.0.1/";

int main()
{
    // TODO creat a global bitcoin object and init it
    // initialization should fetch a bunch of potential client ips 
    // into a list.
    // TODO Try to connect to a specified number of ndoes
    
    // Get a potential ip for a remote node
    dns_record_a a_rec;
    dns_get_records_a("seed.tbtc.petertodd.org", &a_rec);
   
    bc_node remote = {
        .magic_number = TESTNET_MAGIC_NUMBER,
        .protocol_version = protocol_version,
        .ip = a_rec.ip,
        .port = TESTNET_DEFAULT_PORT,
        .socket = {0},
    };
    
    if(bc_node_connect(&remote) < 0) {
        return -1;
    }
    
    bc_node_handshake(&remote);
    
    bc_node_disconnect(&remote);
    return 0;
}
