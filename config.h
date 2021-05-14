#ifndef BC_CONFIG_H
#define BC_CONFIG_H

#define BC_USER_AGENT           "/test:0.0.1/"
#define BC_PROTO_VER            70015

// Uncomment to get debug output
#define NET_DEBUG (1)

// Comment this out for mainnet
#define TESTNET (1)

// Mainnet
#ifdef TESTNET
    #define BC_DEFAULT_PORT 18333
    #define BC_MAGIC_NUM    0x0709110b
    #define BC_DNS_SEED     "seed.tbtc.petertodd.org"
#else
    #define BC_DEFAULT_PORT 8333
    #define BC_MAGIC_NUM    0xd9b4bef9
    #define BC_DNS_SEED     "seed.bitcoin.sipa.be"
    //#define BC_DNS_SEED     "seed.btc.petertodd.org"
#endif

#endif
