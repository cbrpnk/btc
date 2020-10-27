#ifndef NETWORK_H
#define NETWORK_H

// Testnet
const uint32_t testnet_magic_number = 0x0709110b;
const uint16_t testnet_port = 18333;

typedef struct bc_network {
    uint32_t magic_number;
    uint16_t default_port;
} bc_network;


#endif
