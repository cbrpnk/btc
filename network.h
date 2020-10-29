#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>

// Testnet
extern const uint32_t testnet_magic_number;
extern const uint16_t testnet_port;

typedef struct bc_network {
    uint32_t magic_number;
    uint16_t default_port;
} bc_network;

#endif
