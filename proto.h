#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>
#include <stdbool.h>

#include "serial_buffer.h"
#include "socket.h"

#define MESSAGE_HEADER_LEN 24

typedef struct bp_net_addr {
    uint32_t time;      // Not present in version message
    uint64_t services;
    uint64_t ip;        // IPVv4/v6
    uint16_t port;
} bp_net_addr;

typedef struct bc_msg_header {
    uint32_t magic;
    char     command[12];
    uint32_t len;
    uint32_t checksum;
} bc_msg_header;

typedef struct bc_msg_version {
    uint32_t    version;
    uint64_t    services;
    uint64_t    timestamp;
    bp_net_addr dest;
    bp_net_addr src;
    uint64_t    nonce;
    size_t      user_agent_len;
    char        *user_agent;
    // Start height, last block received by us
    uint32_t    start_height;
    bool        relay;
} bc_msg_version;

void bc_proto_send_version(bc_socket *socket, bc_msg_version *msg);
void bc_proto_send_message(bc_socket *socket, serial_buffer *msg);

#endif
