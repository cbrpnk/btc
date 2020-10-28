#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>

typedef struct bc_msg_header {
    uint32_t magic;
    char     command[12];
    uint32_t len;
    uint32_t checksum;
} bc_msg_header;

typedef struct bc_msg_version {
    uint32_t version;
    uint64_t services;
    uint64_t timestamp;
    uint32_t dest_ip;
    uint16_t dest_port;
    uint32_t src_ip;
    uint16_t src_port;
    uint64_t nonce;
    size_t user_agent_len;
    char *user_agent;
    uint32_t start_height;
    bool relay;
} bc_msg_version;

void send_version(bc_msg_version *msg);
void send_msg();

void send_message(bc_node *node, bc_proto_msg *msg);

#endif
