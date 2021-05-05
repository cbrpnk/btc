#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>
#include <stdbool.h>

#include "../serial_buffer.h"
#include "socket.h"

#define MESSAGE_HEADER_LEN 24

typedef struct bc_proto_net_addr {
    uint32_t time;      // Not present in version message
    uint64_t services;
    uint64_t ip;        // IPVv4/v6
    uint16_t port;
} bc_proto_net_addr;

void bc_proto_net_addr_print(bc_proto_net_addr *n);

typedef enum bc_proto_msg_type {
    BC_PROTO_INVALID = 0, // In case a type is zero-initialized
    BC_PROTO_VERSION,
    BC_PROTO_VERACK,
} bc_proto_msg_type;

typedef struct bc_proto_header {
    uint32_t magic;
    char     command[12];
    uint32_t len;               // TODO rename to payload_len
    uint32_t checksum;
} bc_proto_header;

// The first member of every derived message is a bc_proto_msg_type.
// This struct is a abstract msg which enables casting to a specific 
// msg type at run time.
typedef struct bc_proto_msg {
    bc_proto_msg_type   type;
} bc_proto_msg;
void bc_proto_msg_destroy(bc_proto_msg *msg);

////////////////////////////// Version
typedef struct bc_msg_version {
    // Type has to be the first element to allow casting 
    bc_proto_msg_type type;
    uint32_t          version;
    uint64_t          services;
    uint64_t          timestamp;
    bc_proto_net_addr dest;
    bc_proto_net_addr src;
    uint64_t          nonce;
    
    // TODO Prefix this constant
    // TODO Make printing handle a non-null terminated string
    #define USER_AGENT_MAX_LEN 64
    char              user_agent[USER_AGENT_MAX_LEN];
    
    // Start height, last block received by us
    uint32_t          start_height;
    bool              relay;
} bc_msg_version;

////////////////////////////// Verack
typedef struct bc_msg_verack {
    bc_proto_msg_type type; // A verack msg is just a header
} bc_msg_verack;


void bc_proto_send_buffer(bc_socket *socket, serial_buffer *msg);
void bc_proto_recv(bc_socket *socket, bc_proto_msg **msg_out);

void bc_proto_version_deserialize(bc_msg_version *msg, serial_buffer *buf);
void bc_proto_version_send(bc_socket *socket, bc_msg_version *msg);
void bc_proto_version_print(bc_msg_version *msg);

void bc_proto_verack_send(bc_socket *socket);
void bc_proto_verack_print();

#endif
