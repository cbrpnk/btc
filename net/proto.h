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

typedef struct bc_proto_header {
    uint32_t magic;
    char     command[12];
    uint32_t payload_len;
    uint32_t checksum;
} bc_proto_header;

void bc_proto_serialize_header(serial_buffer *message, const char *cmd);
void bc_proto_deserialize_header(serial_buffer *msg, bc_proto_header *header);


//////////////////// Variable length fields ///////////////////////

void bc_proto_varint_deserialize();

///////////////////////////// Msg //////////////////////////////

typedef enum bc_msg_type {
    BC_MSG_INVALID = 0, // In case a type is zero-initialized
    BC_MSG_INV,
    BC_MSG_PING,
    BC_MSG_PONG,
    BC_MSG_VERACK,
    BC_MSG_VERSION,
} bc_msg_type;

// The first member of every derived message is a bc__msg_type.
// This struct is a abstract msg which enables casting to a specific 
// msg type at run time.
typedef struct bc_msg {
    bc_msg_type type;
} bc_msg;
void bc_msg_destroy(bc_msg *msg);

////////////////////////////// Inv //////////////////////////

typedef struct bc_proto_inv_vec {
    uint32_t type;  // TODO Make that an enum
    char hash[32];
} bc_proto_inv_vec;

typedef struct bc_msg_inv {
    bc_msg_type type;
    uint64_t count;
    bc_proto_inv_vec *inv_vec;  // TODO Memory Leak here
} bc_msg_inv;

void bc_proto_inv_deserialize(bc_msg_inv *msg, serial_buffer *buf);
void bc_proto_inv_print(bc_msg_inv *msg);

////////////////////////////// Ping //////////////////////////

typedef struct bc_msg_ping {
    bc_msg_type type;
    uint64_t nonce;
} bc_msg_ping;

void bc_msg_ping_serialize(bc_msg_ping *msg, serial_buffer *buf);
void bc_msg_ping_deserialize(bc_msg_ping *msg, serial_buffer *buf);
void bc_msg_ping_print(bc_msg_ping *msg);

////////////////////////////// Pong //////////////////////////

typedef struct bc_msg_pong {
    bc_msg_type type;
    uint64_t nonce;
} bc_msg_pong;

void bc_msg_pong_serialize(bc_msg_pong *msg, serial_buffer *buf);
void bc_msg_pong_deserialize(bc_msg_pong *msg, serial_buffer *buf);
void bc_msg_pong_print(bc_msg_pong *msg);

////////////////////////////// Verack ////////////////////////
typedef struct bc_msg_verack {
    bc_msg_type type; // A verack msg is just a header
} bc_msg_verack;


void bc_msg_verack_serialize(serial_buffer *buf);
void bc_msg_verack_print();


////////////////////////////// Version ///////////////////////////
typedef struct bc_msg_version {
    // Type has to be the first element to allow casting 
    bc_msg_type type;
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

void bc_msg_version_serialize(bc_msg_version *msg, serial_buffer *buf);
void bc_msg_version_deserialize(bc_msg_version *msg, serial_buffer *buf);
void bc_msg_version_print(bc_msg_version *msg);

#endif
