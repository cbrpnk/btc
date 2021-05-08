#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "peer.h"
#include "proto.h"
#include "../config.h"
#include "../crypto/crypto.h"

static void handle_msg_ping(bc_peer *peer, bc_msg_ping *msg)
{
    bc_proto_ping_print(msg);
    bc_msg_pong pong = {
        .type = BC_PROTO_PONG,
        .nonce = msg->nonce
    };
    bc_peer_send(peer, (bc_proto_msg *) &pong);
    bc_proto_pong_print(&pong);
}

static void handle_msg_pong(bc_msg_pong *msg)
{
    bc_proto_pong_print(msg);
}

static void handle_msg_verack()
{
    bc_proto_verack_print();
}

static void handle_msg_version(bc_peer *peer, bc_msg_version *msg)
{
    bc_proto_version_print(msg);
    bc_proto_msg verack = {
        .type = BC_PROTO_VERACK
    };
    bc_peer_send(peer, &verack);
    bc_proto_verack_print();
}


// TODO There should not be a handshake function. The peer should
// send a version message, then enter the non-blocking recv/process loop.
static void handshake(bc_peer *peer)
{
    bc_msg_version msg = {
        .type = BC_PROTO_VERSION,
        .version = BC_PROTO_VER,
        .services = 1,
        .timestamp = (uint64_t) time(NULL),
        .dest = {
            .time = 0,
            .services = 1,
            .ip = (uint64_t) peer->ip,
            .port = peer->port
        },
        .src = {
            .time = 0,
            .services = 1,
            .ip = 0,
            .port = 0
        },
        .nonce = gen_nonce_64(),
        //.user_agent is memcopied below
        .start_height = 0,
        .relay = 1
    };
    memcpy(msg.user_agent, BC_USER_AGENT, strlen(BC_USER_AGENT));
    bc_proto_version_print(&msg);
    bc_peer_send(peer, (bc_proto_msg *) &msg);
    
    // Main loop
    // TODO Peer should only handle version verack ping pong
    // Everything else should be handeled by upper layer
    //for(int i=0; i<10; ++i) {
    while(1) {
        bc_proto_msg *res = NULL;
        bc_peer_recv(peer, &res);
        if(res) {
            switch(res->type) {
            case BC_PROTO_PING:
                handle_msg_ping(peer, (bc_msg_ping *) res);
                break;
            case BC_PROTO_PONG:
                handle_msg_pong((bc_msg_pong *) res);
                break;
            case BC_PROTO_VERACK:
                handle_msg_verack();
                break;
            case BC_PROTO_VERSION:
                handle_msg_version(peer, (bc_msg_version *) res);
                break;
            case BC_PROTO_INVALID:
                // Cascade down
            default:
                printf("Peer: invalid message");
            }
            bc_proto_msg_destroy(res);
        }
    }
}

int bc_peer_connect(bc_peer *remote)
{
    bc_socket_init(&remote->socket, BC_SOCKET_TCP, remote->ip, remote->port);
    bc_socket_connect(&remote->socket);
    handshake(remote);
    return 0;
}

int bc_peer_disconnect(bc_peer *remote)
{
    bc_socket_destroy(&remote->socket);
    return 0;
}

void bc_peer_send(bc_peer *remote, bc_proto_msg *msg)
{
    serial_buffer buf;
    serial_buffer_init(&buf, 100);
    switch(msg->type) {
    case BC_PROTO_INVALID:
        printf("(peer) Invalid Message %d\n", msg->type);
        break;
    case BC_PROTO_PING:
        bc_proto_ping_serialize((bc_msg_ping *) msg, &buf);
        break;
    case BC_PROTO_PONG:
        bc_proto_pong_serialize((bc_msg_pong *) msg, &buf);
        break;
    case BC_PROTO_VERSION:
        bc_proto_version_serialize((bc_msg_version *) msg, &buf);
        break;
    case BC_PROTO_VERACK:  bc_proto_verack_serialize(&buf);  break;
    }
    bc_socket_send(&remote->socket, buf.data, buf.size);
    serial_buffer_destroy(&buf);
}

static int recv_serial_msg(bc_socket *socket, serial_buffer *out)
{
    // Check if esp32 has a PEEK flag for recv
    
    unsigned char raw_msg[2000] = {0};  // TODO This is hardcoded
    
    // Peek for a message header
    size_t peek_len = 0;
    peek_len = bc_socket_recv(socket, raw_msg, MESSAGE_HEADER_LEN,
                                    MSG_PEEK);
    if(peek_len == 24) {
        serial_buffer serial_response;
        serial_buffer_init_from_data(&serial_response, raw_msg,
                                        MESSAGE_HEADER_LEN);
        bc_proto_header header;
        bc_proto_deserialize_header(&serial_response, &header);
        
        // Peek for a full message
        size_t message_len = MESSAGE_HEADER_LEN + header.payload_len;
        peek_len = bc_socket_recv(socket, raw_msg,
                                  MESSAGE_HEADER_LEN+header.payload_len,
                                  MSG_PEEK);
        if(peek_len == message_len) {
            bc_socket_recv(socket, raw_msg,
                           MESSAGE_HEADER_LEN+header.payload_len, 0);
            serial_buffer_init_from_data(out, raw_msg,
                                         message_len);
            return message_len;
        }
    }
    
    return 0; // 0 bytes read
}

void bc_peer_recv(bc_peer *remote, bc_proto_msg **out)
{
    serial_buffer serial_msg;
    if(recv_serial_msg(&remote->socket, &serial_msg)) {
        bc_proto_header header;
        bc_proto_deserialize_header(&serial_msg, &header);
        if(strcmp(header.command, "ping") == 0) {
            *out = calloc(1, sizeof(bc_msg_ping));
            bc_msg_ping *ping = (bc_msg_ping *) *out;
            ping->type = BC_PROTO_PING;
            bc_proto_ping_deserialize(ping, &serial_msg);
        } else if(strcmp(header.command, "pong") == 0) {
            *out = calloc(1, sizeof(bc_msg_pong));
            bc_msg_pong *pong = (bc_msg_pong *) *out;
            pong->type = BC_PROTO_PONG;
            bc_proto_pong_deserialize(pong, &serial_msg);
        } else if(strcmp(header.command, "version") == 0) {
            *out = calloc(1, sizeof(bc_msg_version));
            bc_msg_version *version = (bc_msg_version *) *out;
            version->type = BC_PROTO_VERSION;
            bc_proto_version_deserialize(version, &serial_msg);
        } else if(strcmp(header.command, "verack") == 0) {
            *out = calloc(1, sizeof(bc_msg_verack));
            bc_msg_verack *verack = (bc_msg_verack *) *out;
            verack->type = BC_PROTO_VERACK;
        } else {
            printf("%s [TODO]\n", header.command);
        }
        serial_buffer_destroy(&serial_msg);
    }
}
