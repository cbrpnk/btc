#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "peer.h"
#include "proto.h"
#include "../config.h"
#include "../crypto/crypto.h"

static void handle_msg_inv(bc_msg_inv *msg)
{
    bc_msg_inv_print(msg);
}

static void handle_msg_ping(bc_peer *peer, bc_msg_ping *msg)
{
    bc_msg_ping_print(msg);
    bc_msg_pong *pong = bc_msg_pong_new();
    pong->nonce = msg->nonce;
    bc_peer_send(peer, (bc_msg *) pong);
    bc_msg_pong_print(pong);
    bc_msg_pong_destroy(pong);
}

static void handle_msg_pong(bc_msg_pong *msg)
{
    bc_msg_pong_print(msg);
}

static void handle_msg_verack()
{
    bc_msg_verack_print();
}

static void handle_msg_version(bc_peer *peer, bc_msg_version *msg)
{
    bc_msg_version_print(msg);
    bc_msg verack = {
        .type = BC_MSG_VERACK
    };
    bc_peer_send(peer, &verack);
    bc_msg_verack_print();
}


// TODO There should not be a handshake function. The peer should
// send a version message, then enter the non-blocking recv/process loop.
static void handshake(bc_peer *peer)
{
    bc_msg_version msg = {
        .type = BC_MSG_VERSION,
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
    bc_msg_version_print(&msg);
    bc_peer_send(peer, (bc_msg *) &msg);
    
    // Main loop
    // TODO Peer should only handle version verack ping pong
    // Everything else should be handeled by upper layer
    while(1) {
        bc_peer_recv(peer);
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

void bc_peer_send(bc_peer *remote, bc_msg *msg)
{
    serial_buffer buf;
    serial_buffer_init(&buf, 100);
    bc_msg_serialize(msg, &buf);
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
        serial_buffer_destroy(&serial_response);
    }
    
    return 0; // 0 bytes read
}

void bc_peer_recv(bc_peer *remote)
{
    serial_buffer serial_msg;
    if(recv_serial_msg(&remote->socket, &serial_msg)) {
        bc_msg *msg = bc_msg_new_from_buffer(&serial_msg);
        if(msg) {
            switch(msg->type) {
                case BC_MSG_INV:
                    handle_msg_inv((bc_msg_inv *) msg);
                    break;
                case BC_MSG_PING:
                    handle_msg_ping(remote, (bc_msg_ping *) msg);
                    break;
                case BC_MSG_PONG:
                    handle_msg_pong((bc_msg_pong *) msg);
                    break;
                case BC_MSG_VERACK:
                    handle_msg_verack((bc_msg_verack *) msg);
                    break;
                case BC_MSG_VERSION:
                    handle_msg_version(remote, (bc_msg_version *) msg);
                    break;
                default:
                    printf("Unknown message\n");
            }
            bc_msg_destroy(msg);
        }
        serial_buffer_destroy(&serial_msg);
    }
}
