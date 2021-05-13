#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include "peer.h"
#include "proto.h"
#include "../config.h"
#include "../crypto/crypto.h"


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
    bc_peer_send(peer, (bc_msg *) &msg);
}

int bc_peer_connect(bc_peer *peer)
{
    bc_socket_init(&peer->socket, BC_SOCKET_TCP, peer->ip, peer->port);
    bc_socket_connect(&peer->socket);
    handshake(peer);
    return 0;
}

int bc_peer_disconnect(bc_peer *remote)
{
    bc_socket_destroy(&remote->socket);
    return 0;
}

void bc_peer_send(bc_peer *remote, bc_msg *msg)
{
    #ifdef NET_DEBUG
        printf("[out] => ");
        bc_msg_print(msg);
    #endif
    serial_buffer buf;
    serial_buffer_init(&buf, 100);
    bc_msg_serialize(msg, &buf);
    bc_socket_send(&remote->socket, buf.data, buf.size);
    serial_buffer_destroy(&buf);
}

/////////////////////  Recv helper functiosn ////////////////////////////////

// Fill buf with exactly len bytes of the socket
static int recvn(bc_socket *socket, uint8_t *buf, size_t len)
{
    size_t recved_len = 0;
    while(recved_len < len) {
        recved_len += bc_socket_recv(socket, buf+recved_len, len-recved_len, 0);
    }
}

// Reads one full message
static int recv_msg(bc_socket *socket, serial_buffer *out)
{
    uint8_t *raw_msg = malloc(MESSAGE_HEADER_LEN);
    
    // Read header
    recvn(socket, raw_msg, MESSAGE_HEADER_LEN);
    serial_buffer serial_header;
    serial_buffer_init_from_data(&serial_header, raw_msg,
                                    MESSAGE_HEADER_LEN);
    bc_proto_header header;
    bc_proto_deserialize_header(&serial_header, &header);
    
    // Compute full message len
    size_t msg_len = MESSAGE_HEADER_LEN + header.payload_len;
    
    // Read payload
    raw_msg = realloc(raw_msg, msg_len);
    recvn(socket, raw_msg+MESSAGE_HEADER_LEN, header.payload_len);
    
    serial_buffer_init_from_data(out, raw_msg, msg_len);
    
    free(raw_msg);
    return msg_len;
}

static void handle_msg_ping(bc_peer *peer, bc_msg_ping *msg)
{
    bc_msg_pong *pong = bc_msg_pong_new();
    pong->nonce = msg->nonce;
    bc_peer_send(peer, (bc_msg *) pong);
    bc_msg_pong_destroy(pong);
}

static void handle_msg_verack(bc_peer *peer)
{
    bc_msg_sendcmpct *cmpct = bc_msg_sendcmpct_new();
    cmpct->is_compact = 0;
    cmpct->version = 2;
    bc_peer_send(peer, (bc_msg *) cmpct);
    bc_msg_sendcmpct_destroy(cmpct);
}

static void handle_msg_version(bc_peer *peer, bc_msg_version *msg)
{
    bc_msg verack = {
        .type = BC_MSG_VERACK
    };
    bc_peer_send(peer, &verack);
}

/////////////////////////////// recv ///////////////////////////////////

void bc_peer_recv(bc_peer *peer, bc_msg **msg) {
    serial_buffer serial_msg;
    serial_buffer_init(&serial_msg, 64);
    if(recv_msg(&peer->socket, &serial_msg)) {
        bc_msg *msg = bc_msg_new_from_buffer(&serial_msg);
        if(msg) {
            #ifdef NET_DEBUG
                printf("[in] <= ");
                bc_msg_print(msg);
            #endif
            switch(msg->type) {
                case BC_MSG_INV:
                    //handle_msg_inv((bc_msg_inv *) msg);
                    break;
                case BC_MSG_PING:
                    handle_msg_ping(peer, (bc_msg_ping *) msg);
                    break;
                case BC_MSG_PONG:
                    //handle_msg_pong((bc_msg_pong *) msg);
                    break;
                case BC_MSG_SENDCMPCT:
                    //handle_msg_sendcmpct((bc_msg_sendcmpct *) msg);
                    break;
                case BC_MSG_VERACK:
                    handle_msg_verack(peer);
                    break;
                case BC_MSG_VERSION:
                    handle_msg_version(peer, (bc_msg_version *) msg);
                    break;
                default:
                    printf("Unknown message\n");
            }
            bc_msg_destroy(msg);
        }
    }
    serial_buffer_destroy(&serial_msg);
}
