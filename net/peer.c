#include <stdio.h>
#include <time.h>
#include <string.h>

#include "peer.h"
#include "proto.h"
#include "../config.h"
#include "../crypto/crypto.h"

static void handle_msg_version(bc_peer *peer, bc_msg_version *msg)
{
    bc_proto_version_print(msg);
    bc_proto_msg verack = {
        .type = BC_PROTO_VERACK
    };
    bc_peer_send(peer, &verack);
    bc_proto_verack_print();
}

static void handle_msg_verack()
{
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
        bc_proto_recv(&peer->socket, &res);
        if(res) {
            switch(res->type) {
            case BC_PROTO_VERSION:
                handle_msg_version(peer, (bc_msg_version *) res);
                break;
            case BC_PROTO_VERACK:
                handle_msg_verack();
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
    case BC_PROTO_INVALID: printf("(peer) Invalid Message %d\n"); break;
    case BC_PROTO_VERSION:
        bc_proto_version_serialize((bc_msg_version *) msg, &buf);
        break;
    case BC_PROTO_VERACK:  bc_proto_verack_serialize(&buf);  break;
    }
    bc_socket_send(&remote->socket, buf.data, buf.size);
    serial_buffer_destroy(&buf);
}

int bc_peer_recv(bc_peer *remote, bc_proto_msg *msg)
{
    return 0;
}
