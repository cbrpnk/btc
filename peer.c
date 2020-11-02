#include <stdio.h>
#include <time.h>

#include "peer.h"
#include "config.h"
#include "net/proto.h"
#include "crypto/crypto.h"
#include "debug.h"

static void handshake(bc_peer *peer)
{
    bc_msg_version msg = {
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
        .user_agent = BC_USER_AGENT,
        .start_height = 0,
        .relay = 1
    };
    
    bc_proto_version_print(&msg);
    bc_proto_version_send(&peer->socket, &msg);
    
    printf("RECV-------------------------------------------\n");
    unsigned char message_buffer[2000] = {0};
    // TODO Custom recv that gets a full message
    int len = bc_socket_recv(&peer->socket, message_buffer, 2000);
    dump_hex(message_buffer, len);
    printf("END-------------------------------------------\n");
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

