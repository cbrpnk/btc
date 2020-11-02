#include <stdio.h>
#include <time.h>

#include "proto.h"
#include "node.h"
#include "crypto.h"
#include "debug.h"

int bc_node_connect(bc_node *remote)
{
    bc_socket_init(&remote->socket, BC_SOCKET_TCP);
    bc_socket_connect(&remote->socket, remote->ip, remote->port);
    return 0;
}

int bc_node_disconnect(bc_node *remote)
{
    bc_socket_disconnect(&remote->socket);
    return 0;
}

void bc_node_handshake(bc_node *node)
{
    bc_msg_version msg = {
        .version = node->protocol_version,
        .services = 1,
        .timestamp = (uint64_t) time(NULL),
        .dest = {
            .time = 0,
            .services = 1,
            .ip = (uint64_t) node->ip,
            .port = node->port
        },
        .src = {
            .time = 0,
            .services = 1,
            .ip = 0,
            .port = 0
        },
        .nonce = gen_nonce_64(),
        .user_agent = "/test:0.0.1/",
        .start_height = 0,
        .relay = 1
    };
    
    bc_proto_send_version(&node->socket, &msg);
    
    printf("RECV-------------------------------------------\n");
    unsigned char message_buffer[2000] = {0};
    // TODO Custom recv that gets a full message
    int len = bc_socket_recv(&node->socket, message_buffer, 2000);
    dump_hex(message_buffer, len);
    printf("END-------------------------------------------\n");
}
