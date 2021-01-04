//
// neuropil is copyright 2016-2021 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#ifndef _NP_NETWORK_H_
#define _NP_NETWORK_H_

#include "sys/socket.h"
#include "netdb.h"
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>


#include "event/ev.h"

#include "util/np_list.h"
#include "np_util.h"
#include "np_memory.h"

#include "np_types.h"
#include "np_constants.h"
#include "np_settings.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 ** NETWORK_PACK_SIZE is the maximum packet size that will be handled by neuropil network layer
 **
 */
#define NETWORK_PACK_SIZE 65536

/**
 ** TIMEOUT is the number of seconds to wait for receiving ack from the destination, if you want
 ** the sender to wait forever put 0 for TIMEOUT.
 **
 */
#define TIMEOUT 1.0


enum socket_type {
    UNKNOWN_PROTO  = 0x001,
    IPv4           = 0x002,
    IPv6           = 0x004,
    UDP            = 0x010, // UDP protocol - default
    TCP            = 0x020, // TCP protocol
    // RAW         = 0x040, // pure IP protocol - no ports
    PASSIVE        = 0x100,
    MASK_PROTOCOLL = 0x0FF,
    MASK_OPTION    = 0xF00,
} NP_ENUM;

typedef enum np_network_type_e {
    np_network_type_none	= 0x00,
    np_network_type_server	= 0x01,
    np_network_type_client	= 0x02,
} np_network_type_e;

struct np_network_s
{
    bool initialized;
    int socket;
    ev_io watcher_in;
    ev_io watcher_out;
    bool is_running;
    np_network_type_e type;

    enum socket_type socket_type;

    struct addrinfo* addr_in; // where a node receives messages

    struct sockaddr* remote_addr;
    socklen_t remote_addr_len;

    double last_send_date;
    double last_received_date;
    np_sll_t(void_ptr, out_events);

    uint32_t seqend;

    char ip[CHAR_LENGTH_IP];
    char port[CHAR_LENGTH_PORT];

    np_mutex_t access_lock;
    TSP(bool, can_be_enabled);

} NP_API_INTERN;

_NP_GENERATE_MEMORY_PROTOTYPES(np_network_t);
 
// parse protocol string of the form "tcp4://..." and return the correct @see socket_type
NP_API_INTERN
enum socket_type _np_network_parse_protocol_string (const char* protocol_str);

NP_API_INTERN
char* _np_network_get_protocol_string (np_state_t* context, enum socket_type protocol);

/** network_address:
 ** returns the ip address of the #hostname#
 **
 **/
NP_API_INTERN
bool _np_network_get_address (np_state_t* context, bool create_socket, struct addrinfo** ai, enum socket_type type, char *hostname, char* service);
// struct addrinfo _np_network_get_address (char *hostname);

NP_API_INTERN
void _np_network_stop(np_network_t* ng, bool force);
NP_API_INTERN
void _np_network_start(np_network_t* ng, bool force);

/** _np_network_init:
 ** initiates the networking layer by creating socket and bind it to #port#
 **
 **/
NP_API_INTERN
bool _np_network_init (np_network_t* network, bool create_socket, enum socket_type type, char* hostname, char* service, int prepared_socket_fd, enum socket_type passive_socket_type);

/**
 ** _np_network_append_msg_to_out_queue:
 ** Sends a message to host
 **
 **/
NP_API_INTERN
void _np_network_write(struct ev_loop *loop, ev_io *event, int revents);
NP_API_INTERN
void _np_network_read(struct ev_loop *loop, ev_io *event, int revents);
NP_API_INTERN
void _np_network_accept(struct ev_loop *loop, ev_io *event, int revents);
NP_API_INTERN
void _np_network_disable(np_network_t* self);
NP_API_INTERN
void _np_network_enable(np_network_t* self);
NP_API_INTERN
void _np_network_set_key(np_network_t* self, np_dhkey_t key);

#ifdef __cplusplus
}
#endif

#endif /* _CHIMERA_NETWORK_H_ */
