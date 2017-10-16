//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#ifndef _NP_NETWORK_H_
#define _NP_NETWORK_H_

#include "sys/socket.h"
#include "netdb.h"

#include "event/ev.h"

#include "np_list.h"
#include "np_util.h"
#include "np_memory.h"
#include "np_keycache.h"
#include "np_message.h"
#include "np_types.h"

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
	UNKNOWN_PROTO = 0x00,
	IPv4    	  = 0x01,
	IPv6    	  = 0x02,
	UDP     	  = 0x10, // UDP protocol - default
	TCP     	  = 0x20, // TCP protocol
	RAW     	  = 0x40, // pure IP protocol - no ports
	PASSIVE 	  = 0x80  // TCP passive (like FTP passive) for nodes behind firewalls
} NP_ENUM;

struct np_network_s
{
	np_obj_t* obj;

	np_bool initialized;
	int socket;
	ev_io watcher;

	uint8_t socket_type;
	struct addrinfo* addr_in; // where a node receives messages

	np_tree_t* waiting;

	np_sll_t(void_ptr, in_events);
	np_sll_t(void_ptr, out_events);

	uint32_t seqend;

	char * ip;
	char * port;
	np_mutex_t lock;
} NP_API_INTERN;

_NP_GENERATE_MEMORY_PROTOTYPES(np_network_t);

typedef struct np_prioq_s np_prioq_t;
struct np_prioq_s {

	np_key_t* dest_key; // the destination key / next/final hop of the message
	np_message_t* msg;  // message to send

	uint8_t max_retries; // max number of retries / subject specific
	uint8_t retry;     // number of retries
	uint32_t seqnum; // seqnum to identify the packet to be retransmitted
	double send_at; // this is the time the packet is transmitted (or retransmitted)
} NP_API_INTERN;

// parse protocol string of the form "tcp4://..." and return the correct @see socket_type
NP_API_INTERN
uint8_t _np_network_parse_protocol_string (const char* protocol_str);

NP_API_INTERN
char* _np_network_get_protocol_string (uint8_t protocol);

/** network_address:
 ** returns the ip address of the #hostname#
 **
 **/
NP_API_INTERN
void _np_network_get_address (np_bool create_socket, struct addrinfo** ai, uint8_t type, char *hostname, char* service);
// struct addrinfo _np_network_get_address (char *hostname);

NP_API_INTERN
np_prioq_t* _np_network_get_new_pqentry();
NP_API_INTERN
void _np_network_stop(np_network_t* ng);
NP_API_INTERN
void _np_network_start(np_network_t* ng);
NP_API_INTERN
void _np_network_remap_network( np_key_t* new_target, np_key_t* old_target);

/** _np_network_init:
 ** initiates the networking layer by creating socket and bind it to #port#
 **
 **/
NP_API_INTERN
np_bool _np_network_init (np_network_t* network, np_bool create_socket, uint8_t type, char* hostname, char* service);

NP_API_INTERN
void _network_destroy (np_network_t* network);

/**
 ** _np_network_send_msg: host, data, size
 ** Sends a message to host, updating the measurement info.
 ** type are 1 or 2, 1 indicates that the data should be acknowledged by the
 ** receiver, and 2 indicates that no ack is necessary.
 **
 **/
NP_API_INTERN
void _np_network_send_msg (np_key_t* node,  np_message_t* msg);

/*
 * libev driven functions to send/receive messages over the wire
 */
NP_API_INTERN
void _np_network_sendrecv(struct ev_loop *loop, ev_io *event, int revents);
NP_API_INTERN
void _np_network_send_from_events(struct ev_loop *loop, ev_io *event, int revents);
NP_API_INTERN
void _np_network_read(struct ev_loop *loop, ev_io *event, int revents);
NP_API_INTERN
void _np_network_accept(struct ev_loop *loop, ev_io *event, int revents);
NP_API_INTERN
char* np_network_get_ip(np_key_t * container);
NP_API_INTERN
char* np_network_get_port(np_key_t * container);
NP_API_INTERN
np_bool _np_network_send_handshake(np_key_t* node_key);
#ifdef __cplusplus
}
#endif

#endif /* _CHIMERA_NETWORK_H_ */
