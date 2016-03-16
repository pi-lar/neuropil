/**
 *  copyright 2015 pi-lar GmbH
 *  original version was taken from chimera project (MIT licensed), but heavily modified
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_NETWORK_H_
#define _NP_NETWORK_H_

#include "sys/socket.h"
#include "netdb.h"

#include "event/ev.h"
#include "include.h"
#include "np_list.h"
#include "np_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

/** 
 ** NETWORK_PACK_SIZE is the maximum packet size that will be handled by neuropil network layer
 */
#define NETWORK_PACK_SIZE 65536

/** 
 ** TIMEOUT is the number of seconds to wait for receiving ack from the destination, if you want 
 ** the sender to wait forever put 0 for TIMEOUT. 
 */
#define TIMEOUT 1.0

enum socket_type {
	UNKNOWN_PROTO = 0x00,
	IPv4    = 0x01,
	IPv6    = 0x02,
	UDP     = 0x10, // UDP protocol - default
	TCP     = 0x20, // TCP protocol
	RAW     = 0x40, // pure IP protocol - no ports
	PASSIVE = 0x80  // TCP passive (like FTP passive) for nodes behind firewalls
};

typedef void* void_ptr;
NP_SLL_GENERATE_PROTOTYPES(void_ptr)

struct np_network_s
{
    int socket;
    ev_io watcher;

	uint8_t socket_type;
	struct addrinfo* addr_in; // where a node receives messages

    np_jtree_t* waiting;

    np_sll_t(void_ptr, in_events);
    np_sll_t(void_ptr, out_events);

    uint32_t seqend;

	pthread_attr_t attr;
    pthread_mutex_t lock;
};

typedef struct np_ackentry_s np_ackentry_t;

struct np_ackentry_s {
	np_bool acked;       // signal when all pakets have been acked
	double acktime;      // the time when the last packet is acked
	double transmittime; // this is the time the packet is transmitted (or retransmitted)
	double expiration;   // the time when the ackentry will expire and will be deleted
	np_key_t* dest_key; // the destination key / next/final hop of the message
	uint16_t expected_ack;
	uint16_t received_ack;
};

typedef struct np_prioq_s np_prioq_t;
struct np_prioq_s {

	np_key_t* dest_key; // the destination key / next/final hop of the message
	np_message_t* msg;  // message to send

	uint8_t max_retries; // max number of retries / subject specific
	uint8_t retry;     // number of retries
	uint32_t seqnum; // seqnum to identify the packet to be retransmitted
	double transmittime; // this is the time the packet is transmitted (or retransmitted)
};

// parse protocol string of the form "tcp4://..." and return the correct @see socket_type
uint8_t np_parse_protocol_string (const char* protocol_str);
char* np_get_protocol_string (uint8_t protocol);

/** network_address:
 ** returns the ip address of the #hostname#
 **/
void get_network_address (np_bool create_socket, struct addrinfo** ai, uint8_t type, char *hostname, char* service);
// struct addrinfo get_network_address (char *hostname);

np_ackentry_t* get_new_ackentry();
np_prioq_t* get_new_pqentry();

/** network_init:
 ** initiates the networking layer by creating socket and bind it to #port# 
 **/
np_network_t* network_init (np_bool create_socket, uint8_t type, char* hostname, char* service);

/**
 ** network_send: host, data, size
 ** Sends a message to host, updating the measurement info.
 ** type are 1 or 2, 1 indicates that the data should be acknowledged by the
 ** receiver, and 2 indicates that no ack is necessary.
 **/
void network_send (np_state_t* state, np_key_t* node,  np_message_t* msg);

void _np_network_sendrecv(struct ev_loop *loop, ev_io *event, int revents);
void _np_network_send(struct ev_loop *loop, ev_io *event, int revents);
void _np_network_read(struct ev_loop *loop, ev_io *event, int revents);
void _np_network_accept(struct ev_loop *loop, ev_io *event, int revents);

/**
 ** Resends a message to host
 **/
// int network_resend (np_state_t* state, np_node_t *host, np_message_t* message, size_t size, int ack, unsigned long seqnum, double *transtime);

#ifdef __cplusplus
}
#endif

#endif /* _CHIMERA_NETWORK_H_ */
