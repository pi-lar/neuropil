/*
** $Id: network.c,v 1.30 2007/04/04 00:04:49 krishnap Exp $
**
** Matthew Allen
** description: 
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netdb.h>
#include <pthread.h>
#include <assert.h>


#include "dtime.h"
#include "log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_jobqueue.h"
#include "np_jtree.h"
#include "np_key.h"
#include "np_message.h"
#include "np_network.h"
#include "np_node.h"
#include "np_threads.h"

#define SEND_SIZE NETWORK_PACK_SIZE

// allocate a new pointer and return it
np_prioq_t* get_new_pqentry()
{
	np_prioq_t* entry = (np_prioq_t *) malloc(sizeof(np_prioq_t));

	entry->dest_key = NULL;
	entry->msg = NULL;
	entry->retry = 0;
	entry->seqnum = 0;
	entry->transmittime = 0.0;

	return entry;
}

np_ackentry_t* get_new_ackentry()
{
	np_ackentry_t *entry = (np_ackentry_t *) malloc(sizeof(np_ackentry_t));
	entry->acked = FALSE;
	entry->acktime = 0.0;

	return entry;
}

static char* URN_TCP_V4 = "tcp4";
static char* URN_TCP_V6 = "tcp6";
static char* URN_PAS_V4 = "pas4";
static char* URN_PAS_V6 = "pas6";
static char* URN_UDP_V4 = "udp4";
static char* URN_UDP_V6 = "udp6";
static char* URN_IP_V4  = "ip4";
static char* URN_IP_V6  = "ip6";

uint8_t np_parse_protocol_string (const char* protocol_str) {

	if (0 == strncmp(protocol_str, URN_TCP_V4, 4)) return (TCP     | IPv4);
	if (0 == strncmp(protocol_str, URN_TCP_V6, 4)) return (TCP     | IPv6);
	if (0 == strncmp(protocol_str, URN_PAS_V4, 4)) return (PASSIVE | IPv4);
	if (0 == strncmp(protocol_str, URN_PAS_V6, 4)) return (PASSIVE | IPv6);
	if (0 == strncmp(protocol_str, URN_UDP_V4, 4)) return (UDP     | IPv4);
	if (0 == strncmp(protocol_str, URN_UDP_V6, 4)) return (UDP     | IPv6);
	if (0 == strncmp(protocol_str, URN_IP_V4, 3))  return (RAW     | IPv4);
	if (0 == strncmp(protocol_str, URN_IP_V6, 3))  return (RAW     | IPv6);

	return UNKNOWN_PROTO;
}

char* np_get_protocol_string (uint8_t protocol)
{
	if (protocol == (TCP     | IPv4)) return URN_TCP_V4;
	if (protocol == (TCP     | IPv6)) return URN_TCP_V6;
	if (protocol == (PASSIVE | IPv4)) return URN_PAS_V4;
	if (protocol == (PASSIVE | IPv6)) return URN_PAS_V6;
	if (protocol == (UDP     | IPv4)) return URN_UDP_V4;
	if (protocol == (UDP     | IPv6)) return URN_UDP_V6;
	if (protocol == (RAW     | IPv4)) return URN_IP_V4;
	if (protocol == (RAW     | IPv6)) return URN_IP_V6;

	return "UNKNOWN";
}

/** network_address:
 ** returns the addrinfo structure of the hostname / service
 **/
void get_network_address (np_bool create_socket, struct addrinfo** ai_head, uint8_t type, char *hostname, char* service)
{
	int err;
    // struct addrinfo *ai_head;
    struct addrinfo hints;

    if (TRUE == create_socket)
    	hints.ai_flags = AI_PASSIVE | AI_CANONNAME;
    else
    	hints.ai_flags = AI_CANONNAME;

	if (0 < (type & IPv4) ) {
		hints.ai_family = PF_INET;
	}
	if (0 < (type & IPv6) ) {
		hints.ai_family = PF_INET6;
	}
	if (0 < (type & UDP) ) {
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	}
	if (0 < (type & TCP) ) {
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
	}

	log_msg(LOG_DEBUG, "using getaddrinfo: %d:%s:%s", type, hostname, service);
	if ( 0 != ( err = getaddrinfo( hostname, service, &hints, ai_head ) ))
	{
		log_msg(LOG_ERROR, "error getaddrinfo: %s", gai_strerror( err ) );
	}

	struct addrinfo* ai;
	for ( ai = *ai_head; ai != NULL; ai = ai->ai_next )
	{
		log_msg( LOG_DEBUG,
				"found addrinfo ai_flags = 0x%02X"
				" ai_family = %d (PF_INET = %d, PF_INET6 = %d)"
				" ai_socktype  = %d (SOCK_STREAM = %d, SOCK_DGRAM = %d)"
				" ai_protocol  = %d (IPPROTO_TCP = %d, IPPROTO_UDP = %d)"
				" ai_addrlen   = %d (sockaddr_in = %d, sockaddr_in6 = %d)",
				ai->ai_flags,
				ai->ai_family,
				PF_INET,
				PF_INET6,
				ai->ai_socktype,
				SOCK_STREAM,
				SOCK_DGRAM,
				ai->ai_protocol,
				IPPROTO_TCP,
				IPPROTO_UDP,
				ai->ai_addrlen,
				sizeof( struct sockaddr_in ),
				sizeof( struct sockaddr_in6 ) );
		char hostname[255];
		char sericename[255];

		getnameinfo( ai->ai_addr,
                      ai->ai_addrlen,
					  hostname,
                      sizeof( hostname ),
					  sericename,
                      sizeof( sericename ),
                      NI_NUMERICHOST | NI_NUMERICSERV );
         switch ( ai->ai_family )
         {
            case PF_INET:   /* IPv4 address record. */
            {
                struct sockaddr_in *p = (struct sockaddr_in*) ai->ai_addr;
                log_msg(LOG_DEBUG,
                        "found nameinfo sin_family: %d"
            		    " (AF_INET = %d, AF_INET6 = %d)"
                        " sin_addr:     %s"
                        " sin_port:     %s",
                        p->sin_family,
                        AF_INET,
                        AF_INET6,
						hostname,
						sericename );
                break;
            }  /* End CASE of IPv4. */
            case PF_INET6:   /* IPv6 address record. */
            {
               struct sockaddr_in6 *p = (struct sockaddr_in6*) ai->ai_addr;
               log_msg(LOG_DEBUG,
                        "found nameinfo sin6_family: %d"
            		    " (AF_INET = %d, AF_INET6 = %d)"
                        " sin6_addr:     %s"
                        " sin6_port:     %s"
                        " sin6_flowinfo: %d"
                        " sin6_scope_id: %d",
                        p->sin6_family,
                        AF_INET,
                        AF_INET6,
						hostname,
						sericename,
                        p->sin6_flowinfo,
                        p->sin6_scope_id );
               break;
            }  /* End CASE of IPv6. */
            default:   /* Can never get here, but just for completeness. */
            {
               // freeaddrinfo( aiHead );
               // return -1;
            }  /* End DEFAULT case (unknown protocol family). */
         }  /* End SWITCH on protocol family. */
	}
//	int is_addr;
//    struct hostent *he;
//    unsigned long addr;
//    unsigned long local;
//    int i;
//
//    /* apparently gethostbyname does not portably recognize ip addys */
//#ifdef SunOS
//    is_addr = inet_addr (hostname);
//    if (is_addr == -1)
//	is_addr = 0;
//    else
//	{
//	    memcpy (&addr, (struct in_addr *) &is_addr, sizeof (addr));
//	    is_addr = inet_addr ("127.0.0.1");
//	    memcpy (&local, (struct in_addr *) &is_addr, sizeof (addr));
//	    is_addr = 1;
//	}
//#else
//    is_addr = inet_aton (hostname, (struct in_addr *) &addr);
//    inet_aton ("127.0.0.1", (struct in_addr *) &local);
//#endif
//
//    // pthread_mutex_lock (&(ng->lock));
//    if (is_addr) he = gethostbyaddr ((char *) &addr, sizeof (addr), AF_INET);
//    else         he = gethostbyname (hostname);
//
//    if (he == NULL)
//	{
//	    // pthread_mutex_unlock (&(ng->lock));
//	    return (0);
//	}
//    /* make sure the machine is not returning localhost */
//    addr = *(unsigned long *) he->h_addr_list[0];
//    for (i = 1; he->h_addr_list[i] != NULL && addr == local; i++)
//    	addr = *(unsigned long *) he->h_addr_list[i];
//    // pthread_mutex_unlock (&(ng->lock));
//
//    return (addr);
}


/**
 ** Resends a message to host
 **/
np_bool network_send_udp (np_state_t* state, np_key_t *node_key, np_message_t* msg)
{
	int ret;

	// get encryption details
	np_aaatoken_t* auth_token = node_key->authentication;

	if (NULL == auth_token || !auth_token->valid) {
		if (node_key->node->handshake_status < HANDSHAKE_INITIALIZED) {
			node_key->node->handshake_status = HANDSHAKE_INITIALIZED;
			log_msg(LOG_INFO, "requesting a new handshake with %s:%s (%s)",
					node_key->node->dns_name, node_key->node->port, key_get_as_string(node_key));
			np_msgproperty_t* msg_prop = np_message_get_handler(state, OUTBOUND, NP_MSG_HANDSHAKE);
			job_submit_msg_event(state->jobq, 0.0, msg_prop, node_key, NULL);
		}
		return FALSE;
	}

	// log_msg(LOG_DEBUG, "serializing and encrypting message ...");
	uint64_t max_buffer_len = NETWORK_PACK_SIZE - crypto_secretbox_MACBYTES - crypto_secretbox_NONCEBYTES;
	uint64_t send_buf_len;
	unsigned char send_buffer[max_buffer_len];
	void* send_buffer_ptr = send_buffer;

	np_message_serialize(msg, send_buffer_ptr, &send_buf_len);
	assert(send_buf_len <= max_buffer_len);

	log_msg(LOG_NETWORKDEBUG, "serialized message to %llu bytes", send_buf_len);

	// add protection from replay attacks ...
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, sizeof(nonce));

	uint64_t enc_msg_len = send_buf_len + crypto_secretbox_MACBYTES;
	unsigned char enc_msg[enc_msg_len];
	ret = crypto_secretbox_easy(enc_msg,
								(const unsigned char*) send_buffer,
								send_buf_len,
								nonce,
								auth_token->session_key);
	if (ret != 0)
	{
		log_msg(LOG_WARN,
				"incorrect encryption of message (not sending to %s:%hd)",
				node_key->node->dns_name, node_key->node->port);
		return FALSE;
	}

	uint64_t enc_buffer_len = enc_msg_len + crypto_secretbox_NONCEBYTES;
	char enc_buffer[enc_buffer_len];
	memcpy(enc_buffer, nonce, crypto_secretbox_NONCEBYTES);
	memcpy(enc_buffer + crypto_secretbox_NONCEBYTES, enc_msg, enc_msg_len);

	/* send data */
	pthread_mutex_lock(&(state->my_node_key->node->network->lock));
	// struct sockaddr* to = node_key->node->network->addr_in->ai_addr;
	// socklen_t to_size = node_key->node->network->addr_in->ai_addrlen;

	log_msg(LOG_NETWORKDEBUG, "sending message (%llu bytes) to %s:%s", enc_buffer_len, node_key->node->dns_name, node_key->node->port);
	// ret = sendto (state->my_node_key->node->network->socket, enc_buffer, enc_buffer_len, 0, to, to_size);
	ret = send (node_key->node->network->socket, enc_buffer, enc_buffer_len, 0);

	pthread_mutex_unlock(&(state->my_node_key->node->network->lock));

	if (ret < 0) {
		log_msg (LOG_ERROR, "send message error: %s", strerror (errno));
		return FALSE;
	} else {
		// log_msg (LOG_NETWORKDEBUG, "sent message");
	}
	return TRUE;
}

/** network_init:
 ** initiates the networking layer structures required for a node
 ** if the port number is bigger than zero, it will create a socket and bind it to #port#
 ** the type defines the protocol which is used by the node (@see socket_type)
 **/
np_network_t* network_init (np_bool create_socket, uint8_t type, char* hostname, char* service)
{
    int ret;
    int one = 1;
    int v6_only = 0;

    np_network_t* ng = (np_network_t *) malloc (sizeof (np_network_t));
    ng->addr_in = NULL;
    ng->addr_out = NULL;

    if ((ret = pthread_mutex_init (&(ng->lock), NULL)) != 0)
	{
		log_msg(LOG_ERROR, "pthread_mutex_init: %s:", strerror (ret));
		close (ng->socket);
		return (NULL);
	}

    get_network_address (create_socket, &ng->addr_in, type, hostname, service);

    if (NULL != ng->addr_in) {
    	log_msg(LOG_DEBUG, "canonical name: %s", ng->addr_in->ai_canonname);
    	// create socket
    	// not using a socket for sending messages to a different node leads to unreliable
    	// delivery. The sending socket changes too often to be useful for finding the correct
    	// decryption shared secret. Especially true for ipv6 ...
    	ng->socket = socket (ng->addr_in->ai_family, ng->addr_in->ai_socktype, ng->addr_in->ai_protocol);
    	if (0 > ng->socket)
    	{
    		log_msg(LOG_ERROR, "socket: %s", strerror (errno));
    		return NULL;
    	}

		// check if we have to bind the local a socket
		if (TRUE == create_socket && NULL != ng->addr_in)
		{
			// create own retransmit structures
			ng->waiting = make_jtree();
			ng->retransmit = make_jtree();
			ng->seqend = 0LU;

			if (-1 == setsockopt (ng->socket, SOL_SOCKET, SO_REUSEADDR, (void *) &one, sizeof (one)))
			{
				log_msg(LOG_ERROR, "setsockopt (SO_REUSEADDR): %s: ", strerror (errno));
				close (ng->socket);
				return NULL;
			}
			if (-1 == setsockopt( ng->socket, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof( v6_only) ) )
			{
				// enable ipv4 mapping
				log_msg(LOG_WARN, "setsockopt (IPV6_V6ONLY): %s: ", strerror (errno));
			}

			/* attach socket to #port#. */
			if (0 > bind (ng->socket, ng->addr_in->ai_addr, ng->addr_in->ai_addrlen))
			{
				log_msg(LOG_ERROR, "bind: %s:", strerror (errno));
				close (ng->socket);
				return NULL;
			}

			log_msg(LOG_DEBUG, "created local listening socket");

		} else {
			if (0 > connect(ng->socket, ng->addr_in->ai_addr, ng->addr_in->ai_addrlen))
			{
				log_msg(LOG_ERROR, "connect: %s:", strerror (errno));
				close (ng->socket);
				return NULL;
			}
		}
    }
	return ng;
}

