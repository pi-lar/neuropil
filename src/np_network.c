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

/** network_address:
 ** returns the ip address of the #hostname#
 */
unsigned long get_network_address (char *hostname)
{
    int is_addr;
    struct hostent *he;
    unsigned long addr;
    unsigned long local;
    int i;

    /* apparently gethostbyname does not portably recognize ip addys */
#ifdef SunOS
    is_addr = inet_addr (hostname);
    if (is_addr == -1)
	is_addr = 0;
    else
	{
	    memcpy (&addr, (struct in_addr *) &is_addr, sizeof (addr));
	    is_addr = inet_addr ("127.0.0.1");
	    memcpy (&local, (struct in_addr *) &is_addr, sizeof (addr));
	    is_addr = 1;
	}
#else
    is_addr = inet_aton (hostname, (struct in_addr *) &addr);
    inet_aton ("127.0.0.1", (struct in_addr *) &local);
#endif

    // pthread_mutex_lock (&(ng->lock));
    if (is_addr) he = gethostbyaddr ((char *) &addr, sizeof (addr), AF_INET);
    else         he = gethostbyname (hostname);

    if (he == NULL)
	{
	    // pthread_mutex_unlock (&(ng->lock));
	    return (0);
	}
    /* make sure the machine is not returning localhost */
    addr = *(unsigned long *) he->h_addr_list[0];
    for (i = 1; he->h_addr_list[i] != NULL && addr == local; i++)
    	addr = *(unsigned long *) he->h_addr_list[i];
    // pthread_mutex_unlock (&(ng->lock));

    return (addr);
}


/**
 ** Resends a message to host
 **/
np_bool network_send_udp (np_state_t* state, np_key_t *node_key, np_message_t* msg)
{
	struct sockaddr_in to;
	int ret;

	// get encryption details
	np_aaatoken_t* auth_token = node_key->authentication;

	if (NULL == auth_token || !auth_token->valid) {
		if (node_key->node->handshake_status < HANDSHAKE_INITIALIZED) {
			node_key->node->handshake_status = HANDSHAKE_INITIALIZED;
			log_msg(LOG_INFO, "requesting a new handshake with %s:%i (%s)",
					node_key->node->dns_name, node_key->node->port, key_get_as_string(node_key));
			np_msgproperty_t* msg_prop = np_message_get_handler(state, OUTBOUND, NP_MSG_HANDSHAKE);
			job_submit_msg_event(state->jobq, msg_prop, node_key, NULL);
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
	pthread_mutex_lock(&(state->my_key->node->network->lock));

	memset (&to, 0, sizeof (to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = node_key->node->address;
	to.sin_port = htons ((short) node_key->node->port);

	log_msg(LOG_NETWORKDEBUG, "sending message (%llu bytes) to %s:%hd", enc_buffer_len, node_key->node->dns_name, node_key->node->port);
	ret = sendto (state->my_key->node->network->socket, enc_buffer, enc_buffer_len, 0, (struct sockaddr *) &to, sizeof (to));

	pthread_mutex_unlock(&(state->my_key->node->network->lock));

	if (ret < 0) {
		log_msg (LOG_ERROR, "send message error: %s", strerror (errno));
		return FALSE;
	} else {
		// log_msg (LOG_NETWORKDEBUG, "sent message");
	}
	return TRUE;
}

/** network_init:
 ** initiates the networking layer by creating socket and bind it to #port#
 **/
np_network_t* network_init (uint16_t port)
{
    int ret;
    struct sockaddr_in saddr;
    int one;

    np_network_t* ng = (np_network_t *) malloc (sizeof (np_network_t));

    /* create socket */
    /* TODO: distinguish between raw, udp and tcp */
    ng->socket = socket (AF_INET, SOCK_DGRAM, 0);
    if (ng->socket < 0)
	{
	    log_msg(LOG_ERROR, "socket: %s", strerror (errno));
	    return (NULL);
	}
    if (setsockopt (ng->socket, SOL_SOCKET, SO_REUSEADDR, (void *) &one, sizeof (one)) == -1)
	{
	    log_msg(LOG_ERROR, "setsockopt: %s: ", strerror (errno));
	    close (ng->socket);
	    return (NULL);
	}

    /* attach socket to #port#. */
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl (INADDR_ANY);
    saddr.sin_port = htons (port);

    if (bind (ng->socket, (struct sockaddr *) &saddr, sizeof (saddr)) < 0)
	{
	    log_msg(LOG_ERROR, "bind: %s:", strerror (errno));
	    close (ng->socket);
	    return (NULL);
	}

    if ((ret = pthread_mutex_init (&(ng->lock), NULL)) != 0)
	{
	    log_msg(LOG_ERROR,
	    		"pthread_mutex_init: %s:", strerror (ret));
	    close (ng->socket);
	    return (NULL);
	}

    ng->seqend = 0LU;

    ng->waiting = make_jtree();
	ng->retransmit = make_jtree();

	return ng;
}

