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

#include "proton/message.h"

#include "network.h"

#include "node.h"
#include "jrb.h"
#include "log.h"
#include "message.h"
#include "dtime.h"
#include "key.h"

extern int errno;
#define SEND_SIZE NETWORK_PACK_SIZE

// allocate a new pointer and return it
PQEntry* get_new_pqentry()
{
	PQEntry* entry = (PQEntry *) malloc(sizeof(PQEntry));
	entry->desthost = NULL;
	entry->data = NULL;
	entry->datasize = 0;
	entry->retry = 0;
	entry->seqnum = 0;
	entry->transmittime = 0.0;

	return entry;
}

np_ackentry_t* get_new_ackentry()
{
	np_ackentry_t *entry = (np_ackentry_t *) malloc(sizeof(np_ackentry_t));
	entry->acked = 0;
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
int network_resend (np_networkglobal_t* ng, np_node_t *node, pn_message_t* message, size_t size, int ack, unsigned long seqnum, double *transtime)
{
	struct sockaddr_in to;
	int ret, retval;
	char s[NETWORK_PACK_SIZE];
	double start;

	memset (&to, 0, sizeof (to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = node->address;
	to.sin_port = htons ((short) node->port);

	int err = pn_message_encode(message, s, &size);
	assert(err != PN_OVERFLOW);
	assert(pn_message_errno(message) == 0);
	assert(size<NETWORK_PACK_SIZE);

	/* send data */
	pthread_mutex_lock(&(ng->lock));
	log_msg(LOG_NETWORKDEBUG, "resending message seq=%d ack=%d to %s:%d",
			 seqnum, ack, node->dns_name, node->port);
	ret = sendto (ng->sock, s, size, 0, (struct sockaddr *) &to, sizeof (to));
	pthread_mutex_unlock(&(ng->lock));

	if (ret < 0)
	{
		log_msg (LOG_ERROR, "send message error: %s", strerror (errno));
		// np_node_update_stat (node, 0);
		return 0;

	} else {
		log_msg (LOG_NETWORKDEBUG, "sent message");
		*transtime = dtime();
		// np_node_update_stat (node, 1);
	}
	return 1;
}

/** network_init:
 ** initiates the networking layer by creating socket and bind it to #port#
 **/
np_networkglobal_t* network_init (int port)
{
    int sd;
    int ret;
    struct sockaddr_in saddr;
    int one;
    pthread_t tid;

    np_networkglobal_t* ng = (np_networkglobal_t *) malloc (sizeof (np_networkglobal_t));

    /* create socket */
    sd = socket (AF_INET, SOCK_DGRAM, 0);
    if (sd < 0)
	{
	    log_msg(LOG_ERROR, "socket: %s", strerror (errno));
	    return (NULL);
	}
    if (setsockopt (sd, SOL_SOCKET, SO_REUSEADDR, (void *) &one, sizeof (one)) == -1)
	{
	    log_msg(LOG_ERROR, "setsockopt: %s: ", strerror (errno));
	    close (sd);
	    return (NULL);
	}

    /* attach socket to #port#. */
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl (INADDR_ANY);
    saddr.sin_port = htons ((short) port);

    if (bind (sd, (struct sockaddr *) &saddr, sizeof (saddr)) < 0)
	{
	    log_msg(LOG_ERROR, "bind: %s:", strerror (errno));
	    close (sd);
	    return (NULL);
	}

    if ((ret = pthread_mutex_init (&(ng->lock), NULL)) != 0)
	{
	    log_msg(LOG_ERROR,
	    		"pthread_mutex_init: %s:", strerror (ret));
	    close (sd);
	    return (NULL);
	}

    ng->sock = sd;
    ng->waiting = make_jrb();
    ng->seqstart = 0LU;
    ng->seqend = 0LU;
	ng->retransmit = make_jrb();

	return ng;
}

