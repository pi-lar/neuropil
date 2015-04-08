/**
 ** $Id: network.h,v 1.14 2007/04/04 00:04:49 krishnap Exp $
 ** Matthew Allen
 ** description:
 **/
#ifndef _NP_NETWORK_H_
#define _NP_NETWORK_H_

#include "proton/message.h"

#include "include.h"

/** 
 ** NETWORK_PACK_SIZE is the maximum packet size that will be handled by chimera network layer
 */
#define NETWORK_PACK_SIZE 65536

/** 
 ** TIMEOUT is the number of seconds to wait for receiving ack from the destination, if you want 
 ** the sender to wait forever put 0 for TIMEOUT. 
 */
#define TIMEOUT 1.0

struct np_networkglobal_t
{
    int sock;

    np_jrb_t *waiting;
    np_jrb_t *retransmit;

	unsigned long seqstart, seqend;

	pthread_attr_t attr;
    pthread_mutex_t lock;

};

typedef struct np_ackentry_t {
	int acked;
	double acktime; // the time when the packet is acked
} np_ackentry_t;

typedef struct PriQueueEntry {
	np_node_t *desthost; // who should this message be sent to?
	pn_message_t *data; // what to send?
	int datasize; // how big is it?
	int retry; // number of retries
	unsigned long seqnum; // seqnum to identify the packet to be retransmitted
	double transmittime; // this is the time the packet is transmitted (or retransmitted)
} PQEntry;


/** network_address:
 ** returns the ip address of the #hostname#
 */
unsigned long get_network_address (char *hostname);

np_ackentry_t* get_new_ackentry();
PQEntry* get_new_pqentry();

/** network_init:
 ** initiates the networking layer by creating socket and bind it to #port# 
 */
np_networkglobal_t* network_init (int port);

/**
 ** network_send: host, data, size
 ** Sends a message to host, updating the measurement info.
 ** type are 1 or 2, 1 indicates that the data should be acknowledged by the
 ** receiver, and 2 indicates that no ack is necessary.
 */
int network_send (np_networkglobal_t* state, np_node_t* node, pn_message_t* message, unsigned long ack);

/**
 ** Resends a message to host
 */
int network_resend (np_networkglobal_t* ng, np_node_t *host, pn_message_t* message, size_t size, int ack, unsigned long seqnum, double *transtime);

#endif /* _CHIMERA_NETWORK_H_ */
