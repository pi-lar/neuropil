//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netdb.h>
#include <pthread.h>
#include <assert.h>
#include <event/ev.h>

#include "np_network.h"

#include "dtime.h"
#include "np_log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_dhkey.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_message.h"
#include "np_memory.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_event.h"

// double definition in np_message.c !
static const int MSG_CHUNK_SIZE_1024 = 1024;
static const int MSG_ENCRYPTION_BYTES_40 = 40;

NP_SLL_GENERATE_IMPLEMENTATION(void_ptr);


// allocate a new pointer and return it
np_prioq_t* _np_network_get_new_pqentry()
{
    log_msg(LOG_TRACE | LOG_NETWORK, "start: np_prioq_t* _np_network_get_new_pqentry(){");
	np_prioq_t* entry = (np_prioq_t *) malloc(sizeof(np_prioq_t));
	CHECK_MALLOC(entry);

	entry->dest_key = NULL;
	entry->msg = NULL;
	entry->retry = 0;
	entry->seqnum = 0;
	entry->transmittime = 0.0;

	return (entry);
}

np_ackentry_t* _np_network_get_new_ackentry()
{
    log_msg(LOG_TRACE | LOG_NETWORK, "start: np_ackentry_t* _np_network_get_new_ackentry(){");
	np_ackentry_t *entry = (np_ackentry_t *) malloc(sizeof(np_ackentry_t));
	CHECK_MALLOC(entry);

	entry->acked = FALSE;
	entry->acktime = 0.0;
	entry->transmittime = 0.0;

	entry->expected_ack = 0;
	entry->received_ack = 0;

	return (entry);
}

static char* URN_TCP_V4 = "tcp4";
static char* URN_TCP_V6 = "tcp6";
static char* URN_PAS_V4 = "pas4";
static char* URN_PAS_V6 = "pas6";
static char* URN_UDP_V4 = "udp4";
static char* URN_UDP_V6 = "udp6";
static char* URN_IP_V4  = "ip4";
static char* URN_IP_V6  = "ip6";

uint8_t _np_network_parse_protocol_string (const char* protocol_str)
{
	if (0 == strncmp(protocol_str, URN_TCP_V4, 4)) return (TCP     | IPv4);
	if (0 == strncmp(protocol_str, URN_TCP_V6, 4)) return (TCP     | IPv6);
	if (0 == strncmp(protocol_str, URN_PAS_V4, 4)) return (PASSIVE | IPv4);
	if (0 == strncmp(protocol_str, URN_PAS_V6, 4)) return (PASSIVE | IPv6);
	if (0 == strncmp(protocol_str, URN_UDP_V4, 4)) return (UDP     | IPv4);
	if (0 == strncmp(protocol_str, URN_UDP_V6, 4)) return (UDP     | IPv6);
	if (0 == strncmp(protocol_str, URN_IP_V4, 3))  return (RAW     | IPv4);
	if (0 == strncmp(protocol_str, URN_IP_V6, 3))  return (RAW     | IPv6);

	return (UNKNOWN_PROTO);
}

char* _np_network_get_protocol_string (uint8_t protocol)
{
	if (protocol == (TCP     | IPv4)) return (URN_TCP_V4);
	if (protocol == (TCP     | IPv6)) return (URN_TCP_V6);
	if (protocol == (PASSIVE | IPv4)) return (URN_PAS_V4);
	if (protocol == (PASSIVE | IPv6)) return (URN_PAS_V6);
	if (protocol == (UDP     | IPv4)) return (URN_UDP_V4);
	if (protocol == (UDP     | IPv6)) return (URN_UDP_V6);
	if (protocol == (RAW     | IPv4)) return (URN_IP_V4);
	if (protocol == (RAW     | IPv6)) return (URN_IP_V6);

	return ("UNKNOWN");
}

/** network_address:
 ** returns the addrinfo structure of the hostname / service
 **/
void _np_network_get_address (
		np_bool create_socket,
		struct addrinfo** ai_head,
		uint8_t type,
		char *hostname,
		char* service)
{
	int err;
    // struct addrinfo *ai_head;
    struct addrinfo hints;

    if (TRUE == create_socket)
    	hints.ai_flags = AI_PASSIVE | AI_CANONNAME | AI_NUMERICSERV;
    else
    	hints.ai_flags = AI_CANONNAME | AI_NUMERICSERV;

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

	log_debug_msg(LOG_NETWORK | LOG_DEBUG, "using getaddrinfo: %d:%s:%s", type, hostname, service);
	if ( 0 != ( err = getaddrinfo( hostname, service, &hints, ai_head ) ))
	{
		log_msg(LOG_ERROR, "hostname: %s, servicename %s, protocol %d",
				hostname, service, type);
		log_msg(LOG_ERROR, "error getaddrinfo: %s", gai_strerror( err ) );
		return;
	}
/*
	struct addrinfo* ai;
	for ( ai = *ai_head; ai != NULL; ai = ai->ai_next )
	{
		log_msg( LOG_NETWORK | LOG_DEBUG,
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
		char hostname[NI_MAXHOST];
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
            case PF_INET:   // IPv4 address record.
            {
                struct sockaddr_in *p = (struct sockaddr_in*) ai->ai_addr;
                log_debug_msg(LOG_NETWORK | LOG_DEBUG,
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
            }  // End CASE of IPv4.
            case PF_INET6:   // IPv6 address record.
            {
               struct sockaddr_in6 *p = (struct sockaddr_in6*) ai->ai_addr;
               log_debug_msg(LOG_NETWORK | LOG_DEBUG,
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
            }  // End CASE of IPv6.
            default:   // Can never get here, but just for completeness.
            {
               // freeaddrinfo( aiHead );
               // return -1;
            }  // End DEFAULT case (unknown protocol family).
         }  // End SWITCH on protocol family.
	}
*/
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
void _np_network_send_msg (np_key_t *node_key, np_message_t* msg)
{
	int ret;

	// get encryption details
	np_aaatoken_t* auth_token = node_key->aaa_token;

	// if (NULL == auth_token ||
	//  	IS_INVALID(auth_token->state))
	// {
	if (node_key->node->handshake_status < HANDSHAKE_COMPLETE)
	{
		log_msg(LOG_NETWORK | LOG_INFO, "requesting a new handshake with %s:%s (%s)",
				node_key->node->dns_name, node_key->node->port, _np_key_as_str(node_key));

		node_key->node->handshake_status = HANDSHAKE_INITIALIZED;
		np_msgproperty_t* msg_prop = np_msgproperty_get(OUTBOUND, _NP_MSG_HANDSHAKE);
		_np_job_submit_transform_event(0.0, msg_prop, node_key, NULL);
		return;
	}
/*
		for  (int count = 0; 3 > count; count++)
		{
			_np_job_yield(0.031415);
			if (node_key->node->handshake_status > HANDSHAKE_INITIALIZED)
			{
				break;
			}
		}
		if (node_key->node->handshake_status <= HANDSHAKE_INITIALIZED)
		{
			return;
		}
*/
	// }

	// log_msg(LOG_NETWORKDEBUG, "serialized message to %llu bytes", send_buf_len);
	uint16_t i = 0;

	pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
	do
	{
		unsigned char* enc_buffer = malloc(MSG_CHUNK_SIZE_1024);
		CHECK_MALLOC(enc_buffer);

		// add protection from replay attacks ...
		unsigned char nonce[crypto_secretbox_NONCEBYTES];
		// TODO: move nonce to np_node_t and re-use it with increments
		randombytes_buf(nonce, sizeof(nonce));

		// char nonce_hex[crypto_secretbox_NONCEBYTES*2+1];
		// sodium_bin2hex(nonce_hex, crypto_secretbox_NONCEBYTES*2+1, nonce, crypto_secretbox_NONCEBYTES);
		// log_debug_msg(LOG_DEBUG, "encryption nonce %s", nonce_hex);

		// char session_hex[crypto_scalarmult_SCALARBYTES*2+1];
		// sodium_bin2hex(session_hex, crypto_scalarmult_SCALARBYTES*2+1, auth_token->session_key, crypto_scalarmult_SCALARBYTES);
		// log_debug_msg(LOG_DEBUG, "session    key   %s", session_hex);

		// uint64_t enc_msg_len = send_buf_len + crypto_secretbox_MACBYTES;
		unsigned char enc_msg[MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES];
		ret = crypto_secretbox_easy(enc_msg,
				(const unsigned char*) iter->val->msg_part,
				MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40,
				nonce,
				auth_token->session_key);

		if (ret != 0)
		{
			log_msg(LOG_NETWORK | LOG_WARN,
					"incorrect encryption of message (not sending to %s:%s)",
					node_key->node->dns_name, node_key->node->port);
			free(enc_buffer);
			return; //  FALSE;
		}

		uint64_t enc_buffer_len = MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES;
		memcpy(enc_buffer, nonce, crypto_secretbox_NONCEBYTES);
		memcpy(enc_buffer + crypto_secretbox_NONCEBYTES, enc_msg, enc_buffer_len);

		/* send data */
		// _LOCK_ACCESS(_np_state()->my_node_key->network) {
		_LOCK_ACCESS(&node_key->network->lock) {
			if(NULL != node_key->network->out_events) {
				// log_msg(LOG_NETWORKDEBUG, "sending message (%llu bytes) to %s:%s", MSG_CHUNK_SIZE_1024, node_key->node->dns_name, node_key->node->port);
				// ret = sendto (state->my_node_key->node->network->socket, enc_buffer, enc_buffer_len, 0, to, to_size);
				// ret = send (node_key->node->network->socket, enc_buffer, MSG_CHUNK_SIZE_1024, 0);
				sll_append(void_ptr, node_key->network->out_events, (void*) enc_buffer);
			} else {
				free (enc_buffer);
			}
		}

		// if (ret < 0)
		// {
		// log_msg (LOG_ERROR, "send message error: %s", strerror (errno));
		// return FALSE;
		// }
		// else
		// {
		// log_msg (LOG_NETWORKDEBUG, "sent message");
		// }

		pll_next(iter);
		i++;

	} while (NULL != iter);

	return; // TRUE;
}

void _np_network_send_from_events (NP_UNUSED struct ev_loop *loop, ev_io *event, int revents)
{
	if (EV_ERROR == (revents & EV_ERROR))
	{
		log_debug_msg(LOG_NETWORK | LOG_DEBUG, "error event received");
	}
	else if (EV_WRITE == (revents & EV_WRITE))
	{
		np_key_t* key = (np_key_t*) event->data;
		np_tryref_obj(np_key_t, key, keyExists);

		if(keyExists == TRUE) {

			//_np_threads_lock_module(np_network_t_lock);

			np_network_t* key_network = key->network ;
			if (NULL != key && NULL != key_network && TRUE == key_network->initialized)
			{
				np_ref_obj(np_network_t, key_network);
				_LOCK_ACCESS(&key_network->lock)
				{
					//_np_threads_unlock_module(np_network_t_lock);

					if (NULL != key_network->out_events &&
						0 < sll_size(key_network->out_events)
						)
					{
						if (NULL != key->node) {
							log_debug_msg(LOG_DEBUG, "sending message (%d bytes) to %s:%s",
									MSG_CHUNK_SIZE_1024, key->node->dns_name, key->node->port);
						}

						void* data_to_send = sll_head(void_ptr, key_network->out_events);
						if(NULL != data_to_send) {
							ssize_t written = 0, current_write = 0;
							while(written < MSG_CHUNK_SIZE_1024 ){
								current_write = write(key_network->socket, data_to_send, MSG_CHUNK_SIZE_1024);
								if (current_write == -1) {
									//if(errno != EWOULDBLOCK && errno != EAGAIN) {
										log_msg(LOG_WARN,
											"cannot write to socket: %s (%d)",
											strerror(errno),errno);
									//}
									break;
								}
								written += current_write;
							}
							log_debug_msg(LOG_DEBUG,"did write %d bytes",written);
							free(data_to_send);
						// ret is -1 or > 0 (bytes send)
						// do not update the success, because UDP sending could result in
						// false positives
						// if (0 > ret)
						// {
						//     // _np_node_update_stat(key->node, 0);
						//     // log_debug_msg(LOG_DEBUG, "node update reduce %d", ret);
						// }
						// else
						// {
						//     _np_node_update_stat(key->node, 1);
						//     log_debug_msg(LOG_DEBUG, "node update increase %d", ret);
						// }
						}
					}
					else
					{
						// log_debug_msg(LOG_DEBUG, "no data to write to %s:%s ...", key->node->dns_name, key->node->port);
						// log_debug_msg(LOG_DEBUG, "no data to write ...");
					}
				}
				np_unref_obj(np_network_t, key_network);
			}else{
			//	_np_threads_unlock_module(np_network_t_lock);
			}
			np_unref_obj(np_key_t,key);
		}
	}
	else if (EV_READ == (revents & EV_READ))
	{
		log_debug_msg(LOG_NETWORK | LOG_DEBUG, "unexpected event type");
	}
	else
	{
		log_debug_msg(LOG_NETWORK | LOG_DEBUG, "should never happen");
	}
}

void _np_network_accept(struct ev_loop *loop,  ev_io *event, int revents)
{
    log_msg(LOG_TRACE | LOG_NETWORK, "start: void _np_network_accept(struct ev_loop *loop,  ev_io *event, int revents){");
	log_msg(LOG_NETWORK | LOG_TRACE, ".start.np_network_accept");

	if(EV_ERROR & revents)
	{
		log_debug_msg(LOG_DEBUG,"got invalid tcp accept event");
	  return;
	}

	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);

	//np_state_t* state = _np_state();
	//np_network_t* ng = state->my_node_key->network;
	np_key_t* key = (np_key_t*) event->data; // state->my_node_key->network;
	np_network_t* ng = key->network;

	int client_fd = accept(ng->socket, (struct sockaddr*)NULL,NULL);

	if (client_fd < 0) {
		if(errno != EWOULDBLOCK && errno != EAGAIN ){
			log_msg(LOG_ERROR,
					"Could not accept socket connection on client fd %d. %s (%d)"
					, ng->socket, strerror(errno), errno);
		}
	} else {
		log_debug_msg(LOG_NETWORK | LOG_DEBUG, "accept socket from client fd: %d",
				client_fd);

		int err = -1;
		do{
			err =  getpeername(client_fd, (struct sockaddr*) &from, &fromlen);
		}while(0 != err && errno != ENOTCONN );

		// get calling address and port
		char ipstr[255];
		char port [7];
		// int16_t port;

		// deal with both IPv4 and IPv6:
		if (from.ss_family == AF_INET)
		{   // AF_INET
			struct sockaddr_in *s = (struct sockaddr_in *) &from;
			snprintf(port, 6, "%d", ntohs(s->sin_port));
			inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
		}
		else
		{   // AF_INET6
			struct sockaddr_in6 *s = (struct sockaddr_in6 *) &from;
			snprintf(port, 6, "%d", ntohs(s->sin6_port));
			inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
		}

		log_debug_msg(LOG_NETWORK | LOG_DEBUG,
				"received connection request from %s:%s (client fd: %d)",
				ipstr, port, client_fd);

		np_key_t* alias_key = NULL;
		np_dhkey_t search_key = np_dhkey_create_from_hostport(ipstr, port);
		alias_key = _np_keycache_find(search_key);

		//if(alias_key == NULL) {
			np_network_t* old_network = NULL;
			_LOCK_MODULE(np_network_t)
			{
				if(alias_key != NULL) {
					old_network = 	alias_key->network;
				} else {
					// init new alias key
					alias_key = _np_keycache_create(search_key);
					np_ref_obj(np_key_t, alias_key);
					alias_key->parent = key;
				}
				np_new_obj(np_network_t, alias_key->network);

				_LOCK_ACCESS (&alias_key->network->lock) {
					alias_key->network->socket = client_fd;
					alias_key->network->socket_type = ng->socket_type;
					alias_key->network->waiting = np_tree_create();
					alias_key->network->seqend = 0LU;

					// it could be a passive socket
					sll_init(void_ptr, alias_key->network->out_events);

					// set non blocking
					int current_flags = fcntl(client_fd, F_GETFL);
					current_flags |= O_NONBLOCK;
					fcntl(client_fd, F_SETFL, current_flags);

					alias_key->network->initialized = TRUE;
				}
			}
			EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);

			log_debug_msg(LOG_DEBUG,"suspend ev loop for tcp new socket network start");

			alias_key->network->watcher.data = alias_key;
			ev_io_init(
					&alias_key->network->watcher,
					_np_network_read,
					alias_key->network->socket,
					EV_READ
					);
			_np_network_start(alias_key->network);

			if(old_network != NULL) {
				_LOCK_MODULE(np_network_t)
				{
					np_unref_obj(np_network_t, old_network);
				}
			}
		//}
		log_debug_msg(LOG_NETWORK | LOG_DEBUG,
				"created network for key: %s and watching it.", _np_key_as_str(alias_key));
	}
}

/**
 ** _np_network_read:
 ** reads the network layer in listen mode.
 ** This function delivers incoming messages to the default message handler
 **/
void _np_network_read(struct ev_loop *loop, ev_io *event, NP_UNUSED int revents)
{
    log_msg(LOG_TRACE | LOG_NETWORK, "start: void _np_network_read(struct ev_loop *loop, ev_io *event, NP_UNUSED int revents){");
	log_msg(LOG_NETWORK | LOG_TRACE, ".start.np_network_read");
	// cast event data structure to np_state_t pointer

	char data[MSG_CHUNK_SIZE_1024];
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	// calling address and port
	char ipstr[255];
	char port [7];

	np_key_t* key = (np_key_t*) event->data; // state->my_node_key->network;
	np_network_t* ng = key->network;
	np_network_t* ng_tcp = NULL;

	/* receive the new data */
	int16_t in_msg_len = -1;
	log_debug_msg(LOG_NETWORK | LOG_DEBUG, "ng->socket_type: %d", ng->socket_type);
	log_debug_msg(LOG_NETWORK | LOG_DEBUG, "key: %s", _np_key_as_str(key));

	if ((ng->socket_type & TCP) == TCP) {
		in_msg_len = recv(ng->socket, data,	MSG_CHUNK_SIZE_1024, 0);
		if ( 0 != getpeername(ng->socket, (struct sockaddr*) &from, &fromlen))
		{
			log_msg(LOG_WARN, "could not receive socket peer: %s (%d)",
					strerror(errno), errno);
			return;
		}
		key = key->parent;
		ng_tcp = ng;
		ng = key->network;
	} else {
		in_msg_len = recvfrom(ng->socket, data,
				MSG_CHUNK_SIZE_1024, 0, (struct sockaddr*)&from, &fromlen);
	}
	log_debug_msg(LOG_NETWORK | LOG_DEBUG, "in_msg_len: %d", in_msg_len);

	if ( in_msg_len >=0) {
		// deal with both IPv4 and IPv6:
		if (from.ss_family == AF_INET )
		{
			log_debug_msg(LOG_NETWORK | LOG_DEBUG, "connection is IP4");
			// AF_INET
			struct sockaddr_in *s = (struct sockaddr_in *) &from;
			snprintf(port, 6, "%d", ntohs(s->sin_port));
			inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
		}
		else
		{
			log_debug_msg(LOG_NETWORK | LOG_DEBUG, "connection is IP6");
			// AF_INET6
			struct sockaddr_in6 *s = (struct sockaddr_in6 *) &from;
			snprintf(port, 6, "%d", ntohs(s->sin6_port));
			inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
		}

		if (0 == in_msg_len && ng_tcp != NULL)
		{
			// tcp disconnect
			log_msg(LOG_ERROR, "received disconnect from: %s:%s", ipstr, port);
			// TODO handle cleanup of node structures ?
			// maybe / probably the node received already a disjoin message before
			_np_network_stop(ng_tcp);
			_np_node_update_stat(key->node, 0);

			log_msg(LOG_NETWORK | LOG_TRACE, ".end  .np_network_read");
			return;
		}

		if (0 > in_msg_len)
		{
			log_msg(LOG_ERROR, "recvfrom failed: %s", strerror(errno));
			// job_submit_event(state->jobq, 0.0, _np_network_read);
			log_msg(LOG_NETWORK | LOG_TRACE, ".end  .np_network_read");
			return;
		}

		if ( ! (MSG_CHUNK_SIZE_1024                            == in_msg_len ||
			   (MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40) == in_msg_len) )
		{
			log_msg(LOG_NETWORK | LOG_WARN, "received wrong message size (%hd)", in_msg_len);
			// job_submit_event(state->jobq, 0.0, _np_network_read);
			log_msg(LOG_NETWORK | LOG_TRACE, ".end  .np_network_read");
			return;
		}

		log_debug_msg(LOG_NETWORK | LOG_DEBUG, "received message from %s:%s (size: %hd)",
				ipstr, port, in_msg_len);

		// we registered this token info before in the first handshake message
		np_dhkey_t search_key = np_dhkey_create_from_hostport(ipstr, port);
		np_key_t* alias_key = _np_keycache_find_or_create(search_key);

		if (NULL == alias_key){
			log_debug_msg(LOG_NETWORK | LOG_DEBUG, "could not find alias_key for msg");
			log_msg(LOG_NETWORK | LOG_TRACE, ".end  .np_network_read");
			return;
		}

		log_debug_msg(LOG_NETWORK | LOG_DEBUG, "alias_key for msg: %s",
				_np_key_as_str(alias_key));

		void* data_ptr = malloc(in_msg_len * sizeof(char));
		CHECK_MALLOC(data_ptr);

		memset(data_ptr, 0,    in_msg_len);
		memcpy(data_ptr, data, in_msg_len);

		_LOCK_ACCESS(&ng->lock)
		{
			if(NULL != ng->in_events)
			{
				sll_append(void_ptr, ng->in_events, data_ptr);
			}
		}
		np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, _DEFAULT);

		_np_job_submit_msgin_event(0.0, msg_prop, alias_key, NULL);
		log_debug_msg(LOG_NETWORK | LOG_DEBUG, "submitted msg to list for %s",
				_np_key_as_str(key) );

		np_unref_obj(np_key_t, alias_key);
	} else {
		log_debug_msg(LOG_NETWORK | LOG_DEBUG, "message package error: %s (%d)",
				strerror(errno), errno);
	}
	log_msg(LOG_NETWORK | LOG_TRACE, ".end  .np_network_read");
}

void _np_network_sendrecv(struct ev_loop *loop, ev_io *event, int revents)
{
    log_msg(LOG_TRACE | LOG_NETWORK, "start: void _np_network_sendrecv(struct ev_loop *loop, ev_io *event, int revents){");
	if (revents & EV_WRITE)
	{
		_np_network_send_from_events(loop, event, revents);
	}

	if (revents & EV_READ)
	{
		_np_network_read(loop, event, revents);
	}
}

void _np_network_stop(np_network_t* network){
    log_msg(LOG_TRACE | LOG_NETWORK, "start: void _np_network_stop(np_network_t* network){");
    if(NULL != network){
		_LOCK_ACCESS(&network->lock){
			if(network->isWatching == TRUE) {
				network->isWatching 	= FALSE;
				EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
				ev_io_stop(EV_A_ &network->watcher);
			}
		}
    }
}

void _np_network_start(np_network_t* network){
    log_msg(LOG_TRACE | LOG_NETWORK, "start: void _np_network_start(np_network_t* network){");
    if(NULL != network){
    	_LOCK_ACCESS(&network->lock){
			if(network->isWatching == FALSE) {
				network->isWatching 	= TRUE;
				EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
				ev_io_start(EV_A_ &network->watcher);
			}
    	}
    }
}

/**
 * network_destroy
 */
void _np_network_t_del(void* nw)
{
    log_msg(LOG_TRACE | LOG_NETWORK, "start: void _np_network_t_del(void* nw){");
	np_network_t* network = (np_network_t*) nw;

	_LOCK_ACCESS(&network->lock)
	{
		_np_network_stop(network);
		np_key_t* old_key = (np_key_t*) network->watcher.data;
		np_unref_obj(np_key_t, old_key);

		if (NULL != network->waiting)
			np_tree_free(network->waiting);

		if (NULL != network->in_events)
		{
			if (0 < sll_size(network->in_events))
			{
				do {
					void* tmp = sll_head(void_ptr, network->in_events);
					free(tmp);
				} while (0 < sll_size(network->in_events));
			}
			sll_free(void_ptr, network->in_events);
		}

		if (NULL != network->out_events)
		{
			if (0 < sll_size(network->out_events))
			{
				do {
					void* tmp = sll_head(void_ptr, network->out_events);
					free(tmp);
				} while (0 < sll_size(network->out_events));
			}
			sll_free(void_ptr, network->out_events);
		}

		if (0 < network->socket) close (network->socket);

		network->initialized = FALSE;
	}
	// finally destroy the mutex again
	_np_threads_mutex_destroy (&network->lock);

}


void _np_network_t_new(void* nw)
{
    log_msg(LOG_TRACE | LOG_NETWORK, "start: void _np_network_t_new(void* nw){");
    np_network_t* ng = (np_network_t *) nw;
    ng->addr_in 	= NULL;
    ng->waiting 	= NULL;
    ng->in_events 	= NULL;
    ng->out_events 	= NULL;
    ng->isWatching 	= FALSE;
    ng->initialized = FALSE;

	log_debug_msg(LOG_DEBUG, "try to pthread_mutex_init");
	int network_mutex_init = -1;
	if ((network_mutex_init = _np_threads_mutex_init (
			&ng->lock)) != 0)
	{
		log_msg(LOG_ERROR, "pthread_mutex_init: %s (%d)",
				strerror (network_mutex_init),network_mutex_init);
	}
	log_debug_msg(LOG_DEBUG, "done pthread_mutex_init");

}

/** _np_network_init:
 ** initiates the networking layer structures required for a node
 ** if the port number is bigger than zero, it will create a socket and bind it to #port#
 ** the type defines the protocol which is used by the node (@see socket_type)
 **/
np_bool _np_network_init (np_network_t* ng, np_bool create_socket, uint8_t type, char* hostname, char* service)
{
	int ret = 0;
    int one = 1;
    int v6_only = 0;

    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "try to get_network_address");
    _np_network_get_address (create_socket, &ng->addr_in, type, hostname, service);
    ng->socket_type = type;
    if (NULL == ng->addr_in)
    {
        log_msg(LOG_ERROR, "could not receive network address");
        return FALSE;
    }
    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "done get_network_address");

    // create an inbound socket - happens only once per node
    if (TRUE == create_socket )
    {
    	log_debug_msg(LOG_NETWORK | LOG_DEBUG, "creating receiving network");

		// create own retransmit structures
		ng->waiting = np_tree_create();
		sll_init(void_ptr, ng->in_events);
		// own sequence number counter
		ng->seqend = 0LU;

    	// nothing to do for passive nodes
		if ((type & PASSIVE) != PASSIVE) {

			// server setup - create socket
			// UDP note: not using a connected socket for sending messages to a different node
			// leads to unreliable delivery. The sending socket changes too often to be useful
			// for finding the correct decryption shared secret. Especially true for ipv6 ...

			ng->socket = socket (ng->addr_in->ai_family, ng->addr_in->ai_socktype, ng->addr_in->ai_protocol);
			if (0 > ng->socket)
			{
				log_msg(LOG_ERROR, "could not create socket: %s", strerror (errno));
				return FALSE;
			}
			if (-1 == setsockopt (ng->socket, SOL_SOCKET, SO_REUSEADDR, (void *) &one, sizeof (one)))
			{
				log_msg(LOG_ERROR, "setsockopt (SO_REUSEADDR): %s: ", strerror (errno));
				close (ng->socket);
				return FALSE;
			}
			if (-1 == setsockopt( ng->socket, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof( v6_only) ) )
			{
				// enable ipv4 mapping
				log_msg(LOG_NETWORK | LOG_WARN, "setsockopt (IPV6_V6ONLY): %s: ", strerror (errno));
			}

			// set non blocking
			int current_flags = fcntl(ng->socket, F_GETFL);
			current_flags |= O_NONBLOCK;
			fcntl(ng->socket, F_SETFL, current_flags);

			/* attach socket to #port#. */
			if (0 > bind (ng->socket, ng->addr_in->ai_addr, ng->addr_in->ai_addrlen))
			{
				log_msg(LOG_ERROR, "bind failed: %s:", strerror (errno));
				close (ng->socket);
				// listening port could not be opened
				return FALSE;
			}

			if (type & TCP) {
				if (0 > listen(ng->socket, 10)) {
					log_msg(LOG_ERROR, "listen on tcp port failed: %s:", strerror (errno));
					close (ng->socket);
					return FALSE;
				}
			}

			EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);

			if (type & TCP)
			{
				ev_io_init(&ng->watcher, _np_network_accept, ng->socket, EV_READ);
			}
			else if (type & UDP)
			{
				ev_io_init(&ng->watcher, _np_network_read, ng->socket, EV_READ);
			}
			_np_network_start(ng);
		}
    	ng->initialized = TRUE;
    	log_debug_msg(LOG_NETWORK | LOG_DEBUG, "created local listening socket");

	} else {
		log_debug_msg(LOG_NETWORK | LOG_DEBUG, "creating sending network");

		// client setup

		sll_init(void_ptr, ng->out_events);

		// client socket - wait for writeable socket
    	ng->socket = socket (ng->addr_in->ai_family, ng->addr_in->ai_socktype, ng->addr_in->ai_protocol);
    	if (0 > ng->socket)
    	{
    		log_msg(LOG_ERROR, "could not create socket: %s", strerror (errno));
    		return FALSE;
    	}
    	if (-1 == setsockopt (ng->socket, SOL_SOCKET, SO_REUSEADDR, (void *) &one, sizeof (one)))
    	{
    		log_msg(LOG_ERROR, "setsockopt (SO_REUSEADDR): %s: ", strerror (errno));
    		close (ng->socket);
    		return FALSE;
		}
    	if (-1 == setsockopt( ng->socket, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof( v6_only) ) )
    	{
    		// enable ipv4 mapping
    		log_msg(LOG_NETWORK | LOG_WARN, "setsockopt (IPV6_V6ONLY): %s: ", strerror (errno));
		}


#ifdef SKIP_EVLOOP
    	// TODO: write normal threading receiver
#endif
		// initialize to be on the safe side
		ng->watcher.data = NULL;
		EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);

		// UDP note: not using a connected socket for sending messages to a different node
		// leads to unreliable delivery. The sending socket changes too often to be useful
		// for finding the correct decryption shared secret. Especially true for ipv6 ...

		// As we do have a async connection (and TCP may need longer due to
		// handshake packages) we need to check the connection status for a moment
		int retry_connect = 3;
		int connection_status = -1;
		do{
			connection_status = connect(
					ng->socket, ng->addr_in->ai_addr, ng->addr_in->ai_addrlen);

			log_debug_msg(LOG_NETWORK | LOG_DEBUG,"TRY CONNECT");
			if(connection_status != 0){
				ev_sleep(0.1);
			}
		}while( 0 != connection_status && retry_connect-- > 0);

		if (0 != connection_status) {
			if( errno != EISCONN) {
				log_msg(LOG_ERROR,
						"could not connect: %s (%d)", strerror (errno), errno);
				close (ng->socket);
				return FALSE;
			}
		}
    	// set non blocking
    	int current_flags = fcntl(ng->socket, F_GETFL);
    	current_flags |= O_NONBLOCK;
    	fcntl(ng->socket, F_SETFL, current_flags);

		if (0 != (type & PASSIVE))
		{
			// not here and now, but after the handshake
		}
		else
		{
			ev_io_init(
					&ng->watcher, _np_network_send_from_events,
					ng->socket, EV_WRITE);
		}
		_np_network_start(ng);

		log_debug_msg(LOG_NETWORK | LOG_DEBUG,
				": %d %p %p :", ng->socket, &ng->watcher,  &ng->watcher.data);

		ng->initialized = TRUE;
    	log_debug_msg(LOG_NETWORK | LOG_DEBUG, "created local sending socket");
    }

    freeaddrinfo( ng->addr_in );
    return TRUE;
}
