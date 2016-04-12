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


#include "dtime.h"
#include "log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_jtree.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_network.h"
#include "np_node.h"
#include "np_threads.h"

NP_SLL_GENERATE_IMPLEMENTATION(void_ptr);

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
	entry->transmittime = 0.0;

	entry->expected_ack = 0;
	entry->received_ack = 0;

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

uint8_t np_parse_protocol_string (const char* protocol_str)
{
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

	log_msg(LOG_NETWORK | LOG_DEBUG, "using getaddrinfo: %d:%s:%s", type, hostname, service);
	if ( 0 != ( err = getaddrinfo( hostname, service, &hints, ai_head ) ))
	{
		log_msg(LOG_NETWORK | LOG_ERROR, "error getaddrinfo: %s", gai_strerror( err ) );
		return;
	}

/*	struct addrinfo* ai;
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
                log_msg(LOG_NETWORK | LOG_DEBUG,
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
               log_msg(LOG_NETWORK | LOG_DEBUG,
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
void network_send (np_state_t* state, np_key_t *node_key, np_message_t* msg)
{
	int ret;

	// get encryption details
	np_aaatoken_t* auth_token = node_key->aaa_token;

	if (NULL == auth_token ||
		IS_INVALID(auth_token->state))
	{
		if (node_key->node->handshake_status < HANDSHAKE_INITIALIZED)
		{
			node_key->node->handshake_status = HANDSHAKE_INITIALIZED;

			log_msg(LOG_NETWORK | LOG_INFO, "requesting a new handshake with %s:%s (%s)",
					node_key->node->dns_name, node_key->node->port, _key_as_str(node_key));

			np_msgproperty_t* msg_prop = np_msgproperty_get(OUTBOUND, NP_MSG_HANDSHAKE);
			np_job_submit_msg_event(0.0, msg_prop, node_key, NULL);
		}
		return; // FALSE;
	}

	// log_msg(LOG_NETWORKDEBUG, "serialized message to %llu bytes", send_buf_len);
	uint16_t i = 0;

	pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
	do
	{
		char* enc_buffer = malloc(MSG_CHUNK_SIZE_1024);

		// add protection from replay attacks ...
		unsigned char nonce[crypto_secretbox_NONCEBYTES];
		randombytes_buf(nonce, sizeof(nonce));

		char nonce_hex[crypto_secretbox_NONCEBYTES*2+1];
		sodium_bin2hex(nonce_hex, crypto_secretbox_NONCEBYTES*2+1, nonce, crypto_secretbox_NONCEBYTES);
		// log_msg(LOG_DEBUG, "encryption nonce %s", nonce_hex);

		char session_hex[crypto_scalarmult_SCALARBYTES*2+1];
		sodium_bin2hex(session_hex, crypto_scalarmult_SCALARBYTES*2+1, auth_token->session_key, crypto_scalarmult_SCALARBYTES);
		// log_msg(LOG_DEBUG, "session    key   %s", session_hex);

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
					"incorrect encryption of message (not sending to %s:%hd)",
					node_key->node->dns_name, node_key->node->port);
			return; //  FALSE;
		}

		uint64_t enc_buffer_len = MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES;
		memcpy(enc_buffer, nonce, crypto_secretbox_NONCEBYTES);
		memcpy(enc_buffer + crypto_secretbox_NONCEBYTES, enc_msg, enc_buffer_len);

		/* send data */
		pthread_mutex_lock(&(state->my_node_key->network->lock));

		// log_msg(LOG_NETWORKDEBUG, "sending message (%llu bytes) to %s:%s", MSG_CHUNK_SIZE_1024, node_key->node->dns_name, node_key->node->port);
		// ret = sendto (state->my_node_key->node->network->socket, enc_buffer, enc_buffer_len, 0, to, to_size);
		// ret = send (node_key->node->network->socket, enc_buffer, MSG_CHUNK_SIZE_1024, 0);
		sll_append(void_ptr, node_key->network->out_events, (void*) enc_buffer);

		pthread_mutex_unlock(&(state->my_node_key->network->lock));

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
	// } while (i < chunks && (FALSE == msg->is_single_part));

	return; // TRUE;
}

void _np_network_send (struct ev_loop *loop, ev_io *event, int revents)
{
	if (EV_ERROR == (revents & EV_ERROR))
	{
		log_msg(LOG_NETWORK | LOG_DEBUG, "error event received");
	}
	else if (EV_WRITE == (revents & EV_WRITE))
	{
		np_key_t* key = (np_key_t*) event->data;

		if (NULL != key &&
			NULL != key->node &&
			NULL != key->network &&
			0 < sll_size(key->network->out_events))
		{
			pthread_mutex_lock(&key->network->lock);
			void* data_to_send = sll_head(void_ptr, key->network->out_events);
			// pthread_mutex_unlock(&key->network->lock);

			log_msg(LOG_NETWORK | LOG_DEBUG, "sending message (%llu bytes) to %s:%s", MSG_CHUNK_SIZE_1024, key->node->dns_name, key->node->port);
			// ret = sendto (state->my_node_key->node->network->socket, enc_buffer, enc_buffer_len, 0, to, to_size);
			// int ret = send(key->network->socket, data_to_send, MSG_CHUNK_SIZE_1024, 0);
			int ret = write(key->network->socket, data_to_send, MSG_CHUNK_SIZE_1024);
			free(data_to_send);

			// ret is -1 or > 0 (bytes send)
			// pthread_mutex_lock(&key->network->lock);
			if (0 > ret)
			{
				np_node_update_stat(key->node, 0);
				// log_msg(LOG_DEBUG, "node update reduce %d", ret);
			}
			// do not update the success, because UDP sending could result in false positives
			// else
			// {
			// np_node_update_stat(key->node, 1);
			// log_msg(LOG_DEBUG, "node update increase %d", ret);
			// }
			pthread_mutex_unlock(&key->network->lock);
		}
		else
		{
			// log_msg(LOG_DEBUG, "no data to write to %s:%s ...", key->node->dns_name, key->node->port);
			// log_msg(LOG_DEBUG, "no data to write ...");
		}
	}
	else if (EV_READ == (revents & EV_READ))
	{
		log_msg(LOG_NETWORK | LOG_DEBUG, "unexpected event type");
	}
	else
	{
		log_msg(LOG_NETWORK | LOG_DEBUG, "should never happen");
	}
}

void _np_network_accept(struct ev_loop *loop, ev_io *event, int revents)
{
	log_msg(LOG_NETWORK | LOG_TRACE, ".start.np_network_accept");

	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);

	np_state_t* state = _np_state();
	np_network_t* ng = state->my_node_key->network;

	int client_fd = accept(ng->socket, (struct sockaddr*)&from, &fromlen);

	// get calling address and port
	char ipstr[255];
	char port [6];
	// int16_t port;

	if (from.ss_family == AF_INET)
	{
		struct sockaddr_in *s = (struct sockaddr_in *) &from;
		getnameinfo((struct sockaddr*)s, sizeof s, ipstr, 255, port, 6, 0);
	}
	else
	{
		struct sockaddr_in6 *s = (struct sockaddr_in6 *) &from;
		getnameinfo((struct sockaddr*) s, sizeof s, ipstr, 255, port, 6, 0);
	}

	log_msg(LOG_NETWORK | LOG_DEBUG, "received message from %s:%s (client fd: %hd)", ipstr, port, client_fd);

	np_key_t* alias_key = NULL;
	np_dhkey_t search_key = dhkey_create_from_hostport(ipstr, port);

	LOCK_CACHE(state)
	{
		alias_key = _np_key_find_create(search_key);
	}

	// set non blocking
	int current_flags = fcntl(client_fd, F_GETFL);
	current_flags |= O_NONBLOCK;
	fcntl(client_fd, F_SETFL, current_flags);

	alias_key->network = (np_network_t *) malloc (sizeof (np_network_t));
	alias_key->network->addr_in = NULL;
	alias_key->network->socket = client_fd;
	// it could be a passive socket
	sll_init(void_ptr, alias_key->network->out_events);

    alias_key->network->watcher.data = alias_key;

	_np_suspend_event_loop();
	ev_io_init(&alias_key->network->watcher, _np_network_read, alias_key->network->socket, EV_READ);
	ev_io_start(EV_A_ &ng->watcher);
	_np_resume_event_loop();
}

void _np_network_read(struct ev_loop *loop, ev_io *event, int revents)
{
	log_msg(LOG_NETWORK | LOG_TRACE, ".start.np_network_read");
	// cast event data structure to np_state_t pointer

	np_state_t* state = _np_state();

	char data[MSG_CHUNK_SIZE_1024];
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	// calling address and port
	char ipstr[255];
	char port [6];

	np_key_t* key = (np_key_t*) event->data; // state->my_node_key->network;
	np_network_t* ng = key->network;

	/* receive the new data */
	int16_t in_msg_len = recvfrom(ng->socket, data, MSG_CHUNK_SIZE_1024, 0, (struct sockaddr*)&from, &fromlen);

	if (from.ss_family == AF_INET)
	{
		struct sockaddr_in *s = (struct sockaddr_in *) &from;
		getnameinfo((struct sockaddr*)s, sizeof s, ipstr, 255, port, 6, 0);
	}
	else
	{
		struct sockaddr_in6 *s = (struct sockaddr_in6 *) &from;
		getnameinfo((struct sockaddr*) s, sizeof s, ipstr, 255, port, 6, 0);
	}

	if (0 == in_msg_len)
	{
		// tcp disconnect
		log_msg(LOG_NETWORK | LOG_ERROR, "received disconnect from: %s", ipstr, port);
		// TODO handle cleanup of node structures ?
		// maybe / probably the node received already a disjoin message before
		ev_io_stop(EV_A_ &ng->watcher);
		np_node_update_stat(key->node, 0);
		close(ng->socket);
	}

	if (0 > in_msg_len)
	{
		log_msg(LOG_NETWORK | LOG_ERROR, "recvfrom failed: %s", strerror(errno));
		// job_submit_event(state->jobq, 0.0, _np_network_read);
		log_msg(LOG_NETWORK | LOG_TRACE, ".end  .np_network_read");
		return;
	}

	if ( ! (MSG_CHUNK_SIZE_1024                            == in_msg_len ||
	       (MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40) == in_msg_len) )
	{
		log_msg(LOG_NETWORK | LOG_DEBUG, "received wrong message size (%hd)", in_msg_len);
		// job_submit_event(state->jobq, 0.0, _np_network_read);
		log_msg(LOG_NETWORK | LOG_TRACE, ".end  .np_network_read");
		return;
	}

	log_msg(LOG_NETWORK | LOG_DEBUG, "received message from %s:%s (size: %hd)", ipstr, port, in_msg_len);

	// we registered this token info before in the first handshake message
	np_key_t* alias_key = NULL;
	np_dhkey_t search_key = dhkey_create_from_hostport(ipstr, port);

	LOCK_CACHE(state)
	{
		alias_key = _np_key_find_create(search_key);
	}

	void* data_ptr = malloc(in_msg_len * sizeof(char));
	memset(data_ptr, 0,    in_msg_len);
	memcpy(data_ptr, data, in_msg_len);

	sll_append(void_ptr, ng->in_events, data_ptr);

	np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, DEFAULT);
	np_job_submit_msg_event(0.0, msg_prop, alias_key, NULL);

	log_msg(LOG_NETWORK | LOG_TRACE, ".end  .np_network_read");
}

void _np_network_sendrecv(struct ev_loop *loop, ev_io *event, int revents)
{
	if (revents & EV_WRITE)
	{
		_np_network_send(loop, event, revents);
	}

	if (revents & EV_READ)
	{
		_np_network_read(loop, event, revents);
	}
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

    if ((ret = pthread_mutex_init (&(ng->lock), NULL)) != 0)
	{
		log_msg(LOG_NETWORK | LOG_ERROR, "pthread_mutex_init: %s:", strerror (ret));
		close (ng->socket);
		return NULL;
	}

    get_network_address (create_socket, &ng->addr_in, type, hostname, service);
    if (NULL == ng->addr_in)
    {
    	return NULL;
    }

    // create an inbound socket - happens only once per node
    if (TRUE == create_socket )
    {
    	// nothing to do for passive nodes
    	if (type & PASSIVE) return ng;

    	// server setup
        log_msg(LOG_NETWORK | LOG_DEBUG, "canonical name: %s", ng->addr_in->ai_canonname);
    	// create socket
        // UDP note: not using a connected socket for sending messages to a different node
        // leads to unreliable delivery. The sending socket changes too often to be useful
        // for finding the correct decryption shared secret. Especially true for ipv6 ...

    	ng->socket = socket (ng->addr_in->ai_family, ng->addr_in->ai_socktype, ng->addr_in->ai_protocol);
    	if (0 > ng->socket)
    	{
    		log_msg(LOG_NETWORK | LOG_ERROR, "could not create socket: %s", strerror (errno));
    		exit(1) ;
    	}
    	if (-1 == setsockopt (ng->socket, SOL_SOCKET, SO_REUSEADDR, (void *) &one, sizeof (one)))
    	{
    		log_msg(LOG_NETWORK | LOG_ERROR, "setsockopt (SO_REUSEADDR): %s: ", strerror (errno));
    		close (ng->socket);
    		exit(1);
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
    		log_msg(LOG_NETWORK | LOG_ERROR, "bind failed: %s:", strerror (errno));
    		close (ng->socket);
    		// exit, because listening port could not be opened
    		exit(1);
		}

    	if (type & TCP) {
    		if (0 > listen(ng->socket, 10)) {
    			log_msg(LOG_ERROR, "listen on tcp port failed: %s:", strerror (errno));
    			exit(1);
			}
    	}

    	// create own retransmit structures
    	ng->waiting = make_jtree();
    	sll_init(void_ptr, ng->in_events);

    	// own sequence number counter
    	ng->seqend = 0LU;

    	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);

    	_np_suspend_event_loop();
    	if (type & TCP)
    	{
    		// TODO implement accept and create client socket for each connection
    		ev_io_init(&ng->watcher, _np_network_accept, ng->socket, EV_READ);
    	}
    	else if (type & UDP)
    	{
    		ev_io_init(&ng->watcher, _np_network_read, ng->socket, EV_READ);
    	}
    	ev_io_start(EV_A_ &ng->watcher);
    	_np_resume_event_loop();

    	log_msg(LOG_NETWORK | LOG_DEBUG, "created local listening socket");

	} else {

		// client setup
        log_msg(LOG_NETWORK | LOG_DEBUG, "canonical name: %s", ng->addr_in->ai_canonname);

		sll_init(void_ptr, ng->out_events);

		// client socket - wait for writeable socket
    	ng->socket = socket (ng->addr_in->ai_family, ng->addr_in->ai_socktype, ng->addr_in->ai_protocol);
    	if (0 > ng->socket)
    	{
    		log_msg(LOG_NETWORK | LOG_ERROR, "could not create socket: %s", strerror (errno));
    		return NULL;
    	}
    	if (-1 == setsockopt (ng->socket, SOL_SOCKET, SO_REUSEADDR, (void *) &one, sizeof (one)))
    	{
    		log_msg(LOG_NETWORK | LOG_ERROR, "setsockopt (SO_REUSEADDR): %s: ", strerror (errno));
    		close (ng->socket);
    		return NULL;
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

#ifdef SKIP_EVLOOP
    	// TODO: write normal threading receiver
#endif
		// initialize to be on the safe side
		ng->watcher.data = NULL;
		EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);

    	_np_suspend_event_loop();
    	if (type & PASSIVE)
    	{
    		// not here and now, but after the handshake
    	}
    	else
    	{
    		ev_io_init(&ng->watcher, _np_network_send, ng->socket, EV_WRITE);
    	}
		ev_io_start(EV_A_ &ng->watcher);

		log_msg(LOG_NETWORK | LOG_DEBUG, ": %d %p %p :", &ng->socket, &ng->watcher,  &ng->watcher.data);
		_np_resume_event_loop();

    	// UDP note: not using a connected socket for sending messages to a different node
        // leads to unreliable delivery. The sending socket changes too often to be useful
        // for finding the correct decryption shared secret. Especially true for ipv6 ...
		if (0 > connect(ng->socket, ng->addr_in->ai_addr, ng->addr_in->ai_addrlen))
		{
			log_msg(LOG_NETWORK | LOG_ERROR, "connect: %s:", strerror (errno));
			close (ng->socket);
			return NULL;
    	}
    }

    freeaddrinfo( ng->addr_in );

    return ng;
}

