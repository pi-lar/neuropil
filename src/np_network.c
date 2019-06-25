//
// neuropil is copyright 2016-2019 by pi-lar GmbH
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
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netdb.h>
#include <pthread.h>
#include <assert.h>
#include <event/ev.h>

#include "np_network.h"

#include "core/np_comp_node.h"

#include "dtime.h"
#include "np_log.h"
#include "np_legacy.h"
#include "np_aaatoken.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_dhkey.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_message.h"
#include "np_messagepart.h"
#include "np_memory.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_event.h"
#include "np_types.h"
#include "np_constants.h"
#include "np_settings.h"
#include "np_util.h"
#include "np_statistics.h"
#include "np_dendrit.h"

static char* URN_TCP_V4 = "tcp4";
static char* URN_TCP_V6 = "tcp6";
static char* URN_PAS_V4 = "pas4";
static char* URN_PAS_V6 = "pas6";
static char* URN_UDP_V4 = "udp4";
static char* URN_UDP_V6 = "udp6";
static char* URN_IP_V4  = "ip4";
static char* URN_IP_V6  = "ip6";

enum socket_type _np_network_parse_protocol_string (const char* protocol_str)
{
    if (0 == strncmp(protocol_str, URN_TCP_V4, 4)) return (TCP     | IPv4);
    if (0 == strncmp(protocol_str, URN_TCP_V6, 4)) return (TCP     | IPv6);
    if (0 == strncmp(protocol_str, URN_PAS_V4, 4)) return (PASSIVE | IPv4);
    if (0 == strncmp(protocol_str, URN_PAS_V6, 4)) return (PASSIVE | IPv6);
    if (0 == strncmp(protocol_str, URN_UDP_V4, 4)) return (UDP     | IPv4);
    if (0 == strncmp(protocol_str, URN_UDP_V6, 4)) return (UDP     | IPv6);
    //if (0 == strncmp(protocol_str, URN_IP_V4, 3))  return (RAW     | IPv4);
    //if (0 == strncmp(protocol_str, URN_IP_V6, 3))  return (RAW     | IPv6);

    return (UNKNOWN_PROTO);
}

char* _np_network_get_protocol_string (np_state_t* context, enum socket_type protocol)
{
    if (FLAG_CMP(protocol, (PASSIVE | IPv4))) return (URN_PAS_V4);
    if (FLAG_CMP(protocol, (PASSIVE | IPv6))) return (URN_PAS_V6);
    if (FLAG_CMP(protocol,(TCP     | IPv4))) return (URN_TCP_V4);
    if (FLAG_CMP(protocol,(TCP     | IPv6))) return (URN_TCP_V6);
    if (FLAG_CMP(protocol,(UDP     | IPv4))) return (URN_UDP_V4);
    if (FLAG_CMP(protocol,(UDP     | IPv6))) return (URN_UDP_V6);
    //if (protocol == (RAW     | IPv4)) return (URN_IP_V4);
    //if (protocol == (RAW     | IPv6)) return (URN_IP_V6);
    log_msg(LOG_WARN, "Protocol %d is not availabe!", protocol);
#ifdef DEBUG 
    assert(false && "Protocol is not availabe!");
#endif
    return ("UNKNOWN_PROTOCOL");
}

void __np_network_close(np_network_t* self) {
    np_ctx_memory(self);
    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "Closing network %p -> %d",self,self->socket);
    close(self->socket);
}

/** network_address:
 ** returns the addrinfo structure of the hostname / service
 **/
void _np_network_get_address(
        np_state_t* context, 
        bool create_socket,
        struct addrinfo** ai_head,
        enum socket_type type,
        char *hostname,
        char* service)
{
    int err;
    struct addrinfo hints = { 0,0,0,0,0,0,0,0 };

    if (true == create_socket)
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
        log_msg(LOG_ERROR, "error getaddrinfo: %s (%d)", gai_strerror(err), err);
        log_msg(LOG_ERROR, "error errno: %s (%d)", gai_strerror(errno), errno);

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
//    // pthread_mutex_lock (&(ng->send_data_lock));
//    if (is_addr) he = gethostbyaddr ((char *) &addr, sizeof (addr), AF_INET);
//    else         he = gethostbyname (hostname);
//
//    if (he == NULL)
//	{
//	    // pthread_mutex_unlock (&(ng->send_data_lock));
//	    return (0);
//	}
//    /* make sure the machine is not returning localhost */
//    addr = *(unsigned long *) he->h_addr_list[0];
//    for (i = 1; he->h_addr_list[i] != NULL && addr == local; i++)
//    	addr = *(unsigned long *) he->h_addr_list[i];
//    // pthread_mutex_unlock (&(ng->send_data_lock));
//
//    return (addr);
}

/*
bool _np_network_send_handshake(np_state_t* context, np_key_t* node_key, bool response_handshake, char* response_uuid)
{
    bool ret = false;
    _LOCK_MODULE(np_handshake_t) {
        if (node_key != NULL) {
            np_tryref_obj(np_node_t, node_key->node, node_available, node);
            if(node_available) {
                _LOCK_ACCESS(&(node->lock)) {
                    double now = np_time_now();
                    np_msgproperty_t* msg_prop = _np_msgproperty_get(context, OUTBOUND, _NP_MSG_HANDSHAKE);
                    assert(msg_prop != NULL);

                    if (response_handshake ||
                        node->_handshake_status == np_handshake_status_Disconnected ||
                        (node->_handshake_status == np_handshake_status_SelfInitiated &&
                            (node->handshake_send_at + msg_prop->msg_ttl) < now
                        )
                    )
                    {
                        log_msg(LOG_ROUTING | LOG_HANDSHAKE | LOG_INFO, "requesting a %shandshake with %s:%s (%s)",
                            !response_handshake ? "new " : "",
                            node->dns_name, node->port, _np_key_as_str(node_key));

                        if (!response_handshake)
                        {
                            np_node_set_handshake(node, np_handshake_status_SelfInitiated);
                        }
                        node->handshake_send_at = np_time_now();
                        _np_job_submit_transform_event(context, 0.0, msg_prop, node_key, response_uuid ? strdup(response_uuid) : NULL);
                        ret = true;
                    }
                    else {
                        log_debug_msg(LOG_ROUTING | LOG_HANDSHAKE | LOG_DEBUG,
                            "handshake for alias %s requested, but alias in state %s and last handshake was send at %f (next handshake available n %f sec)",
                            _np_key_as_str(node_key),
                            np_handshake_status_str[node->_handshake_status],
                            node->handshake_send_at,
                            (node->handshake_send_at + msg_prop->msg_ttl) > now ? 
                                (node->handshake_send_at + msg_prop->msg_ttl) - now :
                                -1.
                        );
                    }
                }
                np_unref_obj(np_node_t, node, FUNC);
            }
        }
    }
    return ret;
}
*/
/**
 ** sends a message to host
 **/
bool _np_network_append_msg_to_out_queue (np_key_t *node_key, np_message_t* msg)
{
    np_ctx_memory(msg); 
    bool ret = false;
    np_waitref_obj(np_node_t, node_key->node, target_node);
      
    // Send handshake info if necessary
    if (target_node->_handshake_status == np_handshake_status_Connected)
    {
        np_waitref_obj(np_network_t, node_key->network, node_key_network);

        // get encryption details
        if (target_node->session_key_is_set == false) {
            log_msg(LOG_ERROR, "auth token has no session key, but handshake is done (key: %s)", _np_key_as_str(node_key));
        }
        else {
            log_debug_msg(LOG_NETWORK | LOG_DEBUG, "msg (%s) sending for \"%s\" over key %s", msg->uuid, _np_message_get_subject(msg), _np_key_as_str(node_key));
            _LOCK_ACCESS(&msg->msg_chunks_lock) {

                int part = 0;
                pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
                while (NULL != iter )
                {
                    part++;
                    np_tryref_obj(np_messagepart_t, iter->val, hasMsgPart, msg_part,  "np_tryref_obj_iter->val");
                    if (hasMsgPart) {

                        // add protection from replay attacks ...
                        unsigned char nonce[crypto_secretbox_NONCEBYTES];
                        // TODO: move nonce to np_node_t and re-use it with increments
                        randombytes_buf(nonce, sizeof(nonce));

                        unsigned char enc_msg[MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES];
                        int encryption = crypto_secretbox_easy(enc_msg,
                            (const unsigned char*)msg_part->msg_part,
                            MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40,
                            nonce,
                            target_node->session.session_key_to_write
                        );

                        log_debug_msg(LOG_DEBUG | LOG_HANDSHAKE,
                            "HANDSHAKE SECRET: using shared secret from target %s on system %s to encrypt data (msg: %s)",
                            _np_key_as_str(node_key), _np_key_as_str(context->my_node_key), msg->uuid);

                        if (encryption != 0)
                        {
                            log_msg(LOG_ERROR,
                                "incorrect encryption of message (%s) (not sending to %s:%s)",
                                msg->uuid, target_node->dns_name, target_node->port);
                            np_unref_obj(np_messagepart_t, msg_part, "np_tryref_obj_iter->val");
                            ret = false;

                        } else {
                            unsigned char* enc_buffer = np_memory_new(context, np_memory_types_BLOB_1024);
                            
                            uint32_t enc_buffer_len = MSG_CHUNK_SIZE_1024 - crypto_secretbox_NONCEBYTES;
                            memcpy(enc_buffer, nonce, crypto_secretbox_NONCEBYTES);
                            memcpy(enc_buffer + crypto_secretbox_NONCEBYTES, enc_msg, enc_buffer_len);

                            /* send data */
                            _LOCK_ACCESS(&node_key->network->out_events_lock) {
                                if (NULL != node_key->network->out_events) {
                                    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "appending message (%s part: %d) %p (%d bytes) to queue for %s:%s", msg->uuid, part, enc_buffer, MSG_CHUNK_SIZE_1024, target_node->dns_name, target_node->port);
                                    char tmp_hex[MSG_CHUNK_SIZE_1024*2+1] = { 0 };

                                    log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                                        "(msg: %s) %s",
                                        msg->uuid, sodium_bin2hex(tmp_hex, MSG_CHUNK_SIZE_1024*2+1, enc_buffer, MSG_CHUNK_SIZE_1024));
                                    
                                    sll_append(void_ptr, node_key->network->out_events, (void*)enc_buffer);                                    
                                    ret = true;
                                    _np_network_start(node_key->network, false);
#ifdef DEBUG
                                    if(!node_key->network->is_running){
                                        log_debug_msg(LOG_NETWORK | LOG_DEBUG, "msg (%s) cannot be send (now) as network is not running", msg->uuid);
                                    }
#endif
                                } else {
                                    ret = false;
                                    log_debug_msg(LOG_INFO, "Dropping data package for msg %s due to not initialized out_events", msg->uuid);
                                    np_memory_free(context, enc_buffer);
                                }
                            }
                        }

                        np_unref_obj(np_messagepart_t, msg_part, "np_tryref_obj_iter->val");
                        if (ret == false) {
                            break;
                        }
                        pll_next(iter);

                    }
                }
            }
            np_unref_obj(np_network_t, node_key_network, FUNC);
        }
    } else {
        log_debug_msg(LOG_WARN | LOG_HANDSHAKE, "network and handshake status of target is unclear (key: %s)", _np_key_as_str(node_key));
        // _np_network_send_handshake(context, node_key, false, NULL);
    }
    np_unref_obj(np_node_t, target_node, FUNC);

    if (ret) {
        _np_message_trace_info("out", msg);
    }
    return ret;
}

void _np_network_send_from_events (struct ev_loop *loop, ev_io *event, int revents)
{		
    np_ctx_decl(ev_userdata(loop));
    // np_tryref_obj(np_key_t, event->data, key_available, key);

    NP_CAST(event->data, np_key_t, key);

    // if (key_available) 
    // {
        np_network_t* key_network = _np_key_get_network(key);
        // np_tryref_obj(np_network_t, key->network, key_network_available, key_network);
        // if (key_network) {
            if (!FLAG_CMP(revents, EV_ERROR) && FLAG_CMP(revents, EV_WRITE))
            {
                // _LOCK_ACCESS(&key_network->out_events_lock)
                // {
                    if (key_network->out_events != NULL)
                    {
                        /*
                            a) if a data packet is available, try to send it until
                                a.1) timeout has been reached
                                a.2) the retry for a paket has been reached
                                a.3) the whole paket has been send
                        */
                        void* data_to_send = NULL;
                        // int data_counter = 0;
                        ssize_t written_per_data = 0, current_write_per_data = 0;
                        // double timeout = np_time_now() + 1.;
                        // do {
                            data_to_send = sll_head(void_ptr, key_network->out_events);
                            // written_per_data = 0;

                            if (data_to_send != NULL)
                            {
                            //     int retry = 1;
                            //     do {

                                    /*
                                    Prep for UDP Passive
                                    if (FLAG_CMP(key_network->socket_type, PASSIVE))
                                    {
                                        current_write_per_data = sendTo(
                                        key_network->socket,
                                        (((char*)data_to_send) + written_per_data),
                                            MSG_CHUNK_SIZE_1024 - written_per_data,
        #ifdef MSG_NOSIGNAL
                                            MSG_NOSIGNAL
        #else
                                            0
        #endif
                                        );
                                    }
                                    else {
                                    */
                                    current_write_per_data = send(
                                        key_network->socket,
                                        (((char*)data_to_send) + written_per_data),
                                        MSG_CHUNK_SIZE_1024 - written_per_data,
#ifdef MSG_NOSIGNAL
                                        MSG_NOSIGNAL
#else								
                                        0
#endif
                                    );
                                    // }
                                    // if (current_write_per_data < 0) {
                                    //     np_time_sleep(NP_SLEEP_MIN);
                                    // }
                                    if (current_write_per_data > 0)
                                    {
                                        written_per_data += current_write_per_data;
                                        _np_statistics_add_send_bytes(current_write_per_data);
                                    }
                                // } while (written_per_data < MSG_CHUNK_SIZE_1024 && retry-- > 0);
#ifdef DEBUG 
                                // if (retry != 10) {
                                //     log_debug_msg(LOG_DEBUG | LOG_NETWORK, "send package in %"PRId32" parts", 10 - retry);
                                // }
#endif

                                if (written_per_data != MSG_CHUNK_SIZE_1024) {
                                    log_msg(LOG_DEBUG | LOG_WARN,
                                        "Could not send package %p fully (%"PRIu32"/%"PRIu32") %s (%d)",
                                        data_to_send,
                                        written_per_data, MSG_CHUNK_SIZE_1024,
                                        strerror(errno), errno);
                                }
                                else {
                                    key_network->last_send_date = np_time_now();
                                    log_debug_msg(LOG_DEBUG | LOG_NETWORK, "Did send package %p via %p -> %d", data_to_send, key_network, key_network->socket);
                                }
                                np_memory_free(context, data_to_send);
                            }
                        // } while (written_per_data > 0 && data_counter++ < NP_NETWORK_MAX_MSGS_PER_SCAN_OUT && np_time_now() < timeout);

#ifdef DEBUG 
                        if (sll_size(key_network->out_events) > 0)
                            log_debug_msg(LOG_DEBUG | LOG_NETWORK, "%"PRIu32" packages still in delivery", sll_size(key_network->out_events));
#endif
                    }
                // }
            }
            /*
            else if (EV_READ == (revents & EV_READ))
            {
                log_debug_msg(LOG_NETWORK | LOG_DEBUG, "unexpected event type");
            }
            else
            {
                log_debug_msg(LOG_DEBUG, "should never happen");
            }*/

            // will only stop if queue is empty and a specific time has been lapsed
            _np_network_stop(key_network, false);

            // np_unref_obj(np_network_t, key_network, FUNC);
        // }
    //     np_unref_obj(np_key_t, key, FUNC);
    // }
}

void _np_network_accept(struct ev_loop *loop, ev_io *event, int revents)
{
    np_ctx_decl(ev_userdata(loop));

    if ((EV_ERROR & revents) == EV_ERROR)
    {
        log_debug_msg(LOG_NETWORK | LOG_DEBUG, "got invalid tcp accept event");
        return;
    }
    // calling address and port
    char ipstr[CHAR_LENGTH_IP] = { 0 };
    char port[CHAR_LENGTH_PORT] = { 0 };

    struct sockaddr_storage from = { 0 };
    socklen_t fromlen = sizeof(from);

    //np_state_t* state = context;
    //np_network_t* ng = state->my_node_key->network;
    np_key_t* key = (np_key_t*)event->data; // state->my_node_key->network;
    np_tryref_obj(np_key_t, key, keyExists, cached_key, "np_tryref_obj_key");
    if (keyExists)
    {
        np_tryref_obj(np_network_t, cached_key->network, server_networkExists, ng, "np_tryref_obj_key_network");		
        if (server_networkExists)
        {
            int client_fd = accept(ng->socket, (struct sockaddr*)NULL, NULL);

            if (client_fd < 0) {
                if (errno != EWOULDBLOCK && errno != EAGAIN) {
                    log_msg(LOG_ERROR,
                        "Could not accept socket connection on client fd %d. %s (%d)"
                        , ng->socket, strerror(errno), errno);
                }
            }
            else 
            {
                log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                    "accept socket from %d -> client fd: %d",
                    ng->socket, client_fd
                );
                int optval;
                optval = 1;
                if (setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
                    log_msg(LOG_NETWORK | LOG_WARN, "setsockopt (SO_KEEPALIVE): %s: ", strerror(errno));
                }
                else
                {
                    //if (ng->ip == NULL || ng->port == NULL)
                    {
                        int err = -1;
                        do {
                            err = getpeername(client_fd, (struct sockaddr*) &from, &fromlen);
                        } while (0 != err && errno != ENOTCONN);

                        if (from.ss_family == AF_INET)
                        {
                            log_debug_msg(LOG_NETWORK | LOG_DEBUG, "connection is IP4");
                            // AF_INET
                            struct sockaddr_in *s = (struct sockaddr_in *) &from;
                            snprintf(port, CHAR_LENGTH_PORT, "%d", ntohs(s->sin_port));
                            inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
                        }
                        else
                        {
                            log_debug_msg(LOG_NETWORK | LOG_DEBUG, "connection is IP6");
                            // AF_INET6
                            struct sockaddr_in6 *s = (struct sockaddr_in6 *) &from;
                            snprintf(port, CHAR_LENGTH_PORT, "%d", ntohs(s->sin6_port));
                            inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
                        }

                        if(strncmp(ng->ip, ipstr, strnlen(ipstr, CHAR_LENGTH_IP - 1))!=0)
                            memcpy(ng->ip, ipstr, strnlen(ipstr, CHAR_LENGTH_IP - 1));

                        if (strncmp(ng->port, port, strnlen(port, CHAR_LENGTH_PORT - 1)) != 0)
                            memcpy(ng->port, port, strnlen(port, CHAR_LENGTH_PORT - 1));
                    }

                    log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                        "received connection request from %s:%s (client fd: %d, source fd: %d)",
                        ipstr, port, client_fd, ng->socket);

                    np_dhkey_t search_key = np_dhkey_create_from_hostport(ipstr, port);
                    np_key_t* alias_key = _np_keycache_find(context, search_key);
                    char* alias_key_reason = "_np_keycache_find";
                    np_network_t* old_network = NULL;
                    _LOCK_MODULE(np_network_t)
                    {
                        if (alias_key != NULL) {
                            old_network = alias_key->network;
                        }
                        else {
                            // init new alias key
                            alias_key = _np_keycache_create(context, search_key);
                            alias_key_reason = "_np_keycache_create";                             
                            np_ref_switch(np_key_t, alias_key->parent_key, ref_key_parent, key);
                        }
                        np_new_obj(np_network_t, alias_key->network);

                        _LOCK_ACCESS(&alias_key->network->access_lock) {
                            alias_key->network->socket = client_fd;
                            alias_key->network->socket_type = ng->socket_type;
                            alias_key->network->seqend = 0;

                            // it could be a passive socket
                            sll_init(void_ptr, alias_key->network->out_events);

                            // set non blocking
                            int current_flags = fcntl(client_fd, F_GETFL);
                            current_flags |= O_NONBLOCK;
                            fcntl(client_fd, F_SETFL, current_flags);

                            alias_key->network->initialized = true;
                            alias_key->network->type = np_network_type_server;
                        }
                        _LOCK_ACCESS(&alias_key->network->waiting_lock) {
                            alias_key->network->waiting = np_tree_create();
                        }
                    }

                    _np_network_set_key(alias_key->network, alias_key);
                    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "%p -> %d network is receiving2", alias_key->network, alias_key->network->socket);

                    ev_io_init(
                        &alias_key->network->watcher,
                        _np_network_read,
                        alias_key->network->socket,
                        EV_READ
                    );
                    _np_network_enable(alias_key->network);

                    if (old_network != NULL) {
                        np_unref_obj(np_network_t, old_network, ref_key_network);
                    }

                    log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                        "created network for key: %s and watching it.", _np_key_as_str(alias_key));

                    np_unref_obj(np_key_t, alias_key, alias_key_reason);
                }

            }
            np_unref_obj(np_network_t, ng, "np_tryref_obj_key_network");
        }
        np_unref_obj(np_key_t, cached_key, "np_tryref_obj_key");
    }
}

struct __np_network_data {
    struct sockaddr_storage from;
    char ipstr[CHAR_LENGTH_IP];
    char port[CHAR_LENGTH_PORT];
    void* data;
    int16_t in_msg_len;
    np_network_t* ng_tcp_host;
    np_key_t* key;
};

void _np_network_bidirektional(struct ev_loop *loop, ev_io *event, int revents) {

    if (!FLAG_CMP(revents, EV_ERROR)) 
    {
        if (FLAG_CMP(revents, EV_READ))
        {
            _np_network_read(loop, event, revents);
        }
        if (FLAG_CMP(revents, EV_WRITE))
        {
            _np_network_send_from_events(loop, event, revents);
        }
    }
}

/**
 ** _np_network_read:
 ** reads the network layer in listen mode.
 ** This function delivers incoming messages to the default message handler
 **/
void _np_network_read(struct ev_loop *loop, ev_io *event, NP_UNUSED int revents)
{
    np_ctx_decl(ev_userdata(loop));

    // cast event data structure to np_state_t pointer

    socklen_t fromlen = sizeof(struct sockaddr_storage);
    // calling address and port

    NP_CAST(event->data, np_key_t, key); 

    /* receive the new data */
    int last_recv_result = 0;
    int msgs_received = 0;

    // catch multiple msgs waiting in this pipe
    // double timeout_start = np_time_now();

    // do {
        np_network_t* ng = _np_key_get_network(key);

        struct __np_network_data * data_container = calloc(1, sizeof(struct __np_network_data));
        data_container->key = key;
        data_container->data = np_memory_new(context, np_memory_types_BLOB_1024);

        int16_t in_msg_len = 0;

        // catch a msg even if it was chunked into smaller byte parts by the underlying network
        // do {
            if (FLAG_CMP(ng->socket_type, TCP)) {
                last_recv_result = recv(event->fd, ((char*)data_container->data)+in_msg_len, MSG_CHUNK_SIZE_1024 - in_msg_len, 0);
            } 
            else
            {
                last_recv_result = recvfrom(event->fd, ((char*)data_container->data) + in_msg_len,
                    MSG_CHUNK_SIZE_1024 - in_msg_len, 0, (struct sockaddr*) &data_container->from, &fromlen);
            }

            if (last_recv_result < 0) {
                np_memory_free(context, data_container->data);
                free(data_container);
        		return;
            }
            in_msg_len += last_recv_result;
            _np_statistics_add_received_bytes(last_recv_result);
            // repeat if msg is not 1024 bytes in size and the timeout is not reached
        // } while (in_msg_len > 0 && in_msg_len < MSG_CHUNK_SIZE_1024 && (np_time_now() - timeout_start) < NETWORK_RECEIVING_TIMEOUT_SEC);

        // already done when tcp accepting the connection
        // if (FLAG_CMP(ng->socket_type, TCP)) { // if our own socket is tcp use peername to get the remote IP
        //     if (in_msg_len >= 0) {
        //         uint8_t retry = 2;
        //         int peer_result=0;
        //         do {
        //             if (peer_result != 0) 
        //             {
        //                 np_time_sleep(NP_SLEEP_MIN);
        //             }
        //             peer_result = getpeername(event->fd, (struct sockaddr*) &data_container->from, &fromlen);
        //         } while ((peer_result != 0 || peer_result == EAGAIN) && retry-- != 0);

        //         if (0 != peer_result) {
        //             log_msg(LOG_WARN, "could not receive socket peer: %s (%d)",
        //                 strerror(errno), errno);
        //             np_memory_free(context, data_container->data);
        //             free(data_container);
        //             return;
        //         }
        //         key = key->parent_key; // and then use the parent key for input handling
        //         data_container->ng_tcp_host = ng;
        // }
        //     if (key != NULL) ng = _np_key_get_network(key); // update ng to be on the safe side
        // }

        log_debug_msg(LOG_DEBUG | LOG_NETWORK, "in_msg_len %"PRIi16" bytes via (fd: %d) ", in_msg_len, event->fd);

        if (in_msg_len == MSG_CHUNK_SIZE_1024) {
            
            msgs_received++;
            data_container->in_msg_len = in_msg_len;

            if (data_container->from.ss_family == AF_INET)
            {
                log_debug_msg(LOG_NETWORK | LOG_DEBUG, "connection is IP4");
                // AF_INET
                struct sockaddr_in *s = (struct sockaddr_in *) &data_container->from;
                snprintf(data_container->port, CHAR_LENGTH_PORT-1, "%d", ntohs(s->sin_port));
                inet_ntop(AF_INET, &s->sin_addr, data_container->ipstr, sizeof data_container->ipstr);
            }
            else
            {
                log_debug_msg(LOG_NETWORK | LOG_DEBUG, "connection is IP6");
                // AF_INET6
                struct sockaddr_in6 *s = (struct sockaddr_in6 *) &data_container->from;
                snprintf(data_container->port, CHAR_LENGTH_PORT-1, "%d", ntohs(s->sin6_port));
                inet_ntop(AF_INET6, &s->sin6_addr, data_container->ipstr, sizeof data_container->ipstr);
            }

            // we registered this token info before in the first handshake message
            np_dhkey_t search_key = np_dhkey_create_from_hostport( data_container->ipstr, data_container->port);
            np_key_t* alias_key = _np_keycache_find(context, search_key);

            np_util_event_t in_event = { .type=evt_external|evt_message, .user_data=data_container->data, 
                                         .context=context, .target_dhkey=search_key };

            if (NULL == alias_key || FLAG_CMP(ng->socket_type, TCP) )
            {
                // TODO: always enqueue via jobqueue
                np_util_statemachine_invoke_auto_transition(&key->sm, in_event);
            }
            else if (NULL != alias_key )
            {
                // TODO: always enqueue via jobqueue
                np_util_statemachine_invoke_auto_transition(&alias_key->sm, in_event);
            }
            else
            {
                log_debug_msg(LOG_ERROR, "network in unknown state for key %s", _np_key_as_str(key) );
            }
            
        }
        else 
        {
            log_debug_msg(LOG_INFO | LOG_NETWORK, "Dropping data package due to invalid package size (%"PRIu16")", in_msg_len);
            np_memory_free(context, data_container->data);
            free(data_container);
        }

    // there may be more then one msg in our socket pipeline
    // } while (msgs_received < NP_NETWORK_MAX_MSGS_PER_SCAN_IN && last_recv_result > 0 && (np_time_now() - timeout_start) < NETWORK_RECEIVING_TIMEOUT_SEC);
    
}
    

void _np_network_handle_incomming_data(np_state_t* context, np_jobargs_t args) {
    log_debug_msg(LOG_TRACE, "_np_network_handle_incomming_data");

    struct __np_network_data * data_container = args.custom_data;
    np_network_t* ng = data_container->key->network;

    // deal with both IPv4 and IPv6:
    {
        if (strncmp(ng->ip, data_container->ipstr, strnlen(data_container->ipstr, CHAR_LENGTH_IP - 1)) != 0)
            memcpy(ng->ip, data_container->ipstr, strnlen(data_container->ipstr, CHAR_LENGTH_IP-1));
        
        if (strncmp(ng->port, data_container->port, strnlen(data_container->port, CHAR_LENGTH_PORT - 1)) != 0)
            memcpy(ng->port, data_container->port, strnlen(data_container->port, CHAR_LENGTH_PORT-1));
    }

    if (0 == data_container->in_msg_len)
    {        
        log_debug(LOG_NETWORK, "Received 0 size package");
        np_memory_free(context, data_container->data);
    }
    else 
    {
        if (data_container->in_msg_len != MSG_CHUNK_SIZE_1024 && data_container->in_msg_len != (MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40))
        {
            log_msg(LOG_NETWORK | LOG_WARN, "received wrong message size (%"PRIi16")", data_container->in_msg_len);
            // job_submit_event(state->job, 0.0, _np_network_read);
            log_debug_msg(LOG_INFO, "Dropping data package due to invalid package size (%"PRIi16")", data_container->in_msg_len);
            np_memory_free(context, data_container->data);
        }
        else
        {
            np_key_t* alias_key = NULL;
            char* alias_key_ref_reason = "";

            // we registered this token info before in the first handshake message
            np_dhkey_t search_key = np_dhkey_create_from_hostport( data_container->ipstr, data_container->port);
            alias_key = _np_keycache_find(context, search_key);
            alias_key_ref_reason = "_np_keycache_find";
            if (NULL == alias_key) {
                alias_key = _np_keycache_create(context, search_key);
                alias_key_ref_reason = "_np_keycache_create";
                alias_key->type |= np_key_type_alias;                
                np_ref_switch(np_key_t, alias_key->parent_key, ref_key_parent, data_container->key);
            }
            
            if(alias_key->network != NULL) alias_key->network->last_received_date = np_time_now();

            if (alias_key->in_destroy == false) {
                log_debug_msg(LOG_NETWORK | LOG_DEBUG, "received message from (%d) %s:%s (size: %hd), insert into alias %s",
                    ng->socket, data_container->ipstr, data_container->port, data_container->in_msg_len, _np_key_as_str(alias_key));
            
                _np_in_received(context, alias_key, data_container->data);
            }
            else {
                np_memory_free(context, data_container->data);
                log_debug_msg(LOG_NETWORK | LOG_DEBUG, "received message from %s:%s (size: %hd), but alias is in destroy %s",
                    data_container->ipstr, data_container->port, data_container->in_msg_len, _np_key_as_str(alias_key));
            }

            np_unref_obj(np_key_t, alias_key, alias_key_ref_reason);
        }
    }
    free(data_container);
}

void _np_network_stop(np_network_t* network, bool force) {		    
    assert(NULL != network);

    np_ctx_memory(network);
    _LOCK_ACCESS(&network->out_events_lock) {
        _LOCK_ACCESS(&network->access_lock) {

            // double last_send_diff = np_time_now() - network->last_send_date;
            EV_P;

            if ( (network->is_running == true /*&& last_send_diff >= NP_PI/500 */) &&
                 (force == true || 0 == sll_size(network->out_events)) )
            {
                if (FLAG_CMP(network->type , np_network_type_server)) {
                    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "stopping server network %p", network);
                    loop = _np_event_get_loop_in(context);
                    ev_io_set(&network->watcher, network->socket, EV_READ);
                    if (force == true) {                        
                        ev_io_stop(EV_A_ &network->watcher);
                        _np_event_reconfigure_loop_in(context);
                    }
                }
                if (FLAG_CMP(network->type, np_network_type_client)) {
                    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "stopping client network %p", network);
                    loop = _np_event_get_loop_out(context);
                    ev_io_set(&network->watcher, network->socket, EV_NONE);
                    if (force == true) {
                        ev_io_stop(EV_A_ &network->watcher);
                        _np_event_reconfigure_loop_out(context);
                    }
                }
                network->is_running = false;
            }
        }
    }
}

void _np_network_remap_network(np_key_t* new_target, np_key_t* old_target)
{
    np_ctx_memory(new_target);
    log_debug_msg(LOG_NETWORK | LOG_DEBUG,
            "try to remap network of %s to network of %s",
            _np_key_as_str(old_target),
            _np_key_as_str(new_target)
            );

    assert(old_target->network != NULL);

    np_network_t * old_network = NULL;
    if (new_target->network != NULL) {
        old_network = new_target->network;
    }

    _np_event_suspend_loop_in(context);
    _np_event_suspend_loop_out(context);
    _LOCK_ACCESS(&old_target->network->access_lock) {
        //_np_network_stop(old_target->network); 		// stop network
        new_target->network = old_target->network; 		// remap
        _np_network_set_key(new_target->network, new_target); // remap network key
        old_target->network = NULL;						// remove from old structure
        //_np_network_start(new_target->network); 		// restart network
    }
    _np_event_resume_loop_out(context);
    _np_event_resume_loop_in(context);

    // remove old network referrence (if any)
    if (old_network != NULL) {
        np_unref_obj(np_network_t, old_network, ref_key_network);
    }

    log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                "remap network of %s to network of %s completed",
                _np_key_as_str(old_target),
                _np_key_as_str(new_target)
                );
}

void _np_network_start(np_network_t* network, bool force){

    assert(NULL != network);

    log_trace_msg(LOG_TRACE | LOG_NETWORK, "start: void _np_network_start(np_network_t* network){");
    np_ctx_memory(network);

    np_ref_obj(np_network_t, network, FUNC);
    TSP_GET(bool, network->can_be_enabled, can_be_enabled);
    if (can_be_enabled) {
        NP_PERFORMANCE_POINT_START(network_start_out_events_lock);
        // _LOCK_ACCESS(&network->out_events_lock) {
            NP_PERFORMANCE_POINT_END(network_start_out_events_lock);
            NP_PERFORMANCE_POINT_START(network_start_access_lock);
            // _LOCK_ACCESS(&network->access_lock) {
                NP_PERFORMANCE_POINT_END(network_start_access_lock);

                EV_P;
                if (network->is_running == false)
                {
                    if (FLAG_CMP(network->type , np_network_type_server)) {
                        log_debug_msg(LOG_NETWORK | LOG_DEBUG, "starting server network %p", network);
                        EV_A = _np_event_get_loop_in(context);
                        ev_io_set(&network->watcher, network->socket, EV_READ);
                        if(force == true){							                            
                            ev_io_start(EV_A_ &network->watcher);
                            _np_event_reconfigure_loop_in(context);
                        }
                    }

                    if (FLAG_CMP(network->type, np_network_type_client)) {
                        log_debug_msg(LOG_NETWORK | LOG_DEBUG, "starting client network %p", network);						
                        EV_A = _np_event_get_loop_out(context);
                        ev_io_set(&network->watcher, network->socket, EV_WRITE);
                        if(force == true){
                            ev_io_start(EV_A_ &network->watcher);
                            _np_event_reconfigure_loop_out(context);
                        }						
                    }
                    network->is_running = true;
                }
            // }
        // }
    }
    np_unref_obj(np_network_t, network, FUNC);
}

/**
 * network_destroy
 */
void _np_network_t_del(np_state_t * context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* data)
{
    log_trace_msg(LOG_TRACE | LOG_NETWORK, "start: void _np_network_t_del(void* nw){");
    np_network_t* network = (np_network_t*) data;

    _LOCK_MODULE(np_network_t)
    {
        _LOCK_ACCESS(&network->access_lock)
        {
            _np_network_stop(network, true);
            np_key_t* old_key = (np_key_t*)network->watcher.data;
            //if(old_key) np_unref_obj(np_key_t, old_key, ref_network_watcher);
            network->watcher.data = NULL;

            _LOCK_ACCESS(&network->out_events_lock)
            {

                if (NULL != network->out_events)
                {
                    if (0 < sll_size(network->out_events))
                    {
                        do {
                            void* drop_package = sll_head(void_ptr, network->out_events);
                            log_debug_msg(LOG_INFO, "Dropping data package due to network cleanup");
                            np_memory_free(context, drop_package);
                        } while (0 < sll_size(network->out_events));
                    }
                    sll_free(void_ptr, network->out_events);
                }
            }
            if (0 < network->socket) close (network->socket);

            network->initialized = false;
        }

        _LOCK_ACCESS(&network->waiting_lock)
        {
            if (NULL != network->waiting) {
                np_tree_free(network->waiting);
                network->waiting = NULL;
            }
        }

        // finally destroy the mutex 
        _np_threads_mutex_destroy(context, &network->out_events_lock);
        _np_threads_mutex_destroy(context, &network->access_lock);
        _np_threads_mutex_destroy(context, &network->waiting_lock);

        TSP_DESTROY( network->can_be_enabled);
    }
}

void _np_network_t_new(np_state_t * context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* data)
{
    log_trace_msg(LOG_TRACE | LOG_NETWORK, "start: void _np_network_t_new(void* nw){");
    np_network_t* ng = (np_network_t *) data;
    ng->socket = -1;
    ng->addr_in = NULL;
    ng->waiting 	= NULL;
    ng->out_events 	= NULL;
    ng->initialized = false;
    ng->is_running = false;
    ng->watcher.data = NULL;
    ng->type = np_network_type_none;
    ng->last_send_date = 0.0;
    ng->last_received_date = 0.0;
    ng->seqend = 0;


    ng->ip[0] = 0;
    ng->port[0] = 0;

    _np_threads_mutex_init(context, &ng->access_lock, "network access_lock");
    _np_threads_mutex_init(context, &ng->out_events_lock, "network out_events_lock");
    _np_threads_mutex_init(context, &ng->waiting_lock, "network waiting_lock");

    TSP_INITD( ng->can_be_enabled, true);
}

/** _np_network_init:
 ** initiates the networking layer structures required for a target_node
 ** if the port number is bigger than zero, it will create a socket and bind it to #port#
 ** the type defines the protocol which is used by the target_node (@see socket_type)
 *
 * if "prepared_socket_fd" > 0 no new connection will be created, instead the client_fd will be set to "prepared_socket_fd"
 **/
bool _np_network_init(np_network_t* ng, bool create_server, enum socket_type type, char* hostname, char* service, int prepared_socket_fd, enum socket_type passive_socket_type)
{
    np_ctx_memory(ng);
    int one = 1;
    int v6_only = 0;

    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "try to get_network_address");
    _np_network_get_address(context, create_server, &ng->addr_in, type, hostname, service);
    ng->socket_type = type | passive_socket_type;
    if (NULL == ng->addr_in)
    {
        log_msg(LOG_ERROR, "could not receive network address");
        return false;
    }
    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "done get_network_address");

    // only need for client setup, but initialize to have zero size of list
    if (ng->out_events == NULL) sll_init(void_ptr, ng->out_events);

    // create an inbound socket - happens only once per target_node
    if (true == create_server)
    {
        log_debug_msg(LOG_NETWORK | LOG_DEBUG, "creating receiving network");

        _LOCK_ACCESS(&ng->access_lock)
        {
            ng->type |= np_network_type_server;
            // own sequence number counter
            ng->seqend = 0;
        }

        // create own retransmit structures
        _LOCK_ACCESS(&ng->waiting_lock) {
            if (ng->waiting == NULL) ng->waiting = np_tree_create();
        }

        // server setup - create socket
        // UDP note: not using a connected socket for sending messages to a different target_node
        // leads to unreliable delivery. The sending socket changes too often to be useful
        // for finding the correct decryption shared secret. Especially true for ipv6 ...
        if (!FLAG_CMP(type, PASSIVE)) {
            if (prepared_socket_fd > 0) {
                ng->socket = prepared_socket_fd;
            }
            else {
                ng->socket = socket(ng->addr_in->ai_family, ng->addr_in->ai_socktype, ng->addr_in->ai_protocol);
                if (0 > ng->socket)
                {
                    log_msg(LOG_ERROR, "could not create socket: %s", strerror(errno));
                    return false;
                }
            }

            if (-1 == setsockopt(ng->socket, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one)))
            {
                log_msg(LOG_ERROR, "setsockopt (SO_REUSEADDR): %s: ", strerror(errno));
                __np_network_close(ng);
                return false;
            }

            if (FLAG_CMP(type, IPv6)) {
                if (-1 == setsockopt(ng->socket, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only)))
                {
                    // enable ipv4 mapping
                    log_msg(LOG_NETWORK | LOG_WARN, "setsockopt (IPV6_V6ONLY): %s: ", strerror(errno));
                }
            }
            // set non blocking
            int current_flags = fcntl(ng->socket, F_GETFL);
            current_flags |= O_NONBLOCK;
            fcntl(ng->socket, F_SETFL, current_flags);

            /* attach socket to #port#. */
            if (0 > bind(ng->socket, ng->addr_in->ai_addr, ng->addr_in->ai_addrlen))
            {
                log_msg(LOG_ERROR, "bind failed for %s:%s: %s", hostname, service, strerror(errno));
                __np_network_close(ng);
                // listening port could not be opened
                return false;
            }

            if (FLAG_CMP(type, TCP)) {
                if (0 > listen(ng->socket, 10)) {
                    log_msg(LOG_ERROR, "listen on tcp port failed: %s:", strerror(errno));
                    __np_network_close(ng);
                    return false;
                }
                log_debug_msg(LOG_NETWORK | LOG_DEBUG, "%p -> %d network is receiving accepts", ng, ng->socket);
                ev_io_init(&ng->watcher, _np_network_accept, ng->socket, EV_READ);
            }
            else if (FLAG_CMP(type, UDP))
            {
                log_debug_msg(LOG_NETWORK | LOG_DEBUG, "%p -> %d network is receiving", ng, ng->socket);
                ev_io_init(&ng->watcher, _np_network_read, ng->socket, EV_READ);
            }
            else {
                log_debug_msg(LOG_NETWORK | LOG_DEBUG, "Dont know how to setup server network of type %"PRIu8, type);
            }
        }
        ng->initialized = true;
        log_debug_msg(LOG_NETWORK | LOG_DEBUG, "created local listening socket");
    }
    else 
    {
        log_debug_msg(LOG_NETWORK | LOG_DEBUG, "creating sending network");

        ng->type |= np_network_type_client;

        if (!FLAG_CMP(type, PASSIVE)) 
        {
            // client socket - wait for writeable socket
            if (prepared_socket_fd > 0) {
                ng->socket = prepared_socket_fd;
            }
            else {
                ng->socket = socket(ng->addr_in->ai_family, ng->addr_in->ai_socktype, ng->addr_in->ai_protocol);

                if (0 > ng->socket)
                {
                    log_msg(LOG_ERROR, "could not create socket: %s", strerror(errno));
                    return false;
                }

                if (-1 == setsockopt(ng->socket, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one)))
                {
                    log_msg(LOG_ERROR, "setsockopt (SO_REUSEADDR): %s: ", strerror(errno));
                    __np_network_close(ng);
                    return false;
                }
                if (FLAG_CMP(type, IPv6)) {
                    if (-1 == setsockopt(ng->socket, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only)))
                    {
                        // enable ipv4 mapping
                        log_msg(LOG_NETWORK | LOG_WARN, "setsockopt (IPV6_V6ONLY): %s: ", strerror(errno));
                    }
                }
                int optval;
                if ((type & TCP) == TCP) {
                    optval = 1;
                    if (setsockopt(ng->socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
                        log_msg(LOG_NETWORK | LOG_WARN, "setsockopt (SO_KEEPALIVE): %s: ", strerror(errno));
                    }
                }
                // set non blocking
                int current_flags = fcntl(ng->socket, F_GETFL);
                current_flags |= O_NONBLOCK;
                fcntl(ng->socket, F_SETFL, current_flags);
            }

            // initialize to be on the safe side
            ng->watcher.data = NULL;
            if (FLAG_CMP(type, TCP) || FLAG_CMP(type, UDP))
            {
                np_network_t* my_network = _np_key_get_network(context->my_node_key);
                if (FLAG_CMP(my_network->socket_type, PASSIVE)) 
                {
                    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "%p -> %d network is bidirektional", ng, ng->socket);
                    ev_io_init(
                        &ng->watcher, _np_network_bidirektional,
                        ng->socket, EV_WRITE | EV_READ);
                }
                else
                {
                    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "%p -> %d network is sender", ng, ng->socket);
                    ev_io_init(
                        &ng->watcher, _np_network_send_from_events,
                        ng->socket, EV_WRITE);
                }
            }
            else {
                log_debug_msg(LOG_NETWORK | LOG_DEBUG, "Dont know how to setup client network of type %"PRIu8, type);
            }

            // UDP note: not using a connected socket for sending messages to a different target_node
            // leads to unreliable delivery. The sending socket changes too often to be useful
            // for finding the correct decryption shared secret. Especially true for ipv6 ...

            // As we do have a async connection (and TCP may need longer due to
            // handshake packages) we need to check the connection status for a moment
            if (prepared_socket_fd < 1) 
            {
                int retry_connect = 3;
                int connection_status = -1;
                do {
                    connection_status = connect(
                        ng->socket, ng->addr_in->ai_addr, ng->addr_in->ai_addrlen);

                    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "TRY CONNECT: %"PRIi32, connection_status);
                    if (connection_status != 0) 
                    {
                        np_time_sleep(NP_PI / 10);
                    }
                } while (0 != connection_status && retry_connect-- > 0);

                if (0 != connection_status) {
                    if (errno != EISCONN) {
                        log_msg(LOG_ERROR,
                            "could not connect: %s (%d)", strerror(errno), errno);
                        __np_network_close(ng);
                        return false;
                    }
                }
            }
            log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                "network: %d %p %p :", ng->socket, &ng->watcher, &ng->watcher.data);
        }
        ng->initialized = true;
        log_debug_msg(LOG_NETWORK | LOG_DEBUG, "created local sending socket");
    }
    freeaddrinfo(ng->addr_in);
    ng->addr_in = NULL;

    log_debug_msg(LOG_DEBUG,
        "Inited %s-network %s %s on %s:%s (fd: %d%s)",
        create_server ? "Server" : "Client",
        FLAG_CMP(type, TCP) ? "TCP" : FLAG_CMP(type, UDP) ? "UDP" : "?",
        FLAG_CMP(type, PASSIVE) ? "PASSIVE" : "",
        hostname,
        service,
        ng->socket,
        prepared_socket_fd > 0 ? " (prepared fd)" : ""
    );
    return true;
}


/*
char* test(char* t,int q, char* ip, char* port ) {

    return t;
}
*/
char* np_network_get_desc(np_key_t * container, char* buffer) {
    char* ret = buffer;
    if (ret == NULL) ret = malloc(255);

    char* ip = np_network_get_ip(container, buffer);
    int slen = strnlen(ip, 233);
    buffer[slen] = ':';
    np_network_get_port(container, buffer + slen+1);

    return ret;
}
char* np_network_get_port(np_key_t * container, char* buffer) {
    char* ret = buffer;
    if (ret == NULL) ret = malloc(20);

    char *port = NULL;

    if (container->network != NULL && container->network->initialized && strncmp(container->network->port, "", 1) != 0) {
        port = container->network->port;
    }
    else if (container->parent_key != NULL && container->parent_key->network != NULL && container->parent_key->network->initialized && strncmp(container->parent_key->network->port, "", 1) != 0) {
        port = container->parent_key->network->port;

    }
    else if (container->node != NULL && container->node->port != NULL) {
        port = container->node->port;
    }
    else if (container->parent_key != NULL && container->parent_key->node != NULL && container->parent_key->node->port != NULL) {
        port = container->parent_key->node->port;
    }

    if (port != NULL) {
        snprintf(ret , 20 , "%s",  port);
    }
    else {
        snprintf(ret, 20, "?");
    }

    return ret;
}
char* np_network_get_ip(np_key_t * container, char* buffer) {
    char* ret = buffer;
    if (ret == NULL) ret = malloc(245);

    char *ip = NULL;

    if (container->network != NULL && container->network->initialized && strncmp(container->network->port, "", 1) != 0) {
        ip = container->network->ip;
    }
    else if (container->parent_key != NULL && container->parent_key->network != NULL && container->parent_key->network->initialized && strncmp(container->parent_key->network->port, "", 1) != 0) {
        ip = container->parent_key->network->ip;
    }
    else if (container->node != NULL && container->node->port != NULL) {
        ip = container->node->dns_name;
    }
    else if (container->parent_key != NULL && container->parent_key->node != NULL && container->parent_key->node->port != NULL) {
        ip = container->parent_key->node->dns_name;
    }

    if (ip != NULL) {
        snprintf(ret, 255, "%s", ip);
    }
    else {
        snprintf(ret, 255, "?.?.?.?");
    }

    return ret;
}

void _np_network_disable(np_network_t* self) {
    if (self != NULL) {
        np_ctx_memory(self);
        TSP_SET(self->can_be_enabled, false);
        _np_network_stop(self, true);
    }
}


void _np_network_enable(np_network_t* self)
{
    if (self != NULL) {
        np_ctx_memory(self);
        TSP_SET(self->can_be_enabled, true);
        _np_network_start(self, true);
    }
}

void _np_network_set_key(np_network_t* self, np_key_t* key) {
    self->watcher.data = key; 
}
