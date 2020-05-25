//
// neuropil is copyright 2016-2020 by pi-lar GmbH
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
#include "np_dhkey.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_memory.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_event.h"
#include "np_types.h"
#include "np_constants.h"
#include "np_settings.h"
#include "np_util.h"
#include "np_statistics.h"

static char* URN_TCP_V4 = "tcp4";
static char* URN_TCP_V6 = "tcp6";
static char* URN_PAS_V4 = "pas4";
static char* URN_PAS_V6 = "pas6";
static char* URN_UDP_V4 = "udp4";
static char* URN_UDP_V6 = "udp6";
static char* URN_IP_V4  = "ip4";
static char* URN_IP_V6  = "ip6";

typedef struct _np_network_data_s {
    np_network_t* network;
    np_dhkey_t owner_dhkey;
} _np_network_data_t;


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
    int proto;

    if(sscanf(protocol_str, "%d", &proto) == 1){
        return proto;
    }
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

    if (FLAG_CMP(type, IPv4) ) {
        hints.ai_family = PF_INET;
    }
    if (FLAG_CMP(type, IPv6) ) {
        hints.ai_family = PF_INET6;
    }
    if (FLAG_CMP(type, UDP) ) {
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
    }
    if (FLAG_CMP(type, TCP) ) {
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

void _np_network_write (struct ev_loop *loop, ev_io *event, int revents)
{
    np_ctx_decl(ev_userdata(loop));

    if (FLAG_CMP(revents, EV_ERROR) || FLAG_CMP(revents, EV_READ))
    {
        log_debug_msg(LOG_NETWORK | LOG_DEBUG, "got invalid write event");
        return;
    }
    
    if (event->data == NULL) return;
    np_network_t* network = ((_np_network_data_t*)event->data)->network;

    _TRYLOCK_ACCESS(&network->access_lock)
    {
        /*
            a) if a data packet is available, try to send it until
                a.1) timeout has been reached
                a.2) the retry for a paket has been reached
                a.3) the whole paket has been send
        */
        void* data_to_send = NULL;
        ssize_t written_per_data = 0, current_write_per_data = 0;
        data_to_send = sll_head(void_ptr, network->out_events);

        if (data_to_send != NULL)
        {
            if (!FLAG_CMP(network->socket_type, PASSIVE)) {
                current_write_per_data = send(network->socket,
                                              (((char*)data_to_send) + written_per_data),
                                              MSG_CHUNK_SIZE_1024 - written_per_data,
    #ifdef MSG_NOSIGNAL
                                            MSG_NOSIGNAL
    #else
                                            0
    #endif
                                        );
            } else {
                current_write_per_data = sendto(network->socket,
                                                (((char*)data_to_send) + written_per_data),
                                                MSG_CHUNK_SIZE_1024 - written_per_data,
    #ifdef MSG_NOSIGNAL
                                                MSG_NOSIGNAL,
    #else
                                                0,
    #endif
                                                network->remote_addr,
                                                network->remote_addr_len);
            }

            if (current_write_per_data == MSG_CHUNK_SIZE_1024)
            {
#ifdef DEBUG
                char msg_hex[2*written_per_data+1];
                sodium_bin2hex(msg_hex, 2*written_per_data+1, data_to_send, written_per_data);
                log_debug(LOG_NETWORK, "Did send    data (%"PRIi16" bytes) via fd: %d hex: %.5s...%s", current_write_per_data, network->socket, msg_hex, msg_hex + strlen(msg_hex) - 5);
#endif
                written_per_data += current_write_per_data;
                _np_statistics_add_send_bytes(current_write_per_data);

                np_memory_free(context, data_to_send);
                network->last_send_date = np_time_now();

                log_debug(LOG_NETWORK, "Did send package %p via %p -> %d", data_to_send, network, network->socket);
            } 
            else {
                log_debug(LOG_NETWORK,
                    "Could not send package %p fully (%"PRIu32"/%"PRIu32") %s (%d)",
                    data_to_send, written_per_data, MSG_CHUNK_SIZE_1024,
                    strerror(errno), errno);
                sll_prepend(void_ptr, network->out_events, data_to_send);
            }
        }
#ifdef DEBUG 
        if (sll_size(network->out_events) > 0)
            log_debug_msg(LOG_DEBUG | LOG_NETWORK, "%"PRIu32" packages still in delivery", sll_size(network->out_events));
#endif
    }
}

struct __np_network_data {
    struct sockaddr_storage from;
    char ipstr[CHAR_LENGTH_IP];
    char port[CHAR_LENGTH_PORT];
    void* data;
    int16_t in_msg_len;
    np_network_t* ng_tcp_host;
};

void __np_network_get_ip_and_port(struct __np_network_data* network_data) 
{
    if (network_data->from.ss_family == AF_INET)
    {
        // AF_INET
        struct sockaddr_in *s = (struct sockaddr_in *) &network_data->from;
        inet_ntop(AF_INET, &s->sin_addr, network_data->ipstr, sizeof network_data->ipstr);
        snprintf(network_data->port, CHAR_LENGTH_PORT, "%d", ntohs(s->sin_port));
    }
    else
    {
        // AF_INET6
        struct sockaddr_in6 *s = (struct sockaddr_in6 *) &network_data->from;
        inet_ntop(AF_INET6, &s->sin6_addr, network_data->ipstr, sizeof network_data->ipstr);
        snprintf(network_data->port, CHAR_LENGTH_PORT, "%d", ntohs(s->sin6_port));
    }
}

void _np_network_accept(struct ev_loop *loop, ev_io *event, int revents)
{
    np_ctx_decl(ev_userdata(loop));

    if (FLAG_CMP(revents, EV_ERROR) || FLAG_CMP(revents, EV_WRITE))
    {
        log_debug_msg(LOG_NETWORK | LOG_DEBUG, "got invalid tcp accept event");
        return;
    }

    struct __np_network_data data_container = {0};
    socklen_t fromlen = sizeof(struct sockaddr_storage);

    np_state_t* state = context;
    np_network_t* ng = ((_np_network_data_t*)event->data)->network;

    int client_fd = accept(ng->socket, (struct sockaddr*) &data_container.from, &fromlen);

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
        __np_network_get_ip_and_port(&data_container);

        np_network_t* new_network = NULL;
        np_new_obj(np_network_t, new_network);

        if (_np_network_init(new_network, true, ng->socket_type, data_container.ipstr, data_container.port, client_fd, UNKNOWN_PROTO))
        {
            // it could be a passive socket
            sll_init(void_ptr, new_network->out_events);

            np_dhkey_t search_key = np_dhkey_create_from_hostport(&data_container.ipstr[0], &data_container.port[0]);
            np_key_t* alias_key = _np_keycache_create(context, search_key);
            
            sll_append(void_ptr, alias_key->entities, new_network);
            // will be reset to alias key after first (handshake) message
            _np_network_set_key(new_network, ((_np_network_data_t*) event->data)->owner_dhkey); 

            log_debug_msg(LOG_NETWORK | LOG_DEBUG, "%p -> %d network is receiving", new_network, new_network->socket);

            _np_network_enable(new_network);
            log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                "created network for key: %s and watching it.", _np_key_as_str(alias_key));
            np_unref_obj(np_key_t, alias_key, "_np_keycache_create");
        }
        else
        {
            np_unref_obj(np_network_t, new_network, ref_obj_creation);
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
    if (FLAG_CMP(revents, EV_ERROR) || FLAG_CMP(revents, EV_WRITE))
    {
        log_debug_msg(LOG_NETWORK | LOG_DEBUG, "got invalid read event");
        return;
    }

    // cast event data structure to np_state_t pointer
    socklen_t fromlen = sizeof(struct sockaddr_storage);
    // calling address and port
    if (event->data == NULL) return;

    np_dhkey_t owner_dhkey = ((_np_network_data_t*)event->data)->owner_dhkey;
    np_network_t* ng = ((_np_network_data_t*)event->data)->network;

    /* receive the new data */
    int last_recv_result = 0;
    uint16_t msgs_received = 0;

    // catch multiple msgs waiting in this pipe
    double timeout_start = np_time_now();
    double network_receive_timeout;
    int16_t in_msg_len;
    bool stop = false;

    //do {

        struct __np_network_data data_container = {0}; // calloc(1, sizeof(struct __np_network_data));
        data_container.data = np_memory_new(context, np_memory_types_BLOB_1024);

        in_msg_len = 0;
        // catch a msg even if it was chunked into smaller byte parts by the underlying network
        //do {
        if (FLAG_CMP(ng->socket_type, TCP)) {
            last_recv_result = recv(event->fd, ((char*)data_container.data)+in_msg_len, MSG_CHUNK_SIZE_1024 - in_msg_len, 0);
            int err = -1;
            do {
                err = getpeername(event->fd, (struct sockaddr*) &data_container.from, &fromlen);
            } while (0 != err && errno != ENOTCONN);
        } 
        else
        {
            last_recv_result = recvfrom(event->fd, ((char*)data_container.data) + in_msg_len,
                MSG_CHUNK_SIZE_1024 - in_msg_len, 0, (struct sockaddr*) &data_container.from, &fromlen);
        }

        if (last_recv_result < 0) {
            log_debug(LOG_NETWORK,"Receive stopped. Reason: %s (%"PRId32"/"PRId32")", strerror(errno),errno, last_recv_result);
            np_memory_free(context, data_container.data);
            stop = true;
        }

        if(!stop){
            __np_network_get_ip_and_port(&data_container);
            in_msg_len += last_recv_result;
            _np_statistics_add_received_bytes(last_recv_result);
            // repeat if msg is not 1024 bytes in size and the timeout is not reached
            network_receive_timeout = (np_time_now() - timeout_start) < NETWORK_RECEIVING_TIMEOUT_SEC;
        }             
        //} while (in_msg_len > 0 && in_msg_len < MSG_CHUNK_SIZE_1024 && network_receive_timeout);

        if(!stop){
            #ifdef DEBUG
            	char msg_hex[2*in_msg_len+1];
            	sodium_bin2hex(msg_hex, 2*in_msg_len+1, data_container.data, in_msg_len);
                log_debug(LOG_NETWORK, "Did receive data (%"PRIi16" bytes) via fd: %d hex: %.5s...%s", in_msg_len, event->fd, msg_hex, msg_hex + strlen(msg_hex) - 5);
            #endif

            if (in_msg_len == MSG_CHUNK_SIZE_1024) 
            {
                msgs_received++;
                data_container.in_msg_len = in_msg_len;

                // we registered this token info before in the first handshake message
                np_dhkey_t search_key = np_dhkey_create_from_hostport(&data_container.ipstr[0], &data_container.port[0]);
                np_key_t*  alias_key  = _np_keycache_find(context, search_key);

                np_util_event_t in_event = { .type=evt_external|evt_message, .user_data=data_container.data, 
                                             .context=context, .target_dhkey=search_key };

                if (NULL == alias_key && FLAG_CMP(ng->socket_type, UDP)) 
                {
                    np_node_t* new_node = NULL;
                    np_new_obj(np_node_t, new_node, FUNC);
                    _np_node_update(new_node, UDP, data_container.ipstr, data_container.port);

                    np_key_t* temp_alias_key = _np_keycache_create(context, search_key);

                    np_util_event_t node_evt = { .context=context,    .type=evt_external, 
                                                 .user_data=new_node, .target_dhkey=search_key };
                    if(!np_jobqueue_submit_event(context, 0.0, search_key, node_evt, "event: externe udp node in")){
                        log_debug(LOG_NETWORK, "rejecting possible udp connection as jobqueue is rejecting it");    
                    }
                    np_unref_obj(np_key_t, temp_alias_key, "_np_keycache_create");
                }

                if (FLAG_CMP(ng->socket_type, TCP) || FLAG_CMP(ng->socket_type, PASSIVE) || NULL == alias_key )
                {
                    if(!np_jobqueue_submit_event(context, 0.0, owner_dhkey, in_event, "event: externe message in")){
                        log_debug(LOG_NETWORK, "Dropping data package as jobqueue is rejecting it");    
                    }
                }
                else if (NULL != alias_key )
                {
                    if(!np_jobqueue_submit_event(context, 0.0, alias_key->dhkey, in_event, "event: externe message in")){
                        log_debug(LOG_NETWORK, "Dropping data package as jobqueue is rejecting it");    
                    }
                }
                else
                {
                    // log_debug_msg(LOG_ERROR, "network in unknown state for key %s", _np_key_as_str(key) );
                }            

                if (NULL != alias_key) np_unref_obj(np_key_t, alias_key, "_np_keycache_find");

            } else {
                if(!network_receive_timeout) {
                    log_info(LOG_NETWORK, "Network receive iteration stopped due to timeout (Received Data: %"PRIu16")", in_msg_len);
                }

                if (in_msg_len == 0)
                {   
                    log_info(LOG_NETWORK, "Stopping network due to zero size package (%"PRIu16")", in_msg_len);
                    _np_network_disable(ng);
                }
                else 
                {
                    log_info(LOG_NETWORK, "Dropping data package due to invalid package size (%"PRIu16")", in_msg_len);
                    np_memory_free(context, data_container.data);
                }
            }
        }
    // there may be more then one msg in our socket pipeline
    //} while (!stop && msgs_received < NP_NETWORK_MAX_MSGS_PER_SCAN_IN && in_msg_len > 0 && network_receive_timeout);
    log_debug(LOG_NETWORK, "Received %"PRIu16" messages in one check", msgs_received);
}

void _np_network_stop(np_network_t* network, bool force) 
{    
    assert(NULL != network);

    np_ctx_memory(network);
    log_trace_msg(LOG_TRACE, "start: void _np_network_stop(...){");

    _LOCK_ACCESS(&network->access_lock) 
    {
        EV_P;
        if (network->is_running == true)
        {
            if (FLAG_CMP(network->type , np_network_type_server)) 
            {
                log_debug_msg(LOG_NETWORK | LOG_DEBUG, "stopping server network %p", network);
                loop = _np_event_get_loop_in(context);
                _np_event_suspend_loop_in(context);
                ev_io_stop(EV_A_ &network->watcher_in);
                // ev_io_set(&network->watcher, network->socket, EV_NONE);
                // ev_io_start(EV_A_ &network->watcher);
                _np_event_reconfigure_loop_in(context);
                _np_event_resume_loop_in(context);
            }

            if (FLAG_CMP(network->type, np_network_type_client))
            {
                log_debug_msg(LOG_NETWORK | LOG_DEBUG, "stopping client network %p", network);
                loop = _np_event_get_loop_out(context);
                _np_event_suspend_loop_out(context);
                ev_io_stop(EV_A_ &network->watcher_out);
                // ev_io_set(&network->watcher, network->socket, EV_NONE);
                // ev_io_start(EV_A_ &network->watcher);
                _np_event_reconfigure_loop_out(context);
                _np_event_resume_loop_out(context);
            }
            network->is_running = false;
        }
    }
}

void _np_network_start(np_network_t* network, bool force)
{
    assert(NULL != network);

    np_ctx_memory(network);
    log_debug_msg(LOG_TRACE, "start: void _np_network_start(...){");

    TSP_GET(bool, network->can_be_enabled, can_be_enabled);
    if (can_be_enabled) {
        NP_PERFORMANCE_POINT_START(network_start_out_events_lock);
        _LOCK_ACCESS(&network->access_lock) {
            NP_PERFORMANCE_POINT_END(network_start_out_events_lock);
            if (network->is_running == false)
            {
                EV_P;
                if (FLAG_CMP(network->type , np_network_type_server)) {
                    log_debug_msg(LOG_DEBUG, "starting server network %p", network);
                    _np_event_suspend_loop_in(context);
                    loop = _np_event_get_loop_in(context);
                    // ev_io_stop(EV_A_ &network->watcher);
                    // ev_io_set(&network->watcher, network->socket, EV_READ);
                    ev_io_start(EV_A_ &network->watcher_in);
                    _np_event_reconfigure_loop_in(context);
                    _np_event_resume_loop_in(context);
                }

                if (FLAG_CMP(network->type, np_network_type_client)) {
                    log_debug_msg(LOG_DEBUG, "starting client network %p", network);
                    _np_event_suspend_loop_out(context);
                    loop = _np_event_get_loop_out(context);
                    // ev_io_stop(EV_A_ &network->watcher);
                    // ev_io_set(&network->watcher, network->socket, EV_WRITE);
                    ev_io_start(EV_A_ &network->watcher_out);
                    _np_event_reconfigure_loop_out(context);
                    _np_event_resume_loop_out(context);
                }
                network->is_running = true;
            }
        }
    }
}

/**
 * network_destroy
 */
void _np_network_t_del(np_state_t * context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* data)
{
    log_trace_msg(LOG_TRACE, "start: void _np_network_t_del(void* nw){");
    np_network_t* network = (np_network_t*) data;

    // network->watcher.data = NULL;
    _LOCK_ACCESS(&network->access_lock)
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

    free(network->watcher_in.data);
    free(network->watcher_out.data);
    free(network->remote_addr);

    if ((0 < network->socket)                                                            && 
        !(FLAG_CMP(network->socket_type, PASSIVE) && FLAG_CMP(network->socket_type, UDP)) )
    {
        close (network->socket);
    }
    network->initialized = false;
    // finally destroy the mutex 
    _np_threads_mutex_destroy(context, &network->access_lock);
    TSP_DESTROY(network->can_be_enabled);
}

void _np_network_t_new(np_state_t * context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* data)
{
    log_trace_msg(LOG_TRACE | LOG_NETWORK, "start: void _np_network_t_new(void* nw){");
    np_network_t* ng = (np_network_t *) data;
    ng->socket = -1;
    ng->addr_in = NULL;
    ng->out_events 	= NULL;
    ng->initialized = false;
    ng->is_running = false;
    ng->watcher_in.data = NULL;
    ng->watcher_out.data = NULL;
    ng->type = np_network_type_none;
    ng->last_send_date = 0.0;
    ng->last_received_date = 0.0;
    ng->seqend = 0;

    ng->ip[0] = 0;
    ng->port[0] = 0;

    ng->watcher_in.data = calloc(1, sizeof(_np_network_data_t));
    CHECK_MALLOC(ng->watcher_in.data);
    ng->watcher_out.data = calloc(1, sizeof(_np_network_data_t));
    CHECK_MALLOC(ng->watcher_out.data);

    char mutex_str[64];
    snprintf(mutex_str, 63, "%s:%p", "urn:np:network:access", ng);
    _np_threads_mutex_init(context, &ng->access_lock, "network access_lock");

    TSP_INITD(ng->can_be_enabled, true);
}

void __set_v6_only_false(int socket) 
{
    int v6_only = 0;
    if (-1 == setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only)))
    {
        // enable ipv4 mapping
        // log_msg(LOG_NETWORK | LOG_WARN, "setsockopt (IPV6_V6ONLY): %s: ", strerror(errno));
    }
}

void __set_non_blocking(int socket) 
{
    // set non blocking
    int current_flags = fcntl(socket, F_GETFL);
    current_flags |= O_NONBLOCK;
    fcntl(socket, F_SETFL, current_flags);
}

void __set_keepalive(int socket) 
{
    int optval = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
        // 
    }
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

    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "try to get_network_address");
    _np_network_get_address(context, create_server, &ng->addr_in, type, hostname, service);

    ng->socket_type = type | passive_socket_type;

    if (NULL == ng->addr_in && !FLAG_CMP(type, PASSIVE))
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

        if (prepared_socket_fd > 0) {
            ng->socket = prepared_socket_fd;
        }
        else {
            // server setup - create socket
            ng->socket = socket(ng->addr_in->ai_family, ng->addr_in->ai_socktype, ng->addr_in->ai_protocol);
            if (0 > ng->socket)
            {
                log_msg(LOG_ERROR, "could not create socket: %s", strerror(errno));
                return false;
            }
            /* attach socket to #port#. */
            if (0 > bind(ng->socket, ng->addr_in->ai_addr, ng->addr_in->ai_addrlen))
            {
                // UDP note: not using a connected socket for sending messages to a different target_node
                // leads to unreliable delivery. The sending socket changes too often to be useful
                // for finding the correct decryption shared secret. Especially true for ipv6 ...
                log_msg(LOG_ERROR, "bind failed for %s:%s: %s", hostname, service, strerror(errno));
                __np_network_close(ng);
                // listening port could not be opened
                return false;
            }
            if (-1 == setsockopt(ng->socket, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof(one)))
            {
                log_msg(LOG_ERROR, "setsockopt (SO_REUSEADDR): %s: ", strerror(errno));
                __np_network_close(ng);
                return false;
            }
            if (FLAG_CMP(type, TCP) && 0 > listen(ng->socket, 10) ) {
                log_msg(LOG_ERROR, "listen on tcp port failed: %s:", strerror(errno));
                __np_network_close(ng);
                return false;
            }
        }

        if (FLAG_CMP(type, IPv6)) {
            __set_v6_only_false(ng->socket);
        }
        if (FLAG_CMP(type, TCP)) {
            // __set_keepalive(ng->socket);
        }
        __set_non_blocking(ng->socket);

        if (FLAG_CMP(type, TCP) && prepared_socket_fd < 1) 
        {
            log_debug_msg(LOG_NETWORK | LOG_DEBUG, "%p -> %d network is receiving accepts", ng, ng->socket);
            ev_io_init(&ng->watcher_in, _np_network_accept, ng->socket, EV_READ);
        }
        else if (FLAG_CMP(type, UDP) ||
                (FLAG_CMP(type, TCP) && prepared_socket_fd > 1))
        {
            log_debug_msg(LOG_NETWORK | LOG_DEBUG, "%p -> %d network is receiving", ng, ng->socket);
            ev_io_init(&ng->watcher_in, _np_network_read, ng->socket, EV_READ);
        }
        else {
            log_debug_msg(LOG_NETWORK | LOG_DEBUG, "don't know how to setup server network of type %"PRIu8, type);
        }
        ((_np_network_data_t*)ng->watcher_in.data)->network = ng;

        ng->initialized = true;
        log_debug_msg(LOG_NETWORK | LOG_DEBUG, "created local listening socket");
    }
    else 
    {
        log_debug_msg(LOG_NETWORK | LOG_DEBUG, "creating sending network");

        ng->type |= np_network_type_client;

        // client socket - wait for writeable socket
        if (prepared_socket_fd > 0) 
        {
            ng->socket = prepared_socket_fd;
        }
        else
        {
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
            // UDP note: not using a connected socket for sending messages to a different target_node
            // leads to unreliable delivery. The sending socket changes too often to be useful
            // for finding the correct decryption shared secret. Especially true for ipv6 ...
            int l_errno = 0;
            int retry_connect = 3;
            int connection_status = -1;
            do {
                connection_status = connect(ng->socket, ng->addr_in->ai_addr, ng->addr_in->ai_addrlen);
                l_errno = errno;
                if (connection_status != 0 && l_errno != EISCONN)
                {
                    // As we do have a async connection (and TCP may need longer due to
                    // handshake packages) we need to check the connection status for a moment
                    log_msg(LOG_DEBUG, "trying tcp connect: %"PRIi32" (%s)", connection_status, strerror(l_errno) );
                    np_time_sleep(NP_PI / 100);
                }
            } while (0 != connection_status && retry_connect-- > 0 && l_errno != EISCONN);

            if (0 != connection_status && l_errno != EISCONN) 
            {
                log_msg(LOG_ERROR,
                    "could not connect: %s (%d)", strerror(errno), errno);
                __np_network_close(ng);
                return false;
            }
        }

        if (FLAG_CMP(type, IPv6)  && !FLAG_CMP(type, PASSIVE)) {
            __set_v6_only_false(ng->socket);
        }
        if (FLAG_CMP(type, TCP)) {
            // __set_keepalive(ng->socket);
        }
        __set_non_blocking(ng->socket);

        log_debug_msg(LOG_NETWORK | LOG_DEBUG,
            "network: %d %p %p :", ng->socket, &ng->watcher_out, &ng->watcher_out.data);

        // initialize to be on the safe side
//        np_node_t* my_node = _np_key_get_node(context->my_node_key);
/*        if (FLAG_CMP(my_node->protocol, PASSIVE) || FLAG_CMP(type, PASSIVE)) 
        {
            ng->type |= np_network_type_server;
            ev_io_init(
                &ng->watcher_out, _np_network_bidirektional,
                ng->socket, EV_WRITE | EV_READ);
            log_debug_msg(LOG_NETWORK | LOG_DEBUG, "%p -> %d network is bidirektional", ng, ng->socket);
        }
        else
        if (FLAG_CMP(type, TCP) || FLAG_CMP(type, UDP))
        {
*/
            ev_io_init(
                &ng->watcher_out, _np_network_write,
                ng->socket, EV_WRITE);
            log_debug_msg(LOG_NETWORK | LOG_DEBUG, "%p -> %d network is sender", ng, ng->socket);
  /*      }
        else
        {
            log_debug_msg(LOG_NETWORK | LOG_DEBUG, "don't know how to setup client network of type %"PRIu8, type);
        }*/
        ((_np_network_data_t*)ng->watcher_out.data)->network = ng;

        ng->initialized = true;
        log_debug_msg(LOG_NETWORK | LOG_DEBUG, "created local sending socket");
    }

    if (ng->addr_in != NULL) 
    {
        memset((char *)&ng->remote_addr, 0, sizeof(ng->remote_addr));
        ng->remote_addr = calloc(1, ng->addr_in->ai_addrlen);
        CHECK_MALLOC(ng->remote_addr);

        ng->remote_addr_len = ng->addr_in->ai_addrlen;
        memcpy(ng->remote_addr, ng->addr_in->ai_addr, ng->addr_in->ai_addrlen);
    }
    
    freeaddrinfo(ng->addr_in);
    ng->addr_in = NULL;

    log_debug_msg(LOG_DEBUG,
        "Init %s network %s %s on %s:%s (fd: %d%s)",
        create_server ? "server" : "client",
        FLAG_CMP(type, TCP) ? "TCP" : FLAG_CMP(type, UDP) ? "UDP" : "?",
        FLAG_CMP(type, PASSIVE) ? "PASSIVE" : "",
        hostname,
        service,
        ng->socket,
        prepared_socket_fd > 0 ? " (prepared fd)" : ""
    );
    return ng->initialized;
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

void _np_network_set_key(np_network_t* self, np_dhkey_t dhkey) {
    _np_dhkey_assign(
        &((_np_network_data_t*)self->watcher_in.data)->owner_dhkey, &dhkey);
    _np_dhkey_assign(
        &((_np_network_data_t*)self->watcher_out.data)->owner_dhkey, &dhkey);
}
