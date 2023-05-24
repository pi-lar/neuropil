//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project
/*
** $Id: network.c,v 1.30 2007/04/04 00:04:49 krishnap Exp $
**
** Matthew Allen
** description:
*/

#include "np_network.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <event/ev.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "dtime.h"

#include "neuropil_log.h"

#include "core/np_comp_node.h"
#include "util/np_event.h"

#include "np_constants.h"
#include "np_dhkey.h"
#include "np_evloop.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_node.h"
#include "np_settings.h"
#include "np_statistics.h"
#include "np_threads.h"
#include "np_types.h"
#include "np_util.h"

static char *URN_TCP_V4 = "tcp4";
static char *URN_TCP_V6 = "tcp6";
static char *URN_PAS_V4 = "pas4";
static char *URN_PAS_V6 = "pas6";
static char *URN_UDP_V4 = "udp4";
static char *URN_UDP_V6 = "udp6";
static char *URN_IP_V4  = "ip4";
static char *URN_IP_V6  = "ip6";

typedef struct _np_network_data_s {
  np_network_t *network;
  np_dhkey_t    owner_dhkey;
} _np_network_data_t;

typedef enum _np_network_runtime_status {
  np_network_stopped = 0,
  np_network_server_started,
  np_network_client_started,
};

np_module_struct(network) {
  np_state_t *context;
  TSP(size_t, __msgs_per_sec_in);
  TSP(size_t, __msgs_per_sec_out);
  /**
   * @brief Runtime constant how many messages per second this node can handle,
   * set to 0 to disable.
   */
  size_t max_msgs_per_sec;
};

bool __np_network_module_periodic_capacity_reset(
    np_state_t *context, NP_UNUSED np_util_event_t event) {
  size_t last_msgs_per_sec_in = 0, last_msgs_per_sec_out = 0;
  TSP_SCOPE(np_module(network)->__msgs_per_sec_in) {
    last_msgs_per_sec_in = np_module(network)->__msgs_per_sec_in;
    np_module(network)->__msgs_per_sec_in = 0;
  }
  TSP_SCOPE(np_module(network)->__msgs_per_sec_out) {
    last_msgs_per_sec_out = np_module(network)->__msgs_per_sec_out;
    np_module(network)->__msgs_per_sec_out = 0;
  }
  if (last_msgs_per_sec_in > 0 || last_msgs_per_sec_out > 0)
    log_info(LOG_EXPERIMENT,
             "[network capacity] total in:%" PRIsizet " total out:%" PRIsizet,
             last_msgs_per_sec_in,
             last_msgs_per_sec_out);
  return true;
}

bool _np_network_module_init(np_state_t *context) {
  if (!np_module_initiated(network)) {
    np_module_malloc(network);

    TSP_INITD(_module->__msgs_per_sec_in, 0);
    TSP_INITD(_module->__msgs_per_sec_out, 0);
    if (context->settings->max_msgs_per_sec > 0) {
      _module->max_msgs_per_sec = context->settings->max_msgs_per_sec;
    } else {
      _module->max_msgs_per_sec = NP_NETWORK_DEFAULT_MAX_MSGS_PER_SEC;
    }

    np_jobqueue_submit_event_periodic(
        context,
        NP_PRIORITY_HIGH,
        0,
        1,
        __np_network_module_periodic_capacity_reset,
        "__np_network_module_periodic_capacity_reset");
  }

  return (true);
}

void _np_network_module_destroy(np_state_t *context) {
  if (np_module_initiated(network)) {
    np_module_var(network);
    TSP_DESTROY(_module->__msgs_per_sec_in);
    TSP_DESTROY(_module->__msgs_per_sec_out);

    np_module_free(route);
  }
}

socket_type _np_network_parse_protocol_string(const char *protocol_str) {
  if ((strnlen(protocol_str, 4) == 4) &&
      0 == strncmp(protocol_str, URN_TCP_V4, 4))
    return (TCP | IPv4);
  if ((strnlen(protocol_str, 4) == 4) &&
      0 == strncmp(protocol_str, URN_TCP_V6, 4))
    return (TCP | IPv6);
  if ((strnlen(protocol_str, 4) == 4) &&
      0 == strncmp(protocol_str, URN_PAS_V4, 4))
    return (PASSIVE | IPv4);
  if ((strnlen(protocol_str, 4) == 4) &&
      0 == strncmp(protocol_str, URN_PAS_V6, 4))
    return (PASSIVE | IPv6);
  if ((strnlen(protocol_str, 4) == 4) &&
      0 == strncmp(protocol_str, URN_UDP_V4, 4))
    return (UDP | IPv4);
  if ((strnlen(protocol_str, 4) == 4) &&
      0 == strncmp(protocol_str, URN_UDP_V6, 4))
    return (UDP | IPv6);
  // if (0 == strncmp(protocol_str, URN_IP_V4, 3))  return (RAW     | IPv4);
  // if (0 == strncmp(protocol_str, URN_IP_V6, 3))  return (RAW     | IPv6);
  /*
      int proto;
      if(sscanf(protocol_str, "%d", &proto) == 1){
          return proto;
      }
  */
  return (UNKNOWN_PROTO);
}

char *_np_network_get_protocol_string(np_state_t *context,
                                      socket_type protocol) {
  if (FLAG_CMP(protocol, (PASSIVE | IPv4))) return (URN_PAS_V4);
  if (FLAG_CMP(protocol, (PASSIVE | IPv6))) return (URN_PAS_V6);
  if (FLAG_CMP(protocol, (TCP | IPv4))) return (URN_TCP_V4);
  if (FLAG_CMP(protocol, (TCP | IPv6))) return (URN_TCP_V6);
  if (FLAG_CMP(protocol, (UDP | IPv4))) return (URN_UDP_V4);
  if (FLAG_CMP(protocol, (UDP | IPv6))) return (URN_UDP_V6);
  // if (protocol == (RAW     | IPv4)) return (URN_IP_V4);
  // if (protocol == (RAW     | IPv6)) return (URN_IP_V6);
  log_msg(LOG_WARNING, "Protocol %d is not availabe!", protocol);
#ifdef DEBUG
  // assert(false && "Protocol is not availabe!");
#endif
  return ("UNKNOWN_PROTOCOL");
}

void __np_network_close(np_network_t *self) {
  np_ctx_memory(self);
  log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                "Closing network %p -> %d",
                self,
                self->socket);
  close(self->socket);
}

/** network_address:
 ** returns the addrinfo structure of the hostname / service
 **/
bool _np_network_get_address(np_state_t       *context,
                             bool              create_socket,
                             struct addrinfo **ai_head,
                             socket_type       type,
                             char             *hostname,
                             char             *service) {
  int             err;
  struct addrinfo hints = {0, 0, 0, 0, 0, 0, 0, 0};

  if (true == create_socket)
    hints.ai_flags = AI_PASSIVE | AI_CANONNAME | AI_NUMERICSERV;
  else hints.ai_flags = AI_CANONNAME | AI_NUMERICSERV;

  if (FLAG_CMP(type, IPv4)) {
    hints.ai_family = PF_INET;
  }
  if (FLAG_CMP(type, IPv6)) {
    hints.ai_family = PF_INET6;
  }
  if (FLAG_CMP(type, UDP)) {
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
  }
  if (FLAG_CMP(type, TCP)) {
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
  }

  log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                "using getaddrinfo: %d:%s:%s",
                type,
                hostname,
                service);
  if (0 != (err = getaddrinfo(hostname, service, &hints, ai_head))) {
    log_msg(LOG_ERROR,
            "hostname: %s, servicename %s, protocol %d",
            hostname,
            service,
            type);
    log_msg(LOG_ERROR, "error getaddrinfo: %s (%d)", gai_strerror(err), err);
    log_msg(LOG_ERROR, "error errno: %s (%d)", gai_strerror(errno), errno);

    return false;
  }
  return true;
}

bool _np_network_send_data(np_state_t   *context,
                           np_network_t *network,
                           void         *data_to_send) {
  ssize_t write_per_data   = 0;
  bool    node_at_capacity = false;
  bool    ret              = false;

#ifdef DEBUG
  unsigned char hash[crypto_generichash_BYTES] = {0};
  crypto_generichash(hash,
                     sizeof hash,
                     data_to_send,
                     MSG_CHUNK_SIZE_1024,
                     NULL,
                     0);
  // char hex[MSG_CHUNK_SIZE_1024 * 2 + 1];
  // sodium_bin2hex(hex, MSG_CHUNK_SIZE_1024 * 2 + 1, data_to_send,
  // MSG_CHUNK_SIZE_1024);
  char hex[crypto_generichash_BYTES * 2 + 1] = {0};
  sodium_bin2hex(hex,
                 crypto_generichash_BYTES * 2 + 1,
                 hash,
                 crypto_generichash_BYTES);

  log_debug(LOG_NETWORK | LOG_EXPERIMENT,
            "OUT DATAPACKAGE %s:%s %s",
            network->ip,
            network->port,
            hex);
#endif // DEBUG

  size_t msgs_per_sec_out = 0;

  if (np_module_initiated(network) &&
      np_module(network)->max_msgs_per_sec > 0) {
    TSP_SCOPE(np_module(network)->__msgs_per_sec_out) {
      node_at_capacity = np_module(network)->__msgs_per_sec_out >
                         np_module(network)->max_msgs_per_sec;
      if (np_module(network)->__msgs_per_sec_out < SIZE_MAX)
        msgs_per_sec_out = np_module(network)->__msgs_per_sec_out++;
    }
  }

  if (node_at_capacity) {
    log_warn(LOG_NETWORK,
             "Dropping data package due to msgs per sec constraint (%" PRIsizet
             " / %" PRIsizet " | OUT)",
             msgs_per_sec_out,
             np_module(network)->max_msgs_per_sec);
  } else {

    do {
      ssize_t bytes_written = 0;
      if (FLAG_CMP(network->socket_type, PASSIVE)) {
        bytes_written =
            sendto(network->socket,
                   (((unsigned char *)data_to_send)) + write_per_data,
                   MSG_CHUNK_SIZE_1024 - write_per_data,
#ifdef MSG_NOSIGNAL
                   MSG_NOSIGNAL,
#else
                   0,
#endif
                   network->remote_addr,
                   network->remote_addr_len);

      } else {
        bytes_written = send(network->socket,
                             (((unsigned char *)data_to_send)) + write_per_data,
                             MSG_CHUNK_SIZE_1024 - write_per_data,
#ifdef MSG_NOSIGNAL
                             MSG_NOSIGNAL
#else
                             0
#endif
        );
      }

      if (bytes_written > 0 && bytes_written <= MSG_CHUNK_SIZE_1024) {
        write_per_data += bytes_written;
      } else {
        break;
      }

    } while (write_per_data < MSG_CHUNK_SIZE_1024);

    _np_debug_log_bin(data_to_send,
                      MSG_CHUNK_SIZE_1024,
                      LOG_NETWORK,
                      "Did send    data (%" PRIsizet
                      " bytes / %p) via fd: %d: %s",
                      write_per_data,
                      data_to_send,
                      network->socket);

    if (write_per_data == MSG_CHUNK_SIZE_1024) {
      _np_statistics_add_send_bytes(write_per_data);

      network->last_send_date = np_time_now();
      ret                     = true;
      log_debug(LOG_NETWORK,
                "Did send package %p via %p -> %d",
                data_to_send,
                network,
                network->socket);
    } else {
      log_error("Could not send package %p (%zd/%d) over fd: %d msg: %s (%d)",
                data_to_send,
                write_per_data,
                MSG_CHUNK_SIZE_1024,
                network->socket,
                strerror(errno),
                errno);
    }
  }
  return ret;
}

void _np_network_write(struct ev_loop *loop, ev_io *event, int revents) {
  np_ctx_decl(ev_userdata(loop));

  if (FLAG_CMP(revents, EV_ERROR) || FLAG_CMP(revents, EV_READ)) {
    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "got invalid write event");
    return;
  }

  if (event->data == NULL) return;

  np_network_t *network = ((_np_network_data_t *)event->data)->network;

  _TRYLOCK_ACCESS(&network->access_lock) {
    uint8_t send_items_counter = 0;

    void *data_to_send = NULL;
    // if a data packet is available, try to send it
    data_to_send = sll_head(void_ptr, network->out_events);
    if (data_to_send != NULL) {
      send_items_counter++;
      _np_network_send_data(context, network, data_to_send);
    }
    np_unref_obj(BLOB_1024, data_to_send, ref_obj_creation);

#ifdef DEBUG
    if (sll_size(network->out_events) > 0) {
      log_debug(LOG_NETWORK,
                "%" PRIu32 " packages still in delivery",
                sll_size(network->out_events));
    }
#endif

    if (sll_size(network->out_events) == 0) {
      EV_P;
      loop = _np_event_get_loop_out(context);
      ev_io_stop(EV_A_ & network->watcher_out);
      log_debug(LOG_NETWORK,
                "network (%s) has been stopped for sending: %d:%s:%s",
                np_memory_get_id(network),
                network->type,
                network->ip,
                network->port);
      network->is_running &= np_network_server_started;
    }
  }
}

struct __np_network_data {
  struct sockaddr_storage from;
  char                    ipstr[CHAR_LENGTH_IP];
  char                    port[CHAR_LENGTH_PORT];
  void                   *data;
  int16_t                 in_msg_len;
  np_network_t           *ng_tcp_host;
};

void __np_network_get_ip_and_port(struct __np_network_data *network_data) {
  if (network_data->from.ss_family == AF_INET) {
    // AF_INET
    struct sockaddr_in *s = (struct sockaddr_in *)&network_data->from;
    inet_ntop(AF_INET,
              &s->sin_addr,
              network_data->ipstr,
              sizeof network_data->ipstr);
    snprintf(network_data->port, CHAR_LENGTH_PORT, "%d", ntohs(s->sin_port));
  } else {
    // AF_INET6
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&network_data->from;
    inet_ntop(AF_INET6,
              &s->sin6_addr,
              network_data->ipstr,
              sizeof network_data->ipstr);
    snprintf(network_data->port, CHAR_LENGTH_PORT, "%d", ntohs(s->sin6_port));
  }
}

void __create_new_alias_key(np_state_t *context,
                            socket_type proto,
                            char       *ip,
                            char       *port,
                            np_dhkey_t  alias_dhkey) {
  np_node_t *new_node = NULL;
  np_new_obj(np_node_t, new_node, FUNC);
  _np_node_update(new_node, proto, ip, port);

  np_key_t *temp_alias_key = _np_keycache_find_or_create(context, alias_dhkey);

  np_util_event_t node_evt = {.type         = evt_external,
                              .user_data    = new_node,
                              .target_dhkey = alias_dhkey};

  log_info(LOG_ROUTING,
           "create new alias key %s (%s:%s)",
           _np_key_as_str(temp_alias_key),
           ip,
           port);
  if (!np_jobqueue_submit_event(context,
                                0.0,
                                alias_dhkey,
                                node_evt,
                                "event: externe node in")) {
    log_warn(LOG_NETWORK | LOG_JOBS,
             "rejecting possible udp connection as jobqueue is rejecting it");
    np_unref_obj(np_node_t, new_node, FUNC);
  }
  np_unref_obj(np_key_t, temp_alias_key, "_np_keycache_find_or_create");
}

void _np_network_accept(struct ev_loop *loop, ev_io *event, int revents) {
  np_ctx_decl(ev_userdata(loop));

  if (FLAG_CMP(revents, EV_ERROR) || FLAG_CMP(revents, EV_WRITE)) {
    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "got invalid tcp accept event");
    return;
  }

  struct __np_network_data data_container = {0};
  socklen_t                fromlen        = sizeof(struct sockaddr_storage);

  np_state_t   *state = context;
  np_network_t *ng    = ((_np_network_data_t *)event->data)->network;

  int client_fd =
      accept(ng->socket, (struct sockaddr *)&data_container.from, &fromlen);

  if (client_fd < 0) {
    if (errno != EWOULDBLOCK && errno != EAGAIN) {
      log_msg(LOG_ERROR,
              "Could not accept socket connection on client fd %d. %s (%d)",
              ng->socket,
              strerror(errno),
              errno);
    }
  } else {
    __np_network_get_ip_and_port(&data_container);

    log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                  "accept socket from %d -> client fd: %d -> %s:%s",
                  ng->socket,
                  client_fd,
                  data_container.ipstr,
                  data_container.port);

    np_network_t *new_network = NULL;
    np_new_obj(np_network_t, new_network);

    if (_np_network_init(new_network,
                         true,
                         ng->socket_type,
                         data_container.ipstr,
                         data_container.port,
                         client_fd,
                         UNKNOWN_PROTO)) {
      new_network->is_multiuse_socket = false;
      // it could be a passive socket

      np_dhkey_t search_key =
          np_dhkey_create_from_hostport(&data_container.ipstr[0],
                                        &data_container.port[0]);
      np_key_t *alias_key = _np_keycache_find_or_create(context, search_key);

      ASSERT(alias_key->entity_array[3] == NULL,
             "There should be no network for a tcp connection yet");

      alias_key->entity_array[3] = new_network;
      // will be reset to alias key after first (handshake) message
      _np_network_set_key(new_network,
                          ((_np_network_data_t *)event->data)->owner_dhkey);
      // new_network->__tcp_alias_dhkey = search_key;

      char buf[100] = {0};
      log_debug_msg(LOG_NETWORK,
                    "%p -> %d network is receiving. alias: %s",
                    new_network,
                    new_network->socket,
                    _np_key_as_str(alias_key));

      _np_network_enable(new_network);
      log_debug_msg(LOG_NETWORK,
                    "created network for key: %s and watching it.",
                    _np_key_as_str(alias_key));
      np_unref_obj(np_key_t, alias_key, "_np_keycache_find_or_create");

      __create_new_alias_key(context,
                             TCP,
                             data_container.ipstr,
                             data_container.port,
                             search_key);
    } else {
      np_unref_obj(np_network_t, new_network, ref_obj_creation);
    }
  }
}

void _np_network_read_msg_event_cleanup(void *context, np_util_event_t ev) {
  np_unref_obj(BLOB_1024, ev.user_data, "_np_network_read");
}

/**
 ** _np_network_read:
 ** reads the network layer in listen mode.
 ** This function delivers incoming messages to the default message handler
 **/
void _np_network_read(struct ev_loop *loop, ev_io *event, int revents) {
  np_ctx_decl(ev_userdata(loop));
  if (FLAG_CMP(revents, EV_ERROR) || FLAG_CMP(revents, EV_WRITE)) {
    log_debug_msg(LOG_NETWORK, "got invalid read event");
    return;
  }

  log_debug(LOG_NETWORK | LOG_WARNING, "Receive started ...");

  // cast event data structure to np_state_t pointer
  socklen_t fromlen = sizeof(struct sockaddr_storage);
  // calling address and port
  if (event->data == NULL) return;

  np_dhkey_t    owner_dhkey = ((_np_network_data_t *)event->data)->owner_dhkey;
  np_network_t *ng          = ((_np_network_data_t *)event->data)->network;

  /* receive the new data */
  int      last_recv_result = 0;
  uint16_t msgs_received    = 0;

  // catch multiple msgs waiting in this pipe
  // double timeout_start = np_time_now();
  bool    check_for_data_nescessary = true;
  bool    network_receive_timeout   = false;
  int16_t in_msg_len;
  bool    stop = false;

  struct __np_network_data data_container = {0};
  np_new_obj(BLOB_1024, data_container.data);

  in_msg_len = 0;
  // catch a msg even if it was chunked into smaller byte parts by the
  // underlying network

  do {
    if (FLAG_CMP(ng->socket_type, TCP)) {
      last_recv_result = recv(event->fd,
                              ((char *)data_container.data) + in_msg_len,
                              MSG_CHUNK_SIZE_1024 - in_msg_len,
                              0);
    } else {
      last_recv_result =
          recvfrom(event->fd,
                   ((unsigned char *)data_container.data) + in_msg_len,
                   MSG_CHUNK_SIZE_1024 - in_msg_len,
                   0,
                   (struct sockaddr *)&data_container.from,
                   &fromlen);
    }

    if (last_recv_result < 0) {
      log_debug(LOG_NETWORK | LOG_WARNING,
                "Receive stopped. Reason: %s (%" PRId32 "/" PRId32 ")",
                strerror(errno),
                errno,
                last_recv_result);
      stop = true;
    }

    if (!stop) {
      in_msg_len += last_recv_result;
      // repeat if msg is not 1024 bytes in size and the timeout is not
      // reached network_receive_timeout = (np_time_now() - timeout_start) >=
      // NETWORK_RECEIVING_TIMEOUT_SEC;
    }
  } while (last_recv_result > 0 &&
           in_msg_len < MSG_CHUNK_SIZE_1024); //! network_receive_timeout);

  if (!stop) {
    if (FLAG_CMP(ng->socket_type, TCP)) {
      int err = -1;
      do {
        err = getpeername(event->fd,
                          (struct sockaddr *)&data_container.from,
                          &fromlen);
      } while (0 != err && errno != ENOTCONN);
    }
    __np_network_get_ip_and_port(&data_container);
    _np_statistics_add_received_bytes(in_msg_len);

#ifdef DEBUG
    char msg_hex[2 * in_msg_len + 1];
    sodium_bin2hex(msg_hex,
                   2 * in_msg_len + 1,
                   data_container.data,
                   in_msg_len);
    log_debug(LOG_NETWORK,
              "Did receive data (%" PRIi16 " bytes / %p) via fd: %d hex: 0x%s",
              in_msg_len,
              data_container.data,
              event->fd,
              msg_hex);
#endif

    if (in_msg_len == MSG_CHUNK_SIZE_1024) {
      bool   node_at_capacity  = false;
      size_t __msgs_per_sec_in = SIZE_MAX;
      if (np_module_initiated(network) &&
          np_module(network)->max_msgs_per_sec > 0) {
        TSP_SCOPE(np_module(network)->__msgs_per_sec_in) {
          node_at_capacity = np_module(network)->__msgs_per_sec_in >
                             np_module(network)->max_msgs_per_sec;
          if (np_module(network)->__msgs_per_sec_in < SIZE_MAX)
            __msgs_per_sec_in = np_module(network)->__msgs_per_sec_in++;
        }
      }
      msgs_received++;
      if (node_at_capacity) {
        log_warn(
            LOG_NETWORK,
            "Dropping data package due to msgs per sec constraint (%" PRIsizet
            " / %" PRIsizet " | IN)",
            __msgs_per_sec_in,
            np_module(network)->max_msgs_per_sec);
      } else {
        data_container.in_msg_len = in_msg_len;

        // we registered this token info before in the first handshake message
        // np_dhkey_t search_key;
        // if (FLAG_CMP(ng->socket_type, TCP)) {
        //     search_key = ng->__tcp_alias_dhkey;
        // }else{
        np_dhkey_t search_key =
            np_dhkey_create_from_hostport(&data_container.ipstr[0],
                                          &data_container.port[0]);
        // }
        np_key_t *alias_key = _np_keycache_find(context, search_key);

        np_util_event_t in_event = {.type      = evt_external | evt_message,
                                    .user_data = data_container.data,
                                    .cleanup =
                                        _np_network_read_msg_event_cleanup,
                                    .target_dhkey = search_key};

        if (NULL == alias_key) // && FLAG_CMP(ng->socket_type, UDP))
        {
          __create_new_alias_key(context,
                                 UDP,
                                 data_container.ipstr,
                                 data_container.port,
                                 search_key);
        }

        char msg_identifier[crypto_generichash_BYTES * 2 + 1 + 30] =
            "urn:np:event:extern_message";
#ifdef DEBUG
        unsigned char hash[crypto_generichash_BYTES] = {0};
        crypto_generichash(hash,
                           sizeof hash,
                           data_container.data,
                           MSG_CHUNK_SIZE_1024,
                           NULL,
                           0);
        // char hex[MSG_CHUNK_SIZE_1024 * 2 + 1];
        // sodium_bin2hex(hex, MSG_CHUNK_SIZE_1024 * 2 + 1, data_to_send,
        // MSG_CHUNK_SIZE_1024);
        char hex[crypto_generichash_BYTES * 2 + 1] = {0};
        sodium_bin2hex(hex,
                       crypto_generichash_BYTES * 2 + 1,
                       hash,
                       crypto_generichash_BYTES);

        log_info(LOG_NETWORK | LOG_EXPERIMENT,
                 "IN DATAPACKAGE %s:%s %s",
                 data_container.ipstr,
                 data_container.port,
                 hex);
        snprintf(msg_identifier, 95, "urn:np:event:extern_message:%s", hex);
#endif // DEBUG

        // get handshake status lock conform...
        enum np_node_status _handshake_status = np_node_status_Disconnected;
        if (alias_key) {
          _LOCK_ACCESS(&alias_key->key_lock) {
            np_node_t *alias_node = _np_key_get_node(alias_key);

            if (alias_node) {
              _handshake_status = alias_node->_handshake_status;
            }
          }
        }

        if (FLAG_CMP(ng->socket_type, PASSIVE) ||
            (_handshake_status < np_node_status_Initiated)) {
          np_ref_obj(BLOB_1024, data_container.data, FUNC);
          char buf[100] = {0};
          log_debug(LOG_NETWORK,
                    "send data to owner %s",
                    np_id_str(buf, &owner_dhkey));
          if (!np_jobqueue_submit_event(context,
                                        0.0,
                                        owner_dhkey,
                                        in_event,
                                        msg_identifier)) {
            log_error(
                "Dropping data package send to owner as jobqueue is rejecting "
                "it");
            np_unref_obj(BLOB_1024, data_container.data, FUNC);
          }
        } else if (NULL != alias_key) {
          np_ref_obj(BLOB_1024, data_container.data, FUNC);
          log_debug(LOG_NETWORK, "send data to alias");
          if (!np_jobqueue_submit_event(context,
                                        0.0,
                                        alias_key->dhkey,
                                        in_event,
                                        msg_identifier)) {
            log_error(
                "Dropping data package send to alias key as jobqueue is "
                "rejecting it");
            np_unref_obj(BLOB_1024, data_container.data, FUNC);
          }
        } else {
          log_debug_msg(LOG_ERROR,
                        "network in unknown state for key %s",
                        _np_key_as_str(alias_key));
        }

        if (NULL != alias_key)
          np_unref_obj(np_key_t, alias_key, "_np_keycache_find");
      }

    } else {
      if (network_receive_timeout) {
        log_info(LOG_NETWORK,
                 "Network receive iteration stopped due to timeout (Received "
                 "Data: %" PRIu16 ")",
                 in_msg_len);
      }

      if (in_msg_len == 0) {
        log_info(LOG_NETWORK,
                 "Stopping network due to zero size package (%" PRIu16 ")",
                 in_msg_len);
        _np_network_disable(ng);
        stop = true;
      } else {
        log_info(LOG_NETWORK,
                 "Dropping data package due to invalid package size (%" PRIu16
                 ")",
                 in_msg_len);
      }
    }
  }

  np_unref_obj(BLOB_1024, data_container.data, ref_obj_creation);
  log_info(LOG_NETWORK | LOG_VERBOSE,
           "Received %" PRIu16 " messages.",
           msgs_received);
}

void _np_network_stop(np_network_t *network, bool force) {
  assert(NULL != network);

  np_ctx_memory(network);
  log_trace_msg(LOG_TRACE, "start: void _np_network_stop(...){");

  _LOCK_ACCESS(&network->access_lock) {
    EV_P;
    if (FLAG_CMP(network->is_running, np_network_server_started)) {
      if (FLAG_CMP(network->type, np_network_type_server)) {
        log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                      "stopping server network %p",
                      network);
        loop = _np_event_get_loop_in(context);
        _np_event_suspend_loop_in(context);
        ev_io_stop(EV_A_ & network->watcher_in);
        // ev_io_set(&network->watcher, network->socket, EV_NONE);
        // ev_io_start(EV_A_ &network->watcher);
        _np_event_reconfigure_loop_in(context);
        _np_event_resume_loop_in(context);
        network->is_running &= np_network_client_started;
      }
    }

    if (FLAG_CMP(network->is_running, np_network_client_started)) {
      if (FLAG_CMP(network->type, np_network_type_client)) {
        log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                      "stopping client network %p",
                      network);
        loop = _np_event_get_loop_out(context);
        _np_event_suspend_loop_out(context);
        ev_io_stop(EV_A_ & network->watcher_out);
        // ev_io_set(&network->watcher, network->socket, EV_NONE);
        // ev_io_start(EV_A_ &network->watcher);
        _np_event_reconfigure_loop_out(context);
        _np_event_resume_loop_out(context);
        network->is_running &= np_network_server_started;
      }
    }
  }
}

void _np_network_start(np_network_t *network, bool force) {
  assert(NULL != network);

  np_ctx_memory(network);
  log_trace_msg(LOG_TRACE, "start: void _np_network_start(...){");

  TSP_GET(bool, network->can_be_enabled, can_be_enabled);
  if (can_be_enabled) {
    _LOCK_ACCESS(&network->access_lock) {
      EV_P;
      if (!FLAG_CMP(network->is_running, np_network_server_started)) {
        if (FLAG_CMP(network->type, np_network_type_server)) {
          log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                        "starting server network %p",
                        network);
          loop = _np_event_get_loop_in(context);
          _np_event_suspend_loop_in(context);
          ev_io_start(EV_A_ & network->watcher_in);
          // ev_io_set(&network->watcher, network->socket, EV_NONE);
          // ev_io_start(EV_A_ &network->watcher);
          _np_event_reconfigure_loop_in(context);
          _np_event_resume_loop_in(context);
          network->is_running |= np_network_server_started;
        }
      }

      if (!FLAG_CMP(network->is_running, np_network_client_started)) {
        if (FLAG_CMP(network->type, np_network_type_client)) {
          log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                        "starting client network %p",
                        network);
          loop = _np_event_get_loop_out(context);
          _np_event_suspend_loop_out(context);
          ev_io_start(EV_A_ & network->watcher_out);
          // ev_io_set(&network->watcher, network->socket, EV_NONE);
          // ev_io_start(EV_A_ &network->watcher);
          _np_event_reconfigure_loop_out(context);
          _np_event_resume_loop_out(context);
          network->is_running |= np_network_client_started;
        }
      }
    }
  }
}

/**
 * network_destroy
 */
void _np_network_t_del(np_state_t       *context,
                       NP_UNUSED uint8_t type,
                       NP_UNUSED size_t  size,
                       void             *data) {
  log_trace_msg(LOG_TRACE, "start: void _np_network_t_del(void* nw){");
  np_network_t *network = (np_network_t *)data;

  _LOCK_ACCESS(&network->access_lock) {
    if (NULL != network->out_events) {
      while (0 != sll_size(network->out_events)) {
        void *drop_package = sll_head(void_ptr, network->out_events);
        log_info(LOG_NETWORK | LOG_ROUTING | LOG_EXPERIMENT,
                 "Dropping data package due to network cleanup");
        np_unref_obj(BLOB_1024, drop_package, ref_obj_creation);
      }
    }
    sll_free(void_ptr, network->out_events);
  }

  free(network->watcher_in.data);
  free(network->watcher_out.data);
  free(network->remote_addr);

  if ((network->socket >= 0) && !network->is_multiuse_socket) {
    log_info(LOG_NETWORK, "Closing network %p due to object deletion", network);
    __np_network_close(network);
  }

  freeaddrinfo(network->addr_in);
  network->initialized = false;
  // finally destroy the mutex
  _np_threads_mutex_destroy(context, &network->access_lock);
  TSP_DESTROY(network->can_be_enabled);
}

void _np_network_t_new(np_state_t       *context,
                       NP_UNUSED uint8_t type,
                       NP_UNUSED size_t  size,
                       void             *data) {
  log_trace_msg(LOG_TRACE | LOG_NETWORK,
                "start: void _np_network_t_new(void* nw){");
  np_network_t *ng       = (np_network_t *)data;
  ng->is_multiuse_socket = false;
  ng->socket             = -1;
  ng->addr_in            = NULL;
  ng->out_events         = NULL;
  ng->initialized        = false;
  ng->is_running         = np_network_stopped;
  ng->watcher_in.data    = NULL;
  ng->watcher_out.data   = NULL;
  ng->type               = np_network_type_none;
  ng->last_send_date     = 0.0;
  ng->last_received_date = 0.0;
  ng->seqend             = 0;

  ng->ip[0]   = 0;
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

void __set_v6_only_false(int socket) {
  int v6_only = 0;
  if (-1 == setsockopt(socket,
                       IPPROTO_IPV6,
                       IPV6_V6ONLY,
                       &v6_only,
                       sizeof(v6_only))) {
    // enable ipv4 mapping
    // log_msg(LOG_NETWORK | LOG_WARNING, "setsockopt (IPV6_V6ONLY): %s: ",
    // strerror(errno));
  }
}

void __set_non_blocking(int socket) {
  // set non blocking
  int current_flags = fcntl(socket, F_GETFL);
  current_flags |= O_NONBLOCK;
  fcntl(socket, F_SETFL, current_flags);
}

void __set_keepalive(int socket) {
  int optval = 1;
  if (setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) <
      0) {
    //
  }
}

/** _np_network_init:
 ** initiates the networking layer structures required for a target_node
 ** if the port number is bigger than zero, it will create a socket and bind it
 *to #port#
 ** the type defines the protocol which is used by the target_node (@see
 *socket_type)
 *
 * if "prepared_socket_fd" > 0 no new connection will be created, instead the
 *client_fd will be set to "prepared_socket_fd"
 **/
bool _np_network_init(np_network_t *ng,
                      bool          create_server,
                      socket_type   type,
                      char         *hostname,
                      char         *service,
                      int           prepared_socket_fd,
                      socket_type   passive_socket_type) {
  np_ctx_memory(ng);
  int one = 1;

  log_debug_msg(LOG_NETWORK | LOG_DEBUG, "try to get_network_address");

  bool res = _np_network_get_address(context,
                                     create_server,
                                     &ng->addr_in,
                                     type,
                                     hostname,
                                     service);

  ng->socket_type = type | passive_socket_type;

  if (!res || (NULL == ng->addr_in && !FLAG_CMP(type, PASSIVE))) {
    log_msg(LOG_ERROR, "could not resolve requested network address");
    return false;
  }

  log_debug_msg(LOG_NETWORK | LOG_DEBUG, "done get_network_address");

  // only need for client setup, but initialize to have zero size of list
  if (ng->out_events == NULL) sll_init(void_ptr, ng->out_events);

  // create an inbound socket - happens only once per target_node
  if (true == create_server) {
    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "creating receiving network");

    _LOCK_ACCESS(&ng->access_lock) {
      ng->type |= np_network_type_server;
      // own sequence number counter
      ng->seqend = 0;
    }

    if (prepared_socket_fd > 0) {
      ng->socket             = prepared_socket_fd;
      ng->is_multiuse_socket = true;
    } else {
      // server setup - create socket
      ng->socket = socket(ng->addr_in->ai_family,
                          ng->addr_in->ai_socktype,
                          ng->addr_in->ai_protocol);
      if (0 > ng->socket) {
        log_error("could not create socket: %s", strerror(errno));
        return false;
      }
      /* attach socket to #port#. */
      if (-1 == setsockopt(ng->socket,
                           SOL_SOCKET,
                           SO_REUSEADDR,
                           (void *)&one,
                           sizeof(one))) {
        log_error("network: %p setsockopt (SO_REUSEADDR): %s: ",
                  ng,
                  strerror(errno));
        __np_network_close(ng);
        return false;
      }
      if (0 > bind(ng->socket, ng->addr_in->ai_addr, ng->addr_in->ai_addrlen)) {
        // UDP note: not using a connected socket for sending messages to a
        // different target_node leads to unreliable delivery. The sending
        // socket changes too often to be useful for finding the correct
        // decryption shared secret. Especially true for ipv6 ...
        log_error("network: %p bind failed for %s:%s: %s",
                  ng,
                  hostname,
                  service,
                  strerror(errno));
        __np_network_close(ng);
        // listening port could not be opened
        return false;
      }
      if (FLAG_CMP(type, TCP) && 0 > listen(ng->socket, 10)) {
        log_error("network: %p listen on tcp port failed: %s:",
                  ng,
                  strerror(errno));
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

    if (FLAG_CMP(type, TCP) && prepared_socket_fd < 1) {
      log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                    "%p -> %d network is receiving accepts",
                    ng,
                    ng->socket);
      ev_io_init(&ng->watcher_in, _np_network_accept, ng->socket, EV_READ);
    } else if (FLAG_CMP(type, UDP) ||
               (FLAG_CMP(type, TCP) && prepared_socket_fd > 1)) {
      log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                    "%p -> %d network is receiving",
                    ng,
                    ng->socket);
      ev_io_init(&ng->watcher_in, _np_network_read, ng->socket, EV_READ);
    } else {
      log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                    "don't know how to setup server network of type %" PRIu8,
                    type);
    }
    ((_np_network_data_t *)ng->watcher_in.data)->network = ng;

    ng->initialized = true;
    log_debug_msg(LOG_NETWORK, "created local listening socket");
  } else {
    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "creating sending network");

    ng->type |= np_network_type_client;

    int l_errno           = 0;
    int retry_connect     = 3;
    int connection_status = 0;

    // client socket - wait for writeable socket
    if (prepared_socket_fd > 0) {
      ng->socket             = prepared_socket_fd;
      ng->is_multiuse_socket = true;
    } else {
      ng->socket = socket(ng->addr_in->ai_family,
                          ng->addr_in->ai_socktype,
                          ng->addr_in->ai_protocol);
      if (0 > ng->socket) {
        log_error("could not create socket: %s", strerror(errno));
        return false;
      }
      if (-1 == setsockopt(ng->socket,
                           SOL_SOCKET,
                           SO_REUSEADDR,
                           (void *)&one,
                           sizeof(one))) {
        log_error("network: %p setsockopt (SO_REUSEADDR): %s: ",
                  ng,
                  strerror(errno));
        __np_network_close(ng);
        return false;
      }
      // UDP note: not using a bound and connected socket for sending messages
      // to a different target_node leads to unreliable delivery. The sending
      // socket changes too often to be useful for finding the correct
      // decryption shared secret. Especially true for ipv6 ...

      // https://www.geeksforgeeks.org/explicitly-assigning-port-number-client-socket/
      // https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ
      if (FLAG_CMP(type, UDP) && !FLAG_CMP(type, PASSIVE)) {
        if (connection_status == 0) {
          if (FLAG_CMP(type, IPv4)) {
            struct sockaddr_in my_addr1 = {0};
            my_addr1.sin_family         = AF_INET;
            my_addr1.sin_addr.s_addr    = INADDR_ANY;
            my_addr1.sin_port           = htons(0);
            connection_status           = bind(ng->socket,
                                     (struct sockaddr *)&my_addr1,
                                     sizeof(struct sockaddr_in));
            log_info(LOG_NETWORK,
                     "statically connect %p to %s:%s:%s ret: %" PRId32,
                     ng,
                     _np_network_get_protocol_string(context, type),
                     hostname,
                     service,
                     connection_status);
          } else if (FLAG_CMP(type, IPv6)) {
            struct sockaddr_in6 my_addr1 = {0};
            my_addr1.sin6_family         = AF_INET;
            // my_addr1.sin6_addr.s_addr = INADDR_ANY;
            my_addr1.sin6_port = htons(0);
            connection_status  = bind(ng->socket,
                                     (struct sockaddr *)&my_addr1,
                                     sizeof(struct sockaddr_in6));
            log_info(LOG_NETWORK,
                     "statically connect %p to %s:%s:%s ret: %" PRId32,
                     ng,
                     _np_network_get_protocol_string(context, type),
                     hostname,
                     service,
                     connection_status);
          }
        }
      }
      if (connection_status != 0) {
        log_warn(LOG_NETWORK,
                 "could not statically connect to %s:%s:%s",
                 _np_network_get_protocol_string(context, type),
                 hostname,
                 service);
        log_warn(LOG_NETWORK,
                 "could not statically connect to %s:%s:%s ERROR: %s (%d)",
                 _np_network_get_protocol_string(context, type),
                 hostname,
                 service,
                 strerror(errno),
                 errno);
      }
      do {
        connection_status =
            connect(ng->socket, ng->addr_in->ai_addr, ng->addr_in->ai_addrlen);
        l_errno = errno;
        if (connection_status != 0 && l_errno != EISCONN) {
          // As we do have a async connection (and TCP may need longer due to
          // handshake packages) we need to check the connection status for a
          // moment
          log_debug(LOG_NETWORK | LOG_VERBOSE,
                    "trying connect: %" PRId32 " (%s)",
                    connection_status,
                    strerror(l_errno));
          np_time_sleep(NP_PI / 100);
        }
      } while (0 != connection_status && retry_connect-- > 0 &&
               l_errno != EISCONN);
    }

    if (0 != connection_status) {
      log_error("network: %p could not connect to %s:%s:%s ERROR: %s (%d)",
                ng,
                _np_network_get_protocol_string(context, type),
                hostname,
                service,
                strerror(errno),
                errno);
      __np_network_close(ng);
      return false;
    }

    if (FLAG_CMP(type, IPv6) && !FLAG_CMP(type, PASSIVE)) {
      __set_v6_only_false(ng->socket);
    }
    if (FLAG_CMP(type, TCP)) {
      // __set_keepalive(ng->socket);
    }
    __set_non_blocking(ng->socket);

    log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                  "network: %d %p %p :",
                  ng->socket,
                  &ng->watcher_out,
                  &ng->watcher_out.data);

    // initialize to be on the safe side
    //        np_node_t* my_node = _np_key_get_node(context->my_node_key);
    /*        if (FLAG_CMP(my_node->protocol, PASSIVE) || FLAG_CMP(type,
       PASSIVE))
            {
                ng->type |= np_network_type_server;
                ev_io_init(
                    &ng->watcher_out, _np_network_bidirektional,
                    ng->socket, EV_WRITE | EV_READ);
                log_debug_msg(LOG_NETWORK | LOG_DEBUG, "%p -> %d network is
       bidirektional", ng, ng->socket);
            }
            else
            if (FLAG_CMP(type, TCP) || FLAG_CMP(type, UDP))
            {
    */
    ev_io_init(&ng->watcher_out, _np_network_write, ng->socket, EV_WRITE);
    log_debug_msg(LOG_NETWORK | LOG_DEBUG,
                  "%p -> %d network is sender",
                  ng,
                  ng->socket);
    /*      }
          else
          {
              log_debug_msg(LOG_NETWORK | LOG_DEBUG, "don't know how to setup
       client network of type %"PRIu8, type);
          }*/
    ((_np_network_data_t *)ng->watcher_out.data)->network = ng;

    ng->initialized = true;
    log_debug_msg(LOG_NETWORK | LOG_DEBUG, "created local sending socket");
  }

  if (ng->addr_in != NULL) {
    memset((char *)&ng->remote_addr, 0, sizeof(ng->remote_addr));
    ng->remote_addr = calloc(1, ng->addr_in->ai_addrlen);
    CHECK_MALLOC(ng->remote_addr);

    ng->remote_addr_len = ng->addr_in->ai_addrlen;
    memcpy(ng->remote_addr, ng->addr_in->ai_addr, ng->addr_in->ai_addrlen);
  }

  log_info(LOG_NETWORK,
           "Init %s network %s %s on %s:%s (fd: %d%s)",
           create_server ? "server" : "client",
           FLAG_CMP(type, TCP)   ? "TCP"
           : FLAG_CMP(type, UDP) ? "UDP"
                                 : "?",
           FLAG_CMP(type, PASSIVE) ? "PASSIVE" : "",
           hostname,
           service,
           ng->socket,
           prepared_socket_fd > 0 ? " (prepared fd)" : "");
  return ng->initialized;
}

void _np_network_disable(np_network_t *self) {
  if (self != NULL) {
    np_ctx_memory(self);
    TSP_SET(self->can_be_enabled, false);
    _np_network_stop(self, true);
  }
}

void _np_network_enable(np_network_t *self) {
  if (self != NULL) {
    np_ctx_memory(self);
    TSP_SET(self->can_be_enabled, true);
    _np_network_start(self, true);
  }
}

void _np_network_set_key(np_network_t *self, np_dhkey_t dhkey) {
  _np_dhkey_assign(&((_np_network_data_t *)self->watcher_in.data)->owner_dhkey,
                   &dhkey);
  _np_dhkey_assign(&((_np_network_data_t *)self->watcher_out.data)->owner_dhkey,
                   &dhkey);
}
