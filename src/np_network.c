//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
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
#include <ifaddrs.h>
#include <inttypes.h>
#include <net/if.h>
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

enum _np_network_runtime_status {
  np_network_stopped = 0,
  np_network_server_started,
  np_network_client_started,
};

np_module_struct(network) {
  np_state_t *context;

  /**
   * @brief Runtime constant how many messages per second this node can handle,
   * set to 0 to disable.
   */
  uint16_t max_msgs_per_sec;

  TSP(np_bloom_t *, __msgs_per_sec_in);
  TSP(np_bloom_t *, __msgs_per_sec_out);
};

bool __np_network_module_periodic_capacity_reset(
    np_state_t *context, NP_UNUSED np_util_event_t event) {
  uint32_t last_msgs_per_sec_in = 0, last_msgs_per_sec_out = 0;

  if (np_module_not_initiated(network) ||
      np_module(network)->max_msgs_per_sec == 0)
    return true;

  TSP_SCOPE(np_module(network)->__msgs_per_sec_in) {
    _np_counting_bloom_clear_r(np_module(network)->__msgs_per_sec_in,
                               &last_msgs_per_sec_in);
  }
  TSP_SCOPE(np_module(network)->__msgs_per_sec_out) {
    _np_counting_bloom_clear_r(np_module(network)->__msgs_per_sec_out,
                               &last_msgs_per_sec_out);
  }

  if (last_msgs_per_sec_in > 0 || last_msgs_per_sec_out > 0)
    log_info(LOG_NETWORK,
             NULL,
             "[network capacity] total in:%" PRIu32 " total out:%" PRIu32,
             last_msgs_per_sec_in,
             last_msgs_per_sec_out);
  return true;
}

bool _np_network_module_init(np_state_t *context) {
  if (!np_module_initiated(network)) {
    np_module_malloc(network);

    _module->max_msgs_per_sec = context->settings->max_msgs_per_sec > 0
                                    ? context->settings->max_msgs_per_sec
                                    : NP_NETWORK_DEFAULT_MAX_MSGS_PER_SEC;
    // TODO should be based on the number of routing/neighbour nodes
    uint32_t filter_size = 8192;

    _module->__msgs_per_sec_in = _np_counting_bloom_create(filter_size, 8, 1);
    TSP_INIT(_module->__msgs_per_sec_in);

    _module->__msgs_per_sec_out = _np_counting_bloom_create(filter_size, 8, 1);
    TSP_INIT(_module->__msgs_per_sec_out);

    // we want max_messages per second "on average"
    // this callback reduces the contained counters by half of the current value
    np_jobqueue_submit_event_periodic(
        context,
        NP_PRIORITY_HIGH,
        0.88,
        0.88,
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
  log_msg(LOG_WARNING, NULL, "Protocol %d is not availabe!", protocol);
#ifdef DEBUG
  // assert(false && "Protocol is not availabe!");
#endif
  return ("UNKNOWN_PROTOCOL");
}

void __np_network_close(np_network_t *self) {
  np_ctx_memory(self);
  log_debug(LOG_NETWORK | LOG_DEBUG,
            NULL,
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

  log_debug(LOG_NETWORK,
            NULL,
            "using getaddrinfo: %d:%s:%s",
            type,
            hostname,
            service);
  if (0 != (err = getaddrinfo(hostname, service, &hints, ai_head))) {
    log_msg(LOG_ERROR,
            NULL,
            "hostname: %s, servicename %s, protocol %d",
            hostname,
            service,
            type);
    log_msg(LOG_ERROR,
            NULL,
            "error getaddrinfo: %s (%d)",
            gai_strerror(err),
            err);
    log_msg(LOG_ERROR,
            NULL,
            "error errno: %s (%d)",
            gai_strerror(errno),
            errno);

    return false;
  }
  return true;
}

bool _np_network_send_data(np_state_t   *context,
                           np_network_t *network,
                           np_dhkey_t    target,
                           void         *data_to_send) {
  ssize_t  write_per_data        = 0;
  uint32_t current_load_capacity = 0;
  bool     ret                   = false;

#ifdef DEBUG
  unsigned char hash[crypto_generichash_BYTES] = {0};
  crypto_generichash(hash,
                     sizeof hash,
                     data_to_send,
                     MSG_CHUNK_SIZE_1024 + MSG_INSTRUCTIONS_SIZE,
                     NULL,
                     0);
  char hex[crypto_generichash_BYTES * 2 + 1] = {0};
  sodium_bin2hex(hex,
                 crypto_generichash_BYTES * 2 + 1,
                 hash,
                 crypto_generichash_BYTES);

  log_debug(LOG_NETWORK | LOG_EXPERIMENT,
            NULL,
            "OUT DATAPACKAGE %s:%s %s",
            network->ip,
            network->port,
            hex);
#endif // DEBUG

  if (np_module_initiated(network) &&
      np_module(network)->max_msgs_per_sec > 0) {
    TSP_SCOPE(np_module(network)->__msgs_per_sec_out) {
      _np_counting_bloom_check_r(np_module(network)->__msgs_per_sec_out,
                                 target,
                                 &current_load_capacity);
    }
  }

  if (current_load_capacity > np_module(network)->max_msgs_per_sec) {
    log_warn(LOG_NETWORK,
             NULL,
             "Re-scheduling data package due to msgs per sec constraint "
             "(current: %" PRIu32 " / max: %" PRIu16 " | OUT)",
             current_load_capacity,
             np_module(network)->max_msgs_per_sec);
    return ret;
  }
  //
  do {
    ssize_t bytes_written = 0;
    if (FLAG_CMP(network->socket_type, PASSIVE)) {
      bytes_written =
          sendto(network->socket,
                 (((unsigned char *)data_to_send)) + write_per_data,
                 MSG_CHUNK_SIZE_1024 + MSG_INSTRUCTIONS_SIZE - write_per_data,
#ifdef MSG_NOSIGNAL
                 MSG_NOSIGNAL,
#else
                 0,
#endif
                 network->remote_addr,
                 network->remote_addr_len);

    } else {
      bytes_written =
          send(network->socket,
               (((unsigned char *)data_to_send)) + write_per_data,
               MSG_CHUNK_SIZE_1024 + MSG_INSTRUCTIONS_SIZE - write_per_data,
#ifdef MSG_NOSIGNAL
               MSG_NOSIGNAL
#else
               0
#endif
          );
    }

    if (bytes_written > 0 &&
        bytes_written <= (MSG_CHUNK_SIZE_1024 + MSG_INSTRUCTIONS_SIZE)) {
      write_per_data += bytes_written;
    } else {
      break;
    }

  } while (write_per_data < (MSG_CHUNK_SIZE_1024 + MSG_INSTRUCTIONS_SIZE));

  if (write_per_data == (MSG_CHUNK_SIZE_1024 + MSG_INSTRUCTIONS_SIZE)) {
    _np_statistics_add_send_bytes(write_per_data);

    network->last_send_date = np_time_now();
    ret                     = true;
    log_debug(LOG_NETWORK,
              NULL,
              "Did send package %p via %p -> %d",
              data_to_send,
              network,
              network->socket);

    if (np_module(network)->max_msgs_per_sec > 0)
      TSP_SCOPE(np_module(network)->__msgs_per_sec_out) {
        _np_counting_bloom_add(np_module(network)->__msgs_per_sec_out, target);
      }
  } else {
    log_error(NULL,
              "Could not send package %p (%zd/%d) over fd: %d msg: %s (%d)",
              data_to_send,
              write_per_data,
              MSG_CHUNK_SIZE_1024 + MSG_INSTRUCTIONS_SIZE,
              network->socket,
              strerror(errno),
              errno);
  }
  return ret;
}

void _np_network_write(struct ev_loop *loop, ev_io *event, int revents) {
  np_ctx_decl(ev_userdata(loop));

  if (FLAG_CMP(revents, EV_ERROR) || FLAG_CMP(revents, EV_READ)) {
    log_debug(LOG_NETWORK, NULL, "got invalid write event");
    return;
  }

  if (event->data == NULL) return;

  np_network_t *network = ((_np_network_data_t *)event->data)->network;

  _TRYLOCK_ACCESS(&network->access_lock) {
    // if a data packet is available, try to send it
    if (sll_size(network->out_events) > 0) {
      if (_np_network_send_data(
              context,
              network,
              ((_np_network_data_t *)event->data)->owner_dhkey,
              sll_first(network->out_events)->val)) {
        void *data_to_send = sll_head(void_ptr, network->out_events);
        np_unref_obj(BLOB_1024, data_to_send, ref_obj_usage);
      }
    }

#ifdef DEBUG
    if (sll_size(network->out_events) > 0) {
      log_debug(LOG_NETWORK,
                NULL,
                "%" PRIu32 " packages still in delivery",
                sll_size(network->out_events));
    }
#endif

    if (sll_size(network->out_events) == 0) {
      EV_P;
      loop = _np_event_get_loop_out(context);
      ev_io_stop(EV_A_ & network->watcher_out);
      log_debug(LOG_NETWORK,
                np_memory_get_id(network),
                "network has been stopped for sending: %d:%s:%s",
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
             NULL,
             "rejecting possible udp connection as jobqueue is rejecting it");
    np_unref_obj(np_node_t, new_node, FUNC);
  }
  np_unref_obj(np_key_t, temp_alias_key, "_np_keycache_find_or_create");
}

void _np_network_accept(struct ev_loop *loop, ev_io *event, int revents) {
  np_ctx_decl(ev_userdata(loop));

  if (FLAG_CMP(revents, EV_ERROR) || FLAG_CMP(revents, EV_WRITE)) {
    log_debug(LOG_NETWORK | LOG_DEBUG, NULL, "got invalid tcp accept event");
    return;
  }

  struct __np_network_data data_container = {0};
  socklen_t                fromlen        = sizeof(struct sockaddr_storage);

  np_network_t *ng = ((_np_network_data_t *)event->data)->network;

  int client_fd =
      accept(ng->socket, (struct sockaddr *)&data_container.from, &fromlen);

  if (client_fd < 0) {
    if (errno != EWOULDBLOCK && errno != EAGAIN) {
      log_msg(LOG_ERROR,
              NULL,
              "Could not accept socket connection on client fd %d. %s (%d)",
              ng->socket,
              strerror(errno),
              errno);
    }
  } else {
    __np_network_get_ip_and_port(&data_container);

    log_debug(LOG_NETWORK | LOG_DEBUG,
              NULL,
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
                         context->settings->max_msgs_per_sec,
                         client_fd,
                         UNKNOWN_PROTO)) {
      new_network->is_multiuse_socket = false;
      // it could be a passive socket

      np_dhkey_t search_key =
          np_dhkey_create_from_hostport(&data_container.ipstr[0],
                                        &data_container.port[0]);
      np_key_t *alias_key = _np_keycache_find_or_create(context, search_key);

      ASSERT(alias_key->entity_array[e_network] == NULL,
             "There should be no network for a tcp connection yet");

      alias_key->entity_array[e_network] = new_network;
      // will be reset to alias key after first (handshake) message
      _np_network_set_key(new_network,
                          ((_np_network_data_t *)event->data)->owner_dhkey);
      // new_network->__tcp_alias_dhkey = search_key;

      log_debug(LOG_NETWORK,
                NULL,
                "%p -> %d network is receiving. alias: %s",
                new_network,
                new_network->socket,
                _np_key_as_str(alias_key));

      _np_network_enable(new_network);
      log_debug(LOG_NETWORK,
                NULL,
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

/**
 ** _np_network_read:
 ** reads the network layer in listen mode.
 ** This function delivers incoming messages to the default message handler
 **/
void _np_network_read(struct ev_loop *loop, ev_io *event, int revents) {
  np_ctx_decl(ev_userdata(loop));
  if (FLAG_CMP(revents, EV_ERROR) || FLAG_CMP(revents, EV_WRITE)) {
    log_debug(LOG_NETWORK, NULL, "got invalid read event");
    return;
  }

  log_debug(LOG_NETWORK, NULL, "Receive started ...");

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
  bool    network_receive_timeout = false;
  int16_t in_msg_len;
  bool    stop = false;

  struct __np_network_data data_container = {0};
  np_new_obj(BLOB_1024, data_container.data);

  in_msg_len = 0;

  // catch a msg even if it was chunked into smaller byte parts by the
  // underlying network
  do {
    if (FLAG_CMP(ng->socket_type, TCP)) {
      last_recv_result =
          recv(event->fd,
               ((char *)data_container.data) + in_msg_len,
               MSG_CHUNK_SIZE_1024 + MSG_INSTRUCTIONS_SIZE - in_msg_len,
               0);
    } else {
      last_recv_result =
          recvfrom(event->fd,
                   ((unsigned char *)data_container.data) + in_msg_len,
                   MSG_CHUNK_SIZE_1024 + MSG_INSTRUCTIONS_SIZE - in_msg_len,
                   0,
                   (struct sockaddr *)&data_container.from,
                   &fromlen);
    }

    if (last_recv_result < 0) {
      log_msg(LOG_NETWORK | LOG_WARNING,
              NULL,
              "Receive stopped. Reason: %s (%" PRId32 "/ %" PRId32 ")",
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
           in_msg_len < (MSG_CHUNK_SIZE_1024 +
                         MSG_INSTRUCTIONS_SIZE)); //! network_receive_timeout);

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
              NULL,
              "Did receive data (%" PRIi16 " bytes / %p) via fd: %d hex: 0x%s",
              in_msg_len,
              data_container.data,
              event->fd,
              msg_hex);
#endif

    if (in_msg_len == MSG_CHUNK_SIZE_1024 + MSG_INSTRUCTIONS_SIZE) {

      np_dhkey_t search_key =
          np_dhkey_create_from_hostport(&data_container.ipstr[0],
                                        &data_container.port[0]);

      uint32_t current_load_capacity = 0;
      if (np_module_initiated(network) &&
          np_module(network)->max_msgs_per_sec > 0) {

        TSP_SCOPE(np_module(network)->__msgs_per_sec_in) {
          _np_counting_bloom_check_r(np_module(network)->__msgs_per_sec_in,
                                     search_key,
                                     &current_load_capacity);
        }
      }
      if (current_load_capacity > np_module(network)->max_msgs_per_sec) {
        log_warn(LOG_WARNING,
                 NULL,
                 "Dropping data package due to msgs per sec constraint "
                 "(current: %" PRIu32 " / max: %" PRIu16 " | IN)",
                 current_load_capacity,
                 np_module(network)->max_msgs_per_sec);
        np_unref_obj(BLOB_1024, data_container.data, ref_obj_creation);
        return;
      }
      msgs_received++;
      if (np_module_initiated(network) &&
          np_module(network)->max_msgs_per_sec > 0) {
        TSP_SCOPE(np_module(network)->__msgs_per_sec_in) {
          _np_counting_bloom_add(np_module(network)->__msgs_per_sec_in,
                                 search_key);
        }
      }

      data_container.in_msg_len = in_msg_len;

      np_key_t *alias_key = _np_keycache_find(context, search_key);

      np_util_event_t in_event = {
          .type      = evt_external | evt_message,
          .user_data = data_container.data,
          // .cleanup = _np_network_read_msg_event_cleanup,
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

      log_debug(LOG_NETWORK | LOG_EXPERIMENT,
                NULL,
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
        char buf[100] = {0};
        log_debug(LOG_NETWORK,
                  NULL,
                  "send data to owner %s",
                  np_id_str(buf, (np_id *)&owner_dhkey));
        if (!np_jobqueue_submit_event(context,
                                      0.0,
                                      owner_dhkey,
                                      in_event,
                                      msg_identifier)) {
          log_error(
              NULL,
              "%s",
              "Dropping data package send to owner as jobqueue is rejecting "
              "it");
        }
      } else if (NULL != alias_key) {
        log_debug(LOG_NETWORK, NULL, "send data to alias");
        if (!np_jobqueue_submit_event(context,
                                      0.0,
                                      alias_key->dhkey,
                                      in_event,
                                      msg_identifier)) {
          log_error(NULL,
                    "%s",
                    "Dropping data package send to alias key as jobqueue is "
                    "rejecting it");
        }
      } else {
        log_debug(LOG_ERROR,
                  NULL,
                  "network in unknown state for key %s",
                  _np_key_as_str(alias_key));
      }

      if (NULL != alias_key) {
        np_unref_obj(np_key_t, alias_key, "_np_keycache_find");
      }
    } else {
      if (network_receive_timeout) {
        log_info(LOG_NETWORK,
                 NULL,
                 "Network receive iteration stopped due to timeout (Received "
                 "Data: %" PRIu16 ")",
                 in_msg_len);
      }

      if (in_msg_len == 0) {
        log_info(LOG_NETWORK,
                 NULL,
                 "Stopping network due to zero size package (%" PRIu16 ")",
                 in_msg_len);
        _np_network_disable(ng);
        // stop = true;
      } else {
        log_info(LOG_NETWORK,
                 NULL,
                 "Dropping data package due to invalid package size (%" PRIu16
                 ")",
                 in_msg_len);
      }
    }
  }

  np_unref_obj(BLOB_1024, data_container.data, ref_obj_creation);
  log_info(LOG_NETWORK | LOG_VERBOSE,
           NULL,
           "Received %" PRIu16 " messages.",
           msgs_received);
}

void _np_network_stop(np_network_t *network, bool force) {
  assert(NULL != network);

  np_ctx_memory(network);

  _LOCK_ACCESS(&network->access_lock) {
    EV_P;
    if (FLAG_CMP(network->is_running, np_network_server_started)) {
      if (FLAG_CMP(network->type, np_network_type_server)) {
        log_debug(LOG_NETWORK | LOG_DEBUG,
                  NULL,
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
        log_debug(LOG_NETWORK | LOG_DEBUG,
                  NULL,
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

  TSP_GET(bool, network->can_be_enabled, can_be_enabled);
  if (can_be_enabled) {
    _LOCK_ACCESS(&network->access_lock) {
      EV_P;
      if (!FLAG_CMP(network->is_running, np_network_server_started)) {
        if (FLAG_CMP(network->type, np_network_type_server)) {
          log_debug(LOG_NETWORK | LOG_DEBUG,
                    NULL,
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
          log_debug(LOG_NETWORK | LOG_DEBUG,
                    NULL,
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
  np_network_t *network = (np_network_t *)data;

  _LOCK_ACCESS(&network->access_lock) {
    if (NULL != network->out_events) {
      while (0 != sll_size(network->out_events)) {
        void *drop_package = sll_head(void_ptr, network->out_events);
        log_info(LOG_NETWORK | LOG_ROUTING | LOG_EXPERIMENT,
                 NULL,
                 "Dropping data package due to network cleanup");
        np_unref_obj(BLOB_1024, drop_package, ref_obj_usage);
      }
    }
    sll_free(void_ptr, network->out_events);
  }

  free(network->watcher_in.data);
  free(network->watcher_out.data);
  free(network->remote_addr);

  if ((network->socket >= 0) && !network->is_multiuse_socket) {
    log_info(LOG_NETWORK,
             NULL,
             "Closing network %p due to object deletion",
             network);
    __np_network_close(network);
  }

  // freeaddrinfo(network->addr_in);
  network->initialized = false;
  // finally destroy the mutex
  _np_threads_mutex_destroy(context, &network->access_lock);
  TSP_DESTROY(network->can_be_enabled);
}

void _np_network_t_new(np_state_t       *context,
                       NP_UNUSED uint8_t type,
                       NP_UNUSED size_t  size,
                       void             *data) {
  np_network_t *ng       = (np_network_t *)data;
  ng->is_multiuse_socket = false;
  ng->socket             = -1;
  // ng->addr_in                 = NULL;
  ng->out_events              = NULL;
  ng->initialized             = false;
  ng->is_running              = np_network_stopped;
  ng->watcher_in.data         = NULL;
  ng->watcher_out.data        = NULL;
  ng->type                    = np_network_type_none;
  ng->last_send_date          = 0.0;
  ng->last_received_date      = 0.0;
  ng->max_messages_per_second = context->settings->max_msgs_per_sec;
  ng->seqend                  = 0;

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
    // log_msg(LOG_NETWORK | LOG_WARNING, NULL, "setsockopt (IPV6_V6ONLY): %s:
    // ", strerror(errno));
  }
}

void __set_non_blocking(int socket) {
  // set non blocking
  int current_flags = fcntl(socket, F_GETFL);
  current_flags |= O_NONBLOCK;
  fcntl(socket, F_SETFL, current_flags);
}

void __set_keepalive(int socket) {
  int yes = 1;
  if (setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes)) < 0) {
    //
  }
}

void __set_tcp_nodelay(int socket) {
  int yes = 1;
  if (setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes)) < 0) {
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
                      uint16_t      max_messages_per_second,
                      int           prepared_socket_fd,
                      socket_type   passive_socket_type) {
  np_ctx_memory(ng);
  int one = 1;

  log_debug(LOG_NETWORK | LOG_DEBUG, NULL, "try to get_network_address");

  struct addrinfo *address_info = NULL;
  bool             res          = _np_network_get_address(context,
                                     create_server,
                                     &address_info,
                                     type,
                                     hostname,
                                     service);

  ng->socket_type = type | passive_socket_type;

  if (!res || (NULL == address_info && !FLAG_CMP(type, PASSIVE))) {
    log_msg(LOG_ERROR, NULL, "could not resolve requested network address");
    return false;
  }

  log_debug(LOG_NETWORK | LOG_DEBUG, NULL, "done get_network_address");

  ng->max_messages_per_second = max_messages_per_second;

  // only need for client setup, but initialize to have zero size of list
  if (ng->out_events == NULL) sll_init(void_ptr, ng->out_events);

  // create an inbound socket - happens only once per target_node
  if (true == create_server) {
    log_debug(LOG_NETWORK | LOG_DEBUG, NULL, "creating receiving network");

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
      ng->socket = socket(address_info->ai_family,
                          address_info->ai_socktype,
                          address_info->ai_protocol);
      if (0 > ng->socket) {
        log_error(NULL, "could not create socket: %s", strerror(errno));
        freeaddrinfo(address_info);
        return false;
      }
      /* attach socket to #port#. */
      if (-1 == setsockopt(ng->socket,
                           SOL_SOCKET,
                           SO_REUSEADDR,
                           (void *)&one,
                           sizeof(one))) {
        log_error(NULL,
                  "network: %p setsockopt (SO_REUSEADDR): %s: ",
                  ng,
                  strerror(errno));
        __np_network_close(ng);
        freeaddrinfo(address_info);
        return false;
      }
      if (0 >
          bind(ng->socket, address_info->ai_addr, address_info->ai_addrlen)) {
        // UDP note: not using a connected socket for sending messages to a
        // different target_node leads to unreliable delivery. The sending
        // socket changes too often to be useful for finding the correct
        // decryption shared secret. Especially true for ipv6 ...
        log_error(NULL,
                  "network: %p bind failed for %s:%s :: %s",
                  ng,
                  hostname,
                  service,
                  strerror(errno));
        __np_network_close(ng);
        freeaddrinfo(address_info);
        // listening port could not be opened
        return false;
      }
      if (FLAG_CMP(type, TCP) && 0 > listen(ng->socket, 10)) {
        log_error(NULL,
                  "network: %p listen on tcp port failed: %s:",
                  ng,
                  strerror(errno));
        __np_network_close(ng);
        freeaddrinfo(address_info);
        return false;
      }
    }

    if (FLAG_CMP(type, IPv6)) {
      __set_v6_only_false(ng->socket);
    }
    if (FLAG_CMP(type, TCP)) {
      __set_tcp_nodelay(ng->socket);
    }
    __set_non_blocking(ng->socket);

    if (FLAG_CMP(type, TCP) && prepared_socket_fd < 1) {
      log_debug(LOG_NETWORK | LOG_DEBUG,
                NULL,
                "%p -> %d network is receiving accepts",
                ng,
                ng->socket);
      ev_io_init(&ng->watcher_in, _np_network_accept, ng->socket, EV_READ);
    } else if (FLAG_CMP(type, UDP) ||
               (FLAG_CMP(type, TCP) && prepared_socket_fd > 1)) {
      log_debug(LOG_NETWORK | LOG_DEBUG,
                NULL,
                "%p -> %d network is receiving",
                ng,
                ng->socket);
      ev_io_init(&ng->watcher_in, _np_network_read, ng->socket, EV_READ);
    } else {
      log_debug(LOG_NETWORK | LOG_DEBUG,
                NULL,
                "don't know how to setup server network of type %" PRIu16,
                type);
    }
    ((_np_network_data_t *)ng->watcher_in.data)->network = ng;

    ng->initialized = true;
    log_debug(LOG_NETWORK, NULL, "created local listening socket");
  } else {
    log_debug(LOG_NETWORK | LOG_DEBUG, NULL, "creating sending network");

    ng->type |= np_network_type_client;

    int l_errno           = 0;
    int retry_connect     = 3;
    int connection_status = 0;

    // client socket - wait for writeable socket
    if (prepared_socket_fd > 0) {
      ng->socket             = prepared_socket_fd;
      ng->is_multiuse_socket = true;
    } else {
      ng->socket = socket(address_info->ai_family,
                          address_info->ai_socktype,
                          address_info->ai_protocol);
      if (0 > ng->socket) {
        log_error(NULL, "could not create socket: %s", strerror(errno));
        freeaddrinfo(address_info);
        return false;
      }
      if (-1 == setsockopt(ng->socket,
                           SOL_SOCKET,
                           SO_REUSEADDR,
                           (void *)&one,
                           sizeof(one))) {
        log_error(NULL,
                  "network: %p setsockopt (SO_REUSEADDR): %s: ",
                  ng,
                  strerror(errno));
        __np_network_close(ng);
        freeaddrinfo(address_info);
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
                     NULL,
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
                     NULL,
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
                 NULL,
                 "could not statically connect to %s:%s:%s",
                 _np_network_get_protocol_string(context, type),
                 hostname,
                 service);
        log_warn(LOG_NETWORK,
                 NULL,
                 "could not statically connect to %s:%s:%s ERROR: %s (%d)",
                 _np_network_get_protocol_string(context, type),
                 hostname,
                 service,
                 strerror(errno),
                 errno);
      }
      do {
        connection_status = connect(ng->socket,
                                    address_info->ai_addr,
                                    address_info->ai_addrlen);
        l_errno           = errno;
        if (connection_status != 0 && l_errno != EISCONN) {
          // As we do have a async connection (and TCP may need longer due to
          // handshake packages) we need to check the connection status for a
          // moment
          log_debug(LOG_NETWORK | LOG_VERBOSE,
                    NULL,
                    "trying connect: %" PRId32 " (%s)",
                    connection_status,
                    strerror(l_errno));
          np_time_sleep(NP_PI / 100);
        }
      } while (0 != connection_status && retry_connect-- > 0 &&
               l_errno != EISCONN);
    }

    if (0 != connection_status) {
      log_error(NULL,
                "network: %p could not connect to %s:%s:%s ERROR: %s (%d)",
                ng,
                _np_network_get_protocol_string(context, type),
                hostname,
                service,
                strerror(errno),
                errno);
      __np_network_close(ng);
      freeaddrinfo(address_info);
      return false;
    }

    if (FLAG_CMP(type, IPv6) && !FLAG_CMP(type, PASSIVE)) {
      __set_v6_only_false(ng->socket);
    }
    if (FLAG_CMP(type, TCP)) {
      __set_tcp_nodelay(ng->socket);
    }
    __set_non_blocking(ng->socket);

    log_debug(LOG_NETWORK | LOG_DEBUG,
              NULL,
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
                log_debug(LOG_NETWORK | LOG_DEBUG, NULL, "%p -> %d network is
       bidirektional", ng, ng->socket);
            }
            else
            if (FLAG_CMP(type, TCP) || FLAG_CMP(type, UDP))
            {
    */
    ev_io_init(&ng->watcher_out, _np_network_write, ng->socket, EV_WRITE);
    log_debug(LOG_NETWORK | LOG_DEBUG,
              NULL,
              "%p -> %d network is sender",
              ng,
              ng->socket);
    /*      }
          else
          {
              log_debug(LOG_NETWORK | LOG_DEBUG, NULL, "don't know how to setup
       client network of type %"PRIu8, type);
          }*/
    ((_np_network_data_t *)ng->watcher_out.data)->network = ng;

    ng->initialized = true;
    log_debug(LOG_NETWORK | LOG_DEBUG, NULL, "created local sending socket");
  }

  if (address_info != NULL) {
    memset((char *)&ng->remote_addr, 0, sizeof(ng->remote_addr));
    ng->remote_addr = calloc(1, address_info->ai_addrlen);
    CHECK_MALLOC(ng->remote_addr);

    ng->remote_addr_len = address_info->ai_addrlen;
    memcpy(ng->remote_addr, address_info->ai_addr, address_info->ai_addrlen);
  }

  freeaddrinfo(address_info);

  log_info(LOG_NETWORK,
           NULL,
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

uint8_t _np_network_count_common_tuples(NP_UNUSED const np_network_t *ng,
                                        const char                   *remote_ip,
                                        const char *local_ip) {

  uint8_t common_tuples = 0;

  char *colon_pos_r = strchr(remote_ip, ':');
  char *colon_pos_l = strchr(local_ip, ':');

  if ((colon_pos_l != NULL && colon_pos_r == NULL) ||
      (colon_pos_l == NULL && colon_pos_r != NULL))
    return common_tuples;

  if (colon_pos_r == NULL) { // IPv4

    struct in_addr ipv4_remote, ipv4_node;
    if (inet_pton(AF_INET, remote_ip, &ipv4_remote) == 1 &&
        inet_pton(AF_INET, local_ip, &ipv4_node) == 1) {

      uint32_t r_addr = ntohl(ipv4_remote.s_addr);
      uint32_t n_addr = ntohl(ipv4_node.s_addr);

      uint32_t diff = r_addr ^ n_addr;
      common_tuples = __builtin_clz(diff) >> 3;

      // Compare each octet
      // for (int i = 0; i < 4; i++) {
      //   uint8_t r_octet = (r_addr >> (24 - i * 8)) & 0xFF;
      //   uint8_t n_octet = (n_addr >> (24 - i * 8)) & 0xFF;
      //   if (r_octet == n_octet) {
      //     common_tuples++;
      //   } else {
      //     break;
      //   }
      // }
    }
  } else { // IPv6

    struct in6_addr ipv6_remote, ipv6_local;
    if (inet_pton(AF_INET6, remote_ip, &ipv6_remote) == 1 &&
        inet_pton(AF_INET6, local_ip, &ipv6_local) == 1) {
      // Compare each byte pair and increment common_tuples for matching blocks
      for (int i = 0; i < 16; i += 2) {
        if (ipv6_remote.s6_addr[i] == ipv6_local.s6_addr[i] &&
            ipv6_remote.s6_addr[i + 1] == ipv6_local.s6_addr[i + 1]) {
          common_tuples++;
        } else {
          break;
        }
      }
    }
  }
  return common_tuples;
}

enum np_return _np_network_get_outgoing_ip(NP_UNUSED const np_network_t *ng,
                                           const char                   *ip,
                                           const socket_type             type,
                                           char *local_ip) {

  assert(FLAG_CMP(type, IPv4) || FLAG_CMP(type, IPv6));

  enum np_return  ret = np_operation_failed;
  struct addrinfo hints, *res, *p;
  int             sockfd;
  char            service[6];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = (type & IPv4) ? AF_INET : AF_INET6;
  // hints.ai_socktype = (type & TCP) ? SOCK_STREAM : SOCK_DGRAM;
  hints.ai_socktype = SOCK_DGRAM;
  snprintf(service, sizeof(service), "%d", /* FLAG_CMP(type, TCP) ? 80 :*/ 53);

  if (getaddrinfo(ip, service, &hints, &res) != 0) {
    return np_invalid_argument;
  }

  for (p = res; p != NULL; p = p->ai_next) {
    sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sockfd == -1) continue;

    if (connect(sockfd, p->ai_addr, p->ai_addrlen) != -1) {
      struct sockaddr_storage local_addr;
      socklen_t               addr_len = sizeof(local_addr);

      if (getsockname(sockfd, (struct sockaddr *)&local_addr, &addr_len) == 0) {
        if (local_addr.ss_family == AF_INET) {
          struct sockaddr_in *s = (struct sockaddr_in *)&local_addr;
          inet_ntop(AF_INET, &s->sin_addr, local_ip, INET_ADDRSTRLEN);
        } else if (local_addr.ss_family == AF_INET6) {
          struct sockaddr_in6 *s = (struct sockaddr_in6 *)&local_addr;
          inet_ntop(AF_INET6, &s->sin6_addr, local_ip, INET6_ADDRSTRLEN);
        }
        close(sockfd);
        ret = np_ok;
        break;
      }
    }
    close(sockfd);
  }

  freeaddrinfo(res);
  return ret;
}

bool _np_network_is_loopback_address(NP_UNUSED const np_network_t *ng,
                                     const char                   *ip) {
  return strncmp(ip, "127.0.0.1", 9) == 0 || strncmp(ip, "::1", 3) == 0;
}

bool _np_network_is_private_address(NP_UNUSED np_network_t *ng,
                                    const char             *ip) {
  // Check if the IP is IPv4 or IPv6
  struct in_addr  ipv4_addr;
  struct in6_addr ipv6_addr;
  bool            is_ipv4 = inet_pton(AF_INET, ip, &ipv4_addr) == 1;
  bool            is_ipv6 = inet_pton(AF_INET6, ip, &ipv6_addr) == 1;

  if (!is_ipv4 && !is_ipv6) {
    return false; // Invalid IP address
  }

  if (is_ipv4) {
    uint32_t ip_int = ntohl(ipv4_addr.s_addr);

    // Check IPv4 private ranges
    return ((ip_int >= 0x0A000000 &&
             ip_int <= 0x0AFFFFFF) || // 10.0.0.0 to 10.255.255.255
            (ip_int >= 0xAC100000 &&
             ip_int <= 0xAC1FFFFF) || // 172.16.0.0 to 172.31.255.255
            (ip_int >= 0xC0A80000 &&
             ip_int <= 0xC0A8FFFF) // 192.168.0.0 to 192.168.255.255
    );
  } else { // IPv6
    // Check if it's a unique local address (fc00::/7)
    // or link local address (fe80::/7)
    return (ipv6_addr.s6_addr[0] == 0xFC || ipv6_addr.s6_addr[0] == 0xFD ||
            (ipv6_addr.s6_addr[0] == 0xFE && ipv6_addr.s6_addr[1] == 0x80));
  }
}

enum np_return _np_network_get_local_ip(NP_UNUSED const np_network_t *ng,
                                        const char                   *hostname,
                                        const socket_type             type,
                                        char *local_ip) {

  assert(hostname != NULL);
  assert(local_ip != NULL);
  // assert(FLAG_CMP(type, IPv4) || FLAG_CMP(type, IPv6));

  enum np_return ret = np_operation_failed;

  struct ifaddrs *ifaddr;

  if (getifaddrs(&ifaddr) == -1) {
    // perror("getifaddrs");
    return (ret);
  }

  struct ifaddrs *ifa = NULL;
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) continue;

    char host[NI_MAXHOST];
    char host_ip[INET6_ADDRSTRLEN + 1];
    int  name_result = 0;

    if (ifa->ifa_addr->sa_family == AF_INET && FLAG_CMP(type, IPv4)) {
      struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
      inet_ntop(AF_INET, &sa->sin_addr, host_ip, INET_ADDRSTRLEN);
      name_result = getnameinfo(ifa->ifa_addr,
                                sizeof(struct sockaddr_in),
                                host,
                                NI_MAXHOST,
                                NULL,
                                0,
                                NI_NAMEREQD);
    } else if (ifa->ifa_addr->sa_family == AF_INET6 && FLAG_CMP(type, IPv6)) {
      struct sockaddr_in6 *sa = (struct sockaddr_in6 *)ifa->ifa_addr;
      inet_ntop(AF_INET6, &sa->sin6_addr, host_ip, INET6_ADDRSTRLEN);
      name_result = getnameinfo(ifa->ifa_addr,
                                sizeof(struct sockaddr_in6),
                                host,
                                NI_MAXHOST,
                                NULL,
                                0,
                                NI_NAMEREQD);
    } else {
      continue;
    }

    if (strncmp(host_ip, hostname, INET6_ADDRSTRLEN + 1) == 0) {
      // ip addresses already match
      strncpy(local_ip, host_ip, INET6_ADDRSTRLEN + 1);
      ret = np_ok;
      break;
    } else if (name_result == 0 && 0 == strncmp(host, hostname, 255)) {
      strncpy(local_ip, host_ip, INET6_ADDRSTRLEN + 1);
      ret = np_ok;
      break;
    } else {
      // log_msg(LOG_DEBUG, NULL, "NOT OK: %s -> %s", host_ip, host);
    }
  }
  freeifaddrs(ifaddr);

  return (ret);
}

enum np_return _np_network_get_remote_ip(np_context       *context,
                                         const char       *hostname,
                                         const socket_type protocol,
                                         char             *remote_ip) {
  assert(hostname != NULL);
  assert(remote_ip != NULL);
  assert(FLAG_CMP(protocol, IPv4) || FLAG_CMP(protocol, IPv6));

  enum np_return   ret         = np_ok;
  struct addrinfo *adress_info = NULL;
  struct addrinfo  hints       = {0};

  hints.ai_family   = (protocol & IPv4) ? AF_INET : AF_INET6;
  hints.ai_socktype = (protocol & UDP) ? SOCK_DGRAM : SOCK_STREAM;
  hints.ai_flags    = AI_ADDRCONFIG;

  int status = getaddrinfo(hostname, NULL, &hints, &adress_info);
  if (status != 0) {
    // log_msg(LOG_ERROR | LOG_NETWORK,
    //         NULL,
    //         "getaddrinfo error: %s",
    //         gai_strerror(status));
    return np_operation_failed;
  }

  // Iterate through results and get the first IP address
  for (struct addrinfo *rp = adress_info; rp != NULL; rp = rp->ai_next) {
    void *addr = NULL;
    if (rp->ai_family == AF_INET) { // IPv4
      struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
      addr                     = &(ipv4->sin_addr);
    } else if (rp->ai_family == AF_INET6) { // IPv6
      struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
      addr                      = &(ipv6->sin6_addr);
    } else {
      continue;
    }

    // Convert IP to string
    if (inet_ntop(rp->ai_family, addr, remote_ip, INET6_ADDRSTRLEN) != NULL) {
      ret = np_ok;
      break;
    }
  }

  freeaddrinfo(adress_info);
  return ret;
}

void _np_network_disable(np_network_t *self) {
  if (self != NULL) {
    TSP_SET(self->can_be_enabled, false);
    _np_network_stop(self, true);
  }
}

void _np_network_enable(np_network_t *self) {
  if (self != NULL) {
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
