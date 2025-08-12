//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "tuntap/np_tuntap.h"

#include "neuropil_attributes.h"

#include "util/np_pcg_rng.h"

#include "np_evloop.h"
#include "np_legacy.h"

// implementation is just pushed to the different platform specific files
#ifdef __linux__
#include "np_tuntap_linux.c"

#elif defined(__FreeBSD__)
#include "np_tuntap_freebsd.c"

#elif defined(__OpenBSD__)
#include "np_tuntap_openbsd.c"

#elif defined(__APPLE__) && defined(__MACH__)

#include "tuntap/np_tuntap_darwin.c"
#elif defined(_WIN32) || defined(_WIN64)
#include "np_tuntap_win.c"

#else
#error "Platform not yet supported"
#endif

static const char *_NP_TUNTAP_CTL  = "urn:np:tuntap:control:v1";
static const char *_NP_TUNTAP_DATA = "urn:np:tuntap:data:v1";

static uint16_t TUNTAP_MAX_TTL = 3600;
static uint16_t TUNTAP_MIN_TTL = 30;

struct np_raw_ip_paket {
  unsigned char *buffer;
  size_t         size;
};

void _shutdown_tuntap(np_context *ac) {
  struct np_tuntap *tt = (struct np_tuntap *)np_get_userdata(ac);
  np_tuntap_stop(ac, tt);
  np_tuntap_destroy(ac, tt);
}

bool _handle_tuntap_traffic(np_context *ac, struct np_message *msg) {
  np_state_t *context = ac;

  struct np_tuntap *tt = (struct np_tuntap *)np_get_userdata(ac);

  struct np_raw_ip_paket packet = {.buffer = msg->data,
                                   .size   = msg->data_length};

  // Validate packet data
  if (packet.buffer == NULL || packet.size < sizeof(struct ip)) {
    log_msg(LOG_ERROR,
            NULL,
            "Invalid packet data: buffer=%p, size=%zu",
            packet.buffer,
            packet.size);
    return false;
  }

  char       destination_ip[INET_ADDRSTRLEN + 1];
  struct ip *ip = (struct ip *)packet.buffer;

  log_msg(LOG_DEBUG,
          NULL,
          "received packet data: buffer=%p, size=%zu, IP version=%d",
          packet.buffer,
          packet.size,
          ip->ip_v);

  // Validate IP version
  if (ip->ip_v != 4) {
    log_msg(LOG_ERROR, NULL, "IP [version %d != 4] (invalid)", ip->ip_v);
    return false;
  }

  // Validate packet size
  uint16_t ip_total_length = ntohs(ip->ip_len);
  if (packet.size != ip_total_length) {
    log_msg(LOG_ERROR,
            NULL,
            "Packet size mismatch: expected %u, got %zu",
            ip_total_length,
            packet.size);
    return false;
  }

  // Basic IP header validation
  if (ip->ip_hl < 5) { // IP header length must be at least 5 32-bit words
    log_msg(LOG_ERROR, NULL, "Invalid IP header length: %d", ip->ip_hl);
    return false;
  }

  // IPv4 packet
  inet_ntop(AF_INET, &ip->ip_dst, destination_ip, INET_ADDRSTRLEN);

  log_msg(LOG_DEBUG,
          NULL,
          "received packet (size %" PRIsizet "), for target IP %s",
          packet.size,
          destination_ip);

// For all other destinations, write to the TUN device as before
#if defined(__APPLE__) && defined(__MACH__)
  uint32_t     af     = htonl(AF_INET);
  struct iovec iov[2] = {
      {          .iov_base = &af,  .iov_len = sizeof(af)},
      {.iov_base = packet.buffer, .iov_len = packet.size}
  };
  ssize_t written = writev(tt->tuntap_fd, iov, 2);
#else
  ssize_t written = write(tt->tuntap_fd, packet.buffer, packet.size);
#endif

  size_t written_bytes = write(tt->tuntap_fd, packet.buffer, packet.size);
  if (written_bytes < 0) {
    log_msg(LOG_ERROR,
            NULL,
            "Failed to send packet via raw socket: %s",
            strerror(errno));
  }

#if defined(__APPLE__) && defined(__MACH__)
  if (written_bytes != packet.size + 4) {
#else
  if (written_bytes != packet.size) {
#endif
    log_msg(LOG_ERROR,
            NULL,
            "Size mismatch of packet: %d != %d",
            packet.size,
            written_bytes);
  }
  return true;
}

bool _tuntap_authorize_data(np_context *ac, struct np_token *token) {
  np_state_t *context = ac;
  // log_msg(LOG_INFO, token->uuid, "received tuntap data request");
  return true;
}

bool _tuntap_authorize_peers(np_context *ac, struct np_token *token) {
  NP_CAST(ac, np_state_t, context);
  struct np_tuntap *tt = np_get_userdata(ac);

  struct np_data_conf  attr_conf = {0};
  struct np_data_conf *conf      = &attr_conf;

  unsigned char *domain_ptr = NULL;
  if (np_data_ok !=
      np_get_token_attr_bin(token, "DOMAIN", &conf, &domain_ptr)) {
    log_msg(LOG_DEBUG, NULL, "no domain info in peer request, rejecting");
    return false;
  }

  if (strnlen((char *)tt->domain, 255) != conf->data_size ||
      0 != strncmp((char *)tt->domain, (char *)domain_ptr, conf->data_size)) {
    log_msg(LOG_DEBUG,
            NULL,
            "domain info in peer request (%" PRIsizet
            " -> %s) doesn't match (%" PRIsizet
            " -> %s), "
            "rejecting",
            conf->data_size,
            domain_ptr,
            strnlen((char *)tt->domain, 255),
            tt->domain);
    return false;
  }

  struct np_data_conf  netmask_conf     = {0};
  struct np_data_conf *netmask_conf_ptr = &netmask_conf;
  unsigned char       *netmask_ptr      = NULL;
  if (np_data_ok != np_get_token_attr_bin(token,
                                          "NETMASK",
                                          &netmask_conf_ptr,
                                          &netmask_ptr)) {
    log_msg(LOG_DEBUG, NULL, "no netmask info in peer request, rejecting");
    return false;
  }
  if (strnlen((char *)tt->netmask, 255) != netmask_conf.data_size ||
      0 != strncmp((char *)tt->netmask,
                   (char *)netmask_ptr,
                   netmask_conf.data_size)) {
    log_msg(LOG_DEBUG,
            NULL,
            "netmask in peer request doesn't match, rejecting");
    return false;
  }

  struct np_data_conf  ip_conf     = {0};
  struct np_data_conf *ip_conf_ptr = &ip_conf;

  unsigned char *ip_ptr = NULL;
  if (np_data_ok != np_get_token_attr_bin(token, "IP", &ip_conf_ptr, &ip_ptr)) {
    log_msg(LOG_DEBUG, NULL, "no ip info in peer request, rejecting");
    return false;
  }

  if (strnlen((char *)tt->ip, 255) != ip_conf.data_size ||
      0 == strncmp((char *)tt->ip, (char *)ip_ptr, ip_conf.data_size)) {
    log_msg(LOG_DEBUG,
            NULL,
            "ip in peer request (%s) conflicts with ours, rejecting",
            ip_ptr);
    return false;
  }

  if (false == context->authorize_func(context, token)) {
    return false;
  }

  np_subject connect_to = {0};
  // establish data send-to network
  np_generate_subject(&connect_to,
                      _NP_TUNTAP_DATA,
                      strnlen(_NP_TUNTAP_DATA, 256));
  np_generate_subject(&connect_to,
                      (char *)tt->domain,
                      strnlen((char *)tt->domain, 256));
  np_generate_subject(&connect_to, (char *)ip_ptr, ip_conf.data_size);
  np_generate_subject(&connect_to, (char *)netmask_ptr, netmask_conf.data_size);

  struct np_mx_properties tuntap_properties =
      np_get_mx_properties(ac, connect_to);

  tuntap_properties.role                = NP_MX_PROVIDER;
  tuntap_properties.audience_type       = NP_MX_AUD_PRIVATE;
  tuntap_properties.ackmode             = NP_MX_ACK_NONE;
  tuntap_properties.max_retry           = 1;
  tuntap_properties.message_ttl         = 5.0;
  tuntap_properties.max_parallel        = 1;
  tuntap_properties.cache_size          = 20;
  tuntap_properties.cache_policy        = NP_MX_FIFO_PURGE;
  tuntap_properties.intent_ttl          = TUNTAP_MAX_TTL;
  tuntap_properties.intent_update_after = TUNTAP_MIN_TTL;

  np_set_mx_properties(ac, connect_to, tuntap_properties);
  np_set_mx_authorize_cb(ac, connect_to, _tuntap_authorize_data);
  np_add_receive_cb(ac, connect_to, _handle_tuntap_traffic);

  unsigned char *routing_ptr = NULL;
  if (np_data_ok ==
      np_get_token_attr_bin(token, "ROUTING", &conf, &routing_ptr)) {
    // set an additional route to the passed network configuration
    char route[16];
    strncpy(route, (char *)routing_ptr, attr_conf.data_size);
    fprintf(stdout, "setting additional route (%s) to network\n", route);
    np_tuntap_route_add(tt, (char *)&tt->ip[0], route, route);
  }

  unsigned char *dns_ptr = NULL;
  if (np_data_ok == np_get_token_attr_bin(token, "DNS", &conf, &dns_ptr)) {
    np_tuntap_dns_add(tt, (char *)&tt->domain[0], (char *)dns_ptr);
  }

  return true;
}

void _np_tuntap_read_callback(struct ev_loop *loop, ev_io *ev, int event_type) {
  np_state_t       *context = ev_userdata(loop);
  struct np_tuntap *tt      = (struct np_tuntap *)ev->data;

  struct np_raw_ip_paket buf = {0};

  if ((event_type & EV_READ) == EV_READ &&
      (event_type & EV_ERROR) != EV_ERROR) {
#if defined(__APPLE__) && defined(__MACH__)
    unsigned char buffer[tt->mtu + 4];
#else
    unsigned char buffer[tt->mtu];
#endif
    buf.buffer = &buffer[0];
    buf.size   = read(tt->tuntap_fd, buf.buffer, tt->mtu);
    if (0 == buf.size) {
      return;
    }

#if defined(__APPLE__) && defined(__MACH__)
    // on osx four bytes are prepended to the network tun network packet
    // indicating the address family. but currently only IPv4 is supported
    buf.buffer = &buffer[4];
    buf.size   = buf.size - 4;
#endif

    char       destination_ip[INET_ADDRSTRLEN + 1];
    char       source_ip[INET_ADDRSTRLEN + 1];
    struct ip *ip = (struct ip *)buf.buffer;
    // IPv4 packet
    inet_ntop(AF_INET, &ip->ip_dst.s_addr, destination_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->ip_src.s_addr, source_ip, INET_ADDRSTRLEN);

    if (strncmp(&destination_ip[0], &tt->ip[0], INET_ADDRSTRLEN) == 0) {
      // packet for our own IP address? let's drop it
      return;
    }

    if (ip->ip_v != 4) {
      log_msg(LOG_ERROR,
              NULL,
              "Cannot send packet with IP version %d",
              ip->ip_v);
      return;
    }

    log_msg(LOG_DEBUG,
            NULL,
            "received packet (size %" PRIsizet "), for target IP %s from %s",
            buf.size,
            destination_ip,
            source_ip);

    // data send to network
    np_subject np_destination = {0};
    np_generate_subject(&np_destination,
                        _NP_TUNTAP_DATA,
                        strnlen(_NP_TUNTAP_DATA, 256));
    np_generate_subject(&np_destination,
                        (char *)tt->domain,
                        strnlen((char *)tt->domain, 256));
    np_generate_subject(&np_destination,
                        destination_ip,
                        strnlen(destination_ip, INET_ADDRSTRLEN));
    np_generate_subject(&np_destination,
                        (char *)tt->netmask,
                        strnlen((char *)tt->netmask, 32));

    if (np_has_receiver_for(context, np_destination)) {
      // send to target via np-subject
      np_send(context, np_destination, buf.buffer, buf.size);

    } else {
      char np_destination_str[65];
      np_id_str(np_destination_str, np_destination);
      log_msg(LOG_DEBUG,
              NULL,
              "no destination for data packet %d (%s: %" PRIsizet
              "), target was: %s ",
              ip->ip_v,
              destination_ip,
              buf.size,
              np_destination_str);
    }
  }
}

void _np_tuntap_write_callback(NP_UNUSED struct ev_loop *loop,
                               ev_io                    *ev,
                               int                       event_type) {
  // np_state_t       *context = ev_userdata(loop);
  struct np_tuntap *tt = (struct np_tuntap *)ev->data;

  // ssize_t rlen;
  if ((FLAG_CMP(event_type, EV_WRITE) && !FLAG_CMP(event_type, EV_ERROR)) &&
      tt->has_data) {
    // nothing to do for now
    // writev(tt->tuntap_fd, packet.buffer, packet.size);
  }
}

void _np_tuntap_stop_evloop(np_context *context, struct np_tuntap *tt) {

  {
    EV_P = _np_event_get_loop_in(context);

    _np_event_suspend_loop_in(context);
    ev_io_stop(EV_A_ & tt->watcher_in);
    _np_event_resume_loop_in(context);
  }
  {
    EV_P = _np_event_get_loop_out(context);

    _np_event_suspend_loop_out(context);
    ev_io_stop(EV_A_ & tt->watcher_out);
    _np_event_resume_loop_out(context);
  }
}

void _np_tuntap_start_evloop(np_context *context, struct np_tuntap *tt) {

  {
    // process incoming traffic
    EV_P = _np_event_get_loop_in(context);

    _np_event_suspend_loop_in(context);

    ev_io_stop(EV_A_ & tt->watcher_in);
    ev_io_init(&tt->watcher_in,
               _np_tuntap_read_callback,
               tt->tuntap_fd,
               EV_READ);
    if (tt->watcher_in.data) free(tt->watcher_in.data);
    tt->watcher_in.data = tt;
    ev_io_start(EV_A_ & tt->watcher_in);
    _np_event_resume_loop_in(context);
  }
  {
    // process outgoing traffic
    EV_P = _np_event_get_loop_out(context);

    _np_event_suspend_loop_out(context);
    ev_io_stop(EV_A_ & tt->watcher_out);
    ev_io_init(&tt->watcher_out,
               _np_tuntap_write_callback,
               tt->tuntap_fd,
               EV_WRITE);
    if (tt->watcher_out.data) free(tt->watcher_out.data);
    tt->watcher_out.data = tt;
    ev_io_start(EV_A_ & tt->watcher_out);

    _np_event_resume_loop_out(context);
  }
}

void _np_tuntap_init_subjects(np_context *ac, struct np_tuntap *tt) {

  NP_CAST(ac, np_state_t, context);

  // discovery of peers
  np_generate_subject(&tt->tt_subject[0],
                      _NP_TUNTAP_CTL,
                      strnlen(_NP_TUNTAP_CTL, 256));
  np_generate_subject(&tt->tt_subject[0],
                      (char *)tt->domain,
                      strnlen((char *)tt->domain, 256));

  struct np_mx_properties tuntap_properties =
      np_get_mx_properties(ac, tt->tt_subject[0]);

  tuntap_properties.role                = NP_MX_PROSUMER;
  tuntap_properties.audience_type       = NP_MX_AUD_VIRTUAL;
  tuntap_properties.ackmode             = NP_MX_ACK_NONE;
  tuntap_properties.message_ttl         = 5.0;
  tuntap_properties.max_retry           = 1;
  tuntap_properties.max_parallel        = 1;
  tuntap_properties.cache_policy        = NP_MX_FIFO_PURGE;
  tuntap_properties.cache_size          = 1;
  tuntap_properties.intent_ttl          = TUNTAP_MAX_TTL;
  tuntap_properties.intent_update_after = TUNTAP_MIN_TTL;

  // tuntap_properties.reply_id            = {0};
  np_set_mx_properties(ac, tt->tt_subject[0], tuntap_properties);
  np_set_mx_authorize_cb(ac, tt->tt_subject[0], _tuntap_authorize_peers);

  char peer_subject_str[65];
  sodium_bin2hex(peer_subject_str,
                 NP_FINGERPRINT_BYTES * 2 + 1,
                 tt->tt_subject[0],
                 NP_FINGERPRINT_BYTES);
  log_msg(LOG_DEBUG,
          NULL,
          "listening on peer subject id : %s",
          peer_subject_str);

  if (np_data_ok != np_set_mxp_attr_bin(ac,
                                        tt->tt_subject[0],
                                        NP_ATTR_INTENT,
                                        "DOMAIN",
                                        (unsigned char *)&tt->domain[0],
                                        strnlen((char *)tt->domain, 255))) {
    log_msg(LOG_DEBUG,
            NULL,
            "could not set attribute for domain : %s",
            tt->domain);
    np_mx_properties_disable(ac, tt->tt_subject[0]);
    tt->status = np_error;
  };

  if (np_data_ok !=
      np_set_mxp_attr_bin(ac,
                          tt->tt_subject[0],
                          NP_ATTR_INTENT,
                          "IP",
                          (unsigned char *)&tt->ip[0],
                          strnlen((char *)tt->ip, INET_ADDRSTRLEN))) {
    log_msg(LOG_DEBUG, NULL, "could not set attribute for ip : %s", tt->ip);
    np_mx_properties_disable(ac, tt->tt_subject[0]);
    tt->status = np_error;
  };
  if (np_data_ok !=
      np_set_mxp_attr_bin(ac,
                          tt->tt_subject[0],
                          NP_ATTR_INTENT,
                          "NETMASK",
                          (unsigned char *)&tt->netmask[0],
                          strnlen((char *)tt->netmask, INET_ADDRSTRLEN))) {
    log_msg(LOG_DEBUG,
            NULL,
            "could not set attribute for netmask : %s",
            tt->netmask);
    np_mx_properties_disable(ac, tt->tt_subject[0]);
    tt->status = np_error;
  };

  // set routing to network for other peers
  if (strnlen((char *)tt->routing, 255) > 0) {
    if (np_data_ok != np_set_mxp_attr_bin(ac,
                                          tt->tt_subject[0],
                                          NP_ATTR_INTENT,
                                          "ROUTING",
                                          (unsigned char *)&tt->routing[0],
                                          strnlen((char *)tt->routing, 255))) {
      np_mx_properties_disable(ac, tt->tt_subject[0]);
      tt->status = np_error;
    };
  }

  // set dns entry for other peers
  if (strnlen((char *)tt->dns, 255) > 0) {
    if (np_data_ok != np_set_mxp_attr_bin(ac,
                                          tt->tt_subject[0],
                                          NP_ATTR_INTENT,
                                          "DNS",
                                          (unsigned char *)&tt->dns[0],
                                          strnlen((char *)tt->dns, 255))) {
      np_mx_properties_disable(ac, tt->tt_subject[0]);
      tt->status = np_error;
    };
  }

  // data receive network
  np_generate_subject(&tt->tt_subject[1],
                      _NP_TUNTAP_DATA,
                      strnlen(_NP_TUNTAP_DATA, 256));
  np_generate_subject(&tt->tt_subject[1],
                      (char *)tt->domain,
                      strnlen((char *)tt->domain, 256));
  np_generate_subject(&tt->tt_subject[1],
                      (char *)tt->ip,
                      strnlen((char *)tt->ip, 32));
  np_generate_subject(&tt->tt_subject[1],
                      (char *)tt->netmask,
                      strnlen((char *)tt->netmask, 32));

  sodium_bin2hex(peer_subject_str,
                 NP_FINGERPRINT_BYTES * 2 + 1,
                 tt->tt_subject[1],
                 NP_FINGERPRINT_BYTES);
  log_msg(LOG_DEBUG,
          NULL,
          "listening on data subject id : %s",
          peer_subject_str);

  // handle data traffic
  tuntap_properties.role          = NP_MX_CONSUMER;
  tuntap_properties.audience_type = NP_MX_AUD_PRIVATE;
  tuntap_properties.max_parallel  = 5;
  tuntap_properties.cache_size    = 20;

  np_set_mx_properties(ac, tt->tt_subject[1], tuntap_properties);
  np_set_mx_authorize_cb(ac, tt->tt_subject[1], _tuntap_authorize_data);
  np_add_receive_cb(ac, tt->tt_subject[1], _handle_tuntap_traffic);
}

void np_tuntap_init(NP_UNUSED np_context *ac, struct np_tuntap *tt) {
  // np_state_t *context = ac;

  if (tt->status == np_error) {
    np_tuntap_destroy(ac, tt);
    tt->status = np_uninitialized;
  }

  if (tt->status < np_running) {
    np_set_userdata(ac, tt);
    np_add_shutdown_cb(ac, _shutdown_tuntap);

    // initialize addon data structure
    tt->addon_data.key_length       = NP_FINGERPRINT_BYTES;
    tt->addon_data.tree             = NULL;
    tt->addon_data.alloc_key_memory = true;
    tt->local_raw_socket            = -1;

    tt->mtu = 1500;

    tt->tuntap_fd = _np_tuntap_add_itf(tt->tuntap_dev, 0, tt->tuntap_dev);
    if (tt->tuntap_fd > 0) {

      // set p2p ip address
      _np_tuntap_set_ipv4(tt, (char *)&tt->ip[0]);

      // set route to own tun0 network
      np_tuntap_route_add(tt,
                          (char *)&tt->ip[0],
                          (char *)&tt->ip[0],
                          (char *)&tt->netmask[0]);

      _np_tuntap_init_subjects(ac, tt);
      tt->status = np_stopped;
    }
  }
}

void np_tuntap_start(NP_UNUSED np_context *ac, struct np_tuntap *tt) {

  // np_state_t *context = ac;

  if (tt->status < np_running) {
    np_tuntap_init(ac, tt);
  }

  if (tt->status == np_stopped) {
    // only stop data channels
    np_mx_properties_enable(ac, tt->tt_subject[0]);
    np_mx_properties_enable(ac, tt->tt_subject[1]);

    _np_tuntap_if_up(tt);

    _np_tuntap_start_evloop(ac, tt);

    tt->status = np_running;
  }
}

void np_tuntap_stop(NP_UNUSED np_context *ac, struct np_tuntap *tt) {
  // np_state_t *context = ac;
  _np_tuntap_stop_evloop(ac, tt);

  _np_tuntap_if_down(tt);
  // only stop data channels
  np_mx_properties_disable(ac, tt->tt_subject[0]);
  np_mx_properties_disable(ac, tt->tt_subject[1]);

  tt->status = np_stopped;
}

void np_tuntap_destroy(NP_UNUSED np_context *ac, struct np_tuntap *tt) {
  // np_state_t *context = ac;
  if (tt->status != np_stopped) {
    // log_msg(LOG_INFO,
    //         NULL,
    //         "received destroy on running tuntap system, stopping it now");
    np_tuntap_route_delete(tt,
                           (char *)&tt->ip[0],
                           (char *)&tt->ip[0],
                           (char *)&tt->netmask[0]);
    _np_tuntap_if_down(tt);

    np_tuntap_stop(ac, tt);
  }
  // _np_tuntap_delete_itf(tt);
  tt->status = np_uninitialized;
}
