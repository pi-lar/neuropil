//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "tuntap/np_tuntap.h"

// adapted from
// https://john-millikin.com/creating-tun-tap-interfaces-in-linux#steps-1-2-allocating-a-tuntap-interface
// SPDX-License-Identifier: 0BSD

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int _np_tuntap_add_itf(NP_UNUSED const char *iface_name,
                       short                 flags,
                       char                 *iface_name_out) {

  assert(iface_name_out != NULL);
  assert(strnlen(iface_name, IFNAMSIZ) < IFNAMSIZ);

  // set namespace
  // int namespace_fd = open("/run/netns/blue", O_RDONLY);
  // if (setns(namespace_fd, CLONE_NEWNET) == -1) {
  //   perror("setns");
  //   exit(-1);
  // }
  int    tuntap_fd, rc;
  size_t iface_name_len = strnlen(iface_name, IFNAMSIZ);

  tuntap_fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
  if (tuntap_fd == -1) {
    perror("tuntap_fd");
    return -1;
  }

  struct ifreq iff_request = {0};
  iff_request.ifr_flags    = flags | IFF_TUN | IFF_NO_PI;
  strncpy(iff_request.ifr_name, iface_name, iface_name_len);

  rc = ioctl(tuntap_fd, TUNSETIFF, &iff_request);
  if (rc == -1) {
    perror("get IF NAME");
    close(tuntap_fd);
    return -1;
  }

  if (iface_name_out != NULL) {
    strncpy(iface_name_out, iff_request.ifr_name, IFNAMSIZ);
  }

  return tuntap_fd;
}

void _np_tuntap_set_ipv4(struct np_tuntap *tt, const char *alias) {
  struct sockaddr_in *sin;

  struct in_addr addr      = {0};
  struct in_addr mask      = {0};
  struct in_addr broadcast = {0};
  int            cfg_socket;

  // Convert IP and netmask strings to network format
  if (inet_pton(AF_INET, (char *)&tt->ip[0], &addr) != 1 ||
      inet_pton(AF_INET, (char *)&tt->netmask[0], &mask) != 1) {
    tt->status = np_error;
    return;
  }
  broadcast.s_addr = addr.s_addr | ~mask.s_addr;

  if (alias != NULL && inet_pton(AF_INET, alias, &addr) != 1) {
    return;
  }

  int network_prefix_bits = 32 - __builtin_clz(mask.s_addr);

  // Open routing socket
  int cfg_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (cfg_sock < 0) {
    tt->status = np_error;
    return;
  }

  struct {
    struct nlmsghdr  header;
    struct ifaddrmsg content;
    char             attributes_buf[64];
  } ip4_request;

  memset(&ip4_request, 0, sizeof ip4_request);
  size_t attributes_buf_avail = sizeof ip4_request.attributes_buf;

  ip4_request.header.nlmsg_len   = NLMSG_LENGTH(sizeof ip4_request.content);
  ip4_request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE;
  ip4_request.header.nlmsg_type  = RTM_NEWADDR;

  ip4_request.content.ifa_index     = if_nametoindex(tt->tuntap_dev);
  ip4_request.content.ifa_family    = AF_INET;
  ip4_request.content.ifa_prefixlen = network_prefix_bits;

  struct rtattr *request_attr;
  request_attr           = IFA_RTA(&ip4_request.content);
  request_attr->rta_type = IFA_LOCAL;
  request_attr->rta_len  = RTA_LENGTH(sizeof(struct in_addr));
  memcpy(RTA_DATA(request_attr), &addr, request_attr->rta_len);
  ip4_request.header.nlmsg_len += request_attr->rta_len;

  request_attr           = RTA_NEXT(request_attr, attributes_buf_avail);
  request_attr->rta_type = IFA_ADDRESS;
  request_attr->rta_len  = RTA_LENGTH(sizeof(struct in_addr));
  memcpy(RTA_DATA(request_attr), &addr, request_attr->rta_len);
  ip4_request.header.nlmsg_len += request_attr->rta_len;

  request_attr           = RTA_NEXT(request_attr, attributes_buf_avail);
  request_attr->rta_type = IFA_BROADCAST;
  request_attr->rta_len  = RTA_LENGTH(sizeof(struct in_addr));
  memcpy(RTA_DATA(request_attr), &broadcast, request_attr->rta_len);
  ip4_request.header.nlmsg_len += request_attr->rta_len;

  // Write ipv4 message
  if (send(cfg_sock, &ip4_request, sizeof(ip4_request), 0) < 0) {
    tt->status = np_error;
  }
  close(cfg_sock);
}

void np_tuntap_route_add(struct np_tuntap *tt,
                         const char       *gateway,
                         const char       *ip,
                         const char       *netmask) {

  struct in_addr gw, addr, mask, broadcast = {0};

  // Convert IP and netmask strings to network format
  if (inet_pton(AF_INET, gateway, &gw) != 1 ||
      inet_pton(AF_INET, ip, &addr) != 1 ||
      inet_pton(AF_INET, netmask, &mask) != 1) {
    // tt->status = np_error;
    return;
  }
  broadcast.s_addr = addr.s_addr | ~mask.s_addr;

  struct {
    struct nlmsghdr netlink_header;
    struct rtmsg    rt_message;
    char            buffer[1024];
  } route_req;

  /* Initialize route_req structure */
  route_req.netlink_header.nlmsg_len  = NLMSG_LENGTH(sizeof(struct rtmsg));
  route_req.netlink_header.nlmsg_type = RTM_NEWROUTE;
  route_req.netlink_header.nlmsg_flags =
      NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;

  route_req.rt_message.rtm_family   = AF_INET;
  route_req.rt_message.rtm_table    = RT_TABLE_MAIN;
  route_req.rt_message.rtm_scope    = RT_SCOPE_LINK;
  route_req.rt_message.rtm_protocol = RTPROT_BOOT;
  route_req.rt_message.rtm_type     = RTN_UNICAST;
  route_req.rt_message.rtm_dst_len  = 32;

  /* Select scope, for simplicity we supports here only IPv6 and IPv4 */
  if (route_req.rt_message.rtm_family == AF_INET6) {
    route_req.rt_message.rtm_scope = RT_SCOPE_UNIVERSE;
  }

  struct rtattr *rta =
      &route_req.netlink_header + route_req.netlink_header.nlmsg_len;
  rta->rta_type = RTA_GATEWAY;
  memcpy(RTA_DATA(rta), &addr, sizeof(addr));
  rta->rta_len = sizeof(addr);
  route_req.netlink_header.nlmsg_len += rta->rta_len;

  rta = &route_req.netlink_header + route_req.netlink_header.nlmsg_len;
  rta->rta_type = RTA_DST;
  memcpy(RTA_DATA(rta), &mask, sizeof(mask));
  rta->rta_len = sizeof(mask);
  route_req.netlink_header.nlmsg_len += rta->rta_len;

  int if_idx = if_nametoindex(tt->tuntap_dev);
  rta        = &route_req.netlink_header + route_req.netlink_header.nlmsg_len;
  rta->rta_type = RTA_OIF;
  memcpy(RTA_DATA(rta), &if_idx, sizeof(int));
  rta->rta_len = sizeof(int);
  route_req.netlink_header.nlmsg_len += rta->rta_len;

  // Open routing socket
  int cfg_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (cfg_sock < 0) {
    // tt->status = np_error;
    return;
  }

  // Write route message
  if (send(cfg_sock, &route_req, sizeof(route_req), 0) < 0) {
    // tt->status = np_error;
  }
  close(cfg_sock);
}

void np_tuntap_route_delete(struct np_tuntap *tt,
                            const char       *gateway,
                            const char       *ip,
                            const char       *netmask) {
  struct sockaddr_in *sin;

  struct in_addr gw, addr, mask, broadcast = {0};
  int            cfg_socket;

  // Convert IP and netmask strings to network format
  if (inet_pton(AF_INET, gateway, &gw) != 1 ||
      inet_pton(AF_INET, ip, &addr) != 1 ||
      inet_pton(AF_INET, netmask, &mask) != 1) {
    // fprintf(stderr, "Invalid IP address or netmask\n");
    tt->status = np_error;
    return;
  }
  broadcast.s_addr = addr.s_addr | ~mask.s_addr;

  struct {
    struct nlmsghdr netlink_header;
    struct rtmsg    rt_message;
    char            buffer[1024];
  } route_req;

  /* Initialize route_req structure */
  route_req.netlink_header.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
  route_req.netlink_header.nlmsg_type  = RTM_DELROUTE;
  route_req.netlink_header.nlmsg_flags = 0;

  route_req.rt_message.rtm_family   = AF_INET;
  route_req.rt_message.rtm_table    = RT_TABLE_MAIN;
  route_req.rt_message.rtm_scope    = RT_SCOPE_LINK;
  route_req.rt_message.rtm_protocol = RTPROT_BOOT;
  route_req.rt_message.rtm_type     = RTN_UNICAST;
  route_req.rt_message.rtm_dst_len  = 32;

  /* Select scope, for simplicity we supports here only IPv6 and IPv4 */
  if (route_req.rt_message.rtm_family == AF_INET6) {
    route_req.rt_message.rtm_scope = RT_SCOPE_UNIVERSE;
  }

  struct rtattr *rta =
      &route_req.netlink_header + route_req.netlink_header.nlmsg_len;
  rta->rta_type = RTA_GATEWAY;
  memcpy(RTA_DATA(rta), &addr, sizeof(addr));
  rta->rta_len = sizeof(addr);
  route_req.netlink_header.nlmsg_len += rta->rta_len;

  rta = &route_req.netlink_header + route_req.netlink_header.nlmsg_len;
  rta->rta_type = RTA_DST;
  memcpy(RTA_DATA(rta), &mask, sizeof(mask));
  rta->rta_len = sizeof(mask);
  route_req.netlink_header.nlmsg_len += rta->rta_len;

  int if_idx    = if_nametoindex(tt->tuntap_dev);
  rta           = &route_req + route_req.netlink_header.nlmsg_len;
  rta->rta_type = RTA_OIF;
  memcpy(RTA_DATA(rta), &if_idx, sizeof(int));
  rta->rta_len = sizeof(int);
  route_req.netlink_header.nlmsg_len += rta->rta_len;

  // Open routing socket
  int cfg_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (cfg_sock < 0) {
    tt->status = np_error;
    return;
  }

  // Write route message
  if (send(cfg_sock, &route_req, sizeof(route_req), 0) < 0) {
    tt->status = np_error;
  }
  close(cfg_sock);
}

void np_tuntap_dns_add(struct np_tuntap *tt,
                       const char       *domain,
                       char             *dns_ptr) {}

int _np_tuntap_if_up(const struct np_tuntap *tt) {

  // Create socket for interface configuration
  int cfg_sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (cfg_sock == -1) {
    return -1;
  }

  struct {
    struct nlmsghdr  header;
    struct ifinfomsg content;
  } up_req = {0};

  up_req.header.nlmsg_len   = NLMSG_LENGTH(sizeof up_req.content);
  up_req.header.nlmsg_flags = NLM_F_REQUEST;
  up_req.header.nlmsg_type  = RTM_NEWLINK;
  up_req.content.ifi_index  = if_nametoindex(tt->tuntap_dev);
  up_req.content.ifi_flags  = IFF_UP;
  up_req.content.ifi_change = 1;

  if (send(cfg_sock, &up_req, up_req.header.nlmsg_len, 0) == -1) {
    return -1;
  }

  close(cfg_sock);
  return 0;
}

int _np_tuntap_if_down(const struct np_tuntap *tt) {

  // Create socket for interface configuration
  int cfg_sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (cfg_sock == -1) {
    return -1;
  }

  struct {
    struct nlmsghdr  header;
    struct ifinfomsg content;
  } down_req = {0};

  down_req.header.nlmsg_len   = NLMSG_LENGTH(sizeof down_req.content);
  down_req.header.nlmsg_flags = NLM_F_REQUEST;
  down_req.header.nlmsg_type  = RTM_DELLINK;
  down_req.content.ifi_index  = if_nametoindex(tt->tuntap_dev);
  down_req.content.ifi_flags  = 0; /* IFF_DOWN */
  down_req.content.ifi_change = 1;

  if (send(cfg_sock, &down_req, down_req.header.nlmsg_len, 0) == -1) {
    return -1;
  }

  close(cfg_sock);
  return 0;
}
