//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

// adapted from
// https://john-millikin.com/creating-tun-tap-interfaces-in-linux#steps-1-2-allocating-a-tuntap-interface
// SPDX-License-Identifier: 0BSD

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <net/if_tun.h>
#include <net/route.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet6/nd6.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "tuntap/np_tuntap.h"

int _np_tuntap_add_itf(NP_UNUSED const char *iface_name,
                       short                 flags,
                       char                 *iface_name_out) {

  // the code should open a tun/tap interface under the freebsd operating
  // system, and configure it to send and receive IP packets (TCP and UDP).
  // Assignment of IP address and mask will be done in other functions. The
  // return value should be the file descriptor that will be used to read write
  // pakets to teh tun/tap device.

  assert(iface_name != NULL);
  assert(strnlen(iface_name, IFNAMSIZ) < IFNAMSIZ);

  int  tuntap_fd = -1;
  char dev_1[32];
  char dev_2[32];

  // Open first available tun device
  int i = 0;
  while (tuntap_fd < 0) {
    snprintf(dev_1, sizeof(dev_1), "tun%d", i);
    snprintf(dev_2, sizeof(dev_2), "/dev/%s", dev_1);
    tuntap_fd = open(dev_2, O_RDWR);
    i++;
    if (i > 10) break;
  }

  if (tuntap_fd < 0) {
    return -1;
  }

  // Get the actual interface name
  int on = 0;
  if (ioctl(tuntap_fd, TUNSIFHEAD, &on, sizeof(on)) < 0) {
    close(tuntap_fd);
    return -1;
  }

  int mode = IFF_BROADCAST | IFF_MULTICAST;
  if (ioctl(tuntap_fd, TUNSIFMODE, &mode, sizeof(mode)) < 0) {
    perror("set bcast mode");
    close(tuntap_fd);
    return -1;
  }

  // Copy interface name to output if requested
  if (iface_name_out != NULL) {
    strncpy(iface_name_out, dev_1, IFNAMSIZ);
  }

  // Set non-blocking I/O
  int flags_current = fcntl(tuntap_fd, F_GETFD);
  if (flags_current == -1) {
    close(tuntap_fd);
    return -1;
  }
  if (fcntl(tuntap_fd, F_SETFD, flags_current | O_NONBLOCK | FD_CLOEXEC) ==
      -1) {
    close(tuntap_fd);
    return -1;
  }

  return tuntap_fd;
}

void _np_tuntap_set_ipv4(struct np_tuntap *tt, const char *alias) {

  struct in_addr addr;
  struct in_addr mask;
  struct in_addr broadcast;
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

  // Configure interface address and mask
  struct ifaliasreq ifra = {0};
  strncpy(ifra.ifra_name, tt->tuntap_dev, IFNAMSIZ);

  struct sockaddr_in *sin = NULL;

  // Set the interface address
  sin             = (struct sockaddr_in *)&ifra.ifra_addr;
  sin->sin_family = AF_INET;
  sin->sin_len    = sizeof(struct sockaddr_in);
  memcpy(&sin->sin_addr, &addr, sizeof(addr));

  // Set the netmask
  sin             = (struct sockaddr_in *)&ifra.ifra_mask;
  sin->sin_family = AF_INET;
  sin->sin_len    = sizeof(struct sockaddr_in);
  memcpy(&sin->sin_addr, &mask, sizeof(mask));

  // Set the broadcast/destination address (required for point-to-point)
  sin             = (struct sockaddr_in *)&ifra.ifra_broadaddr;
  sin->sin_family = AF_INET;
  sin->sin_len    = sizeof(struct sockaddr_in);
  memcpy(&sin->sin_addr, &broadcast, sizeof(addr));

  // Create socket for interface configuration
  cfg_socket = socket(AF_INET, SOCK_DGRAM, 0);
  if (cfg_socket < 0) {
    tt->status = np_error;
    return;
  }

  // Set the address on the interface
  if (ioctl(cfg_socket, SIOCAIFADDR, &ifra) < 0) {
    tt->status = np_error;
  }
  close(cfg_socket);
}

void np_tuntap_route_add(struct np_tuntap *tt,
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
    return;
  }
  broadcast.s_addr = addr.s_addr | ~mask.s_addr;

  // Create socket for interface configuration
  cfg_socket = socket(AF_INET, SOCK_DGRAM, 0);
  if (cfg_socket < 0) {
    return;
  }

  // Get interface index
  struct ifreq ifr = {0};
  strncpy(ifr.ifr_name, tt->tuntap_dev, IFNAMSIZ);
  if (ioctl(cfg_socket, SIOCGIFINDEX, &ifr) < 0) {
    perror("SIOCGIFINDEX");
    close(cfg_socket);
    return;
  }

  // Add route to the network
  struct rt_msghdr *rtm;
  char              buf[512];
  int               seq = 0;

  memset(buf, 0, sizeof(buf));
  rtm = (struct rt_msghdr *)buf;

  rtm->rtm_msglen  = sizeof(struct rt_msghdr) + 3 * sizeof(struct sockaddr_in);
  rtm->rtm_version = RTM_VERSION;
  rtm->rtm_type    = RTM_ADD;
  rtm->rtm_index   = ifr.ifr_index;
  rtm->rtm_flags   = RTF_UP | RTF_GATEWAY | RTF_STATIC;
  rtm->rtm_addrs   = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
  rtm->rtm_pid     = getpid();
  rtm->rtm_seq     = ++seq;

  // position after header for sockaddr data
  sin = (struct sockaddr_in *)(rtm + 1);

  // set destination network
  sin->sin_family = AF_INET;
  sin->sin_len    = sizeof(addr);
  memcpy(&sin->sin_addr, &broadcast, sizeof(broadcast));

  // set gateway (interface address)
  sin             = (struct sockaddr_in *)((char *)sin + sizeof(*sin));
  sin->sin_family = AF_INET;
  sin->sin_len    = sizeof(gw);
  memcpy(&sin->sin_addr, &gw, sizeof(gw));

  // set netmask
  sin             = (struct sockaddr_in *)((char *)sin + sizeof(*sin));
  sin->sin_family = AF_INET;
  sin->sin_len    = sizeof(mask);
  memcpy(&sin->sin_addr, &mask, sizeof(mask));

  // Open routing socket
  int route_sock = socket(PF_ROUTE, SOCK_RAW, AF_INET);
  if (route_sock < 0) {
    close(cfg_socket);
    return;
  }

  // Write route message
  if (write(route_sock, rtm, rtm->rtm_msglen) < 0) {
    // nothing to do
  }
  close(route_sock);
  close(cfg_socket);
}

void np_tuntap_route_delete(struct np_tuntap *tt,
                            const char       *gateway,
                            const char       *ip,
                            const char       *netmask) {
  // initial cursor AI prompt:
  // the code should open the device specifiy with the argument device_name, and
  // assign the ip address with te given netmask, given in the argument nm, to
  // it. Afterwards, the code should set the route to this network and activate
  // the interface. The code should be running under osx / darwin only
  struct sockaddr_in *sin;

  struct in_addr gw, addr, mask, broadcast = {0};
  int            cfg_socket;

  // Convert IP and netmask strings to network format
  if (inet_pton(AF_INET, gateway, &gw) != 1 ||
      inet_pton(AF_INET, ip, &addr) != 1 ||
      inet_pton(AF_INET, netmask, &mask) != 1) {
    return;
  }
  broadcast.s_addr = addr.s_addr & mask.s_addr;

  // Create socket for interface configuration
  cfg_socket = socket(AF_INET, SOCK_DGRAM, 0);
  if (cfg_socket < 0) {
    return;
  }

  // Get interface index
  struct ifreq ifr = {0};
  strncpy(ifr.ifr_name, tt->tuntap_dev, IFNAMSIZ);
  if (ioctl(cfg_socket, SIOCGIFINDEX, &ifr) < 0) {
    close(cfg_socket);
    return;
  }

  // remove route to the network
  struct rt_msghdr *rtm;
  char              buf[512];
  int               seq = 0;

  memset(buf, 0, sizeof(buf));
  rtm = (struct rt_msghdr *)buf;

  rtm->rtm_msglen  = sizeof(struct rt_msghdr) + 3 * sizeof(struct sockaddr_in);
  rtm->rtm_version = RTM_VERSION;
  rtm->rtm_type    = RTM_DELETE;
  rtm->rtm_index   = ifr.ifr_index;
  rtm->rtm_flags   = RTF_UP | RTF_GATEWAY | RTF_STATIC;
  rtm->rtm_addrs   = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
  rtm->rtm_pid     = getpid();
  rtm->rtm_seq     = ++seq;

  // Position after header for sockaddr data
  sin = (struct sockaddr_in *)(rtm + 1);

  // Set destination network
  sin->sin_family = AF_INET;
  sin->sin_len    = sizeof(*sin);
  memcpy(&sin->sin_addr.s_addr, &broadcast, sizeof(broadcast));

  // Set gateway (interface address)
  sin             = (struct sockaddr_in *)((char *)sin + sizeof(*sin));
  sin->sin_family = AF_INET;
  sin->sin_len    = sizeof(*sin);
  memcpy(&sin->sin_addr.s_addr, &gw, sizeof(gw));

  // Set netmask
  sin             = (struct sockaddr_in *)((char *)sin + sizeof(*sin));
  sin->sin_family = AF_INET;
  sin->sin_len    = sizeof(*sin);
  memcpy(&sin->sin_addr.s_addr, &mask, sizeof(mask));

  // Open routing socket
  int route_sock = socket(PF_ROUTE, SOCK_RAW, AF_INET);
  if (route_sock < 0) {
    close(cfg_socket);
    return;
  }

  // Write route message
  if (write(route_sock, rtm, rtm->rtm_msglen) < 0) {
    // nothing to do
  }
  close(cfg_socket);
  close(route_sock);
}

void np_tuntap_dns_add(struct np_tuntap *tt,
                       const char       *domain,
                       char             *dns_ptr) {

  // Check if inputs are valid
  if (dns_ptr == NULL || domain == NULL) {
    return;
  }

  // Open resolv.conf file for writing
  FILE *fp = fopen("/etc/resolv.conf", "a");
  if (fp == NULL) {
    perror("Failed to open resolv.conf");
    return;
  }
  // Add search domain
  fprintf(fp, "search %s\n", domain);
  // Add nameserver
  fprintf(fp, "nameserver %s\n", dns_ptr);

  fclose(fp);
}

int _np_tuntap_if_up(const struct np_tuntap *tt) {

  // Create socket for interface configuration
  int cfg_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (cfg_sock < 0) {
    return -1;
  }

  // Bring up interface
  struct ifreq ifr = {0};
  strncpy(ifr.ifr_name, tt->tuntap_dev, sizeof(ifr.ifr_name));
  ifr.ifr_mtu = tt->mtu;
  ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

  if (ioctl(cfg_sock, SIOCSIFFLAGS | SIOCSIFMTU, &ifr) < 0) {
    close(cfg_sock);
    return -1;
  }

  close(cfg_sock);
  return 0;
}

int _np_tuntap_if_down(const struct np_tuntap *tt) {

  // Create socket for interface configuration
  int cfg_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (cfg_sock < 0) {
    return -1;
  }

  // Bring up interface
  struct ifreq ifr = {0};
  strncpy(ifr.ifr_name, tt->tuntap_dev, sizeof(ifr.ifr_name));
  ifr.ifr_flags = 0;

  if (ioctl(cfg_sock, SIOCSIFFLAGS, &ifr) < 0) {
    close(cfg_sock);
    return -1;
  }

  close(cfg_sock);
  return 0;
}
