//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
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
#include <net/if_utun.h>
#include <net/route.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet6/nd6.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "tuntap/np_tuntap.h"

int _np_tuntap_add_itf(NP_UNUSED const char *iface_name,
                       NP_UNUSED short       flags,
                       char                 *iface_name_out) {

  assert(iface_name != NULL);
  assert(strnlen(iface_name, IFNAMSIZ) < IFNAMSIZ);

  int tuntap_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
  if (tuntap_fd < 0) {
    perror("socket");
    fprintf(stdout, "could not create tun/tap socket\n");
    return -1;
  }

  struct ctl_info ctl_info = {0};
  strncpy(ctl_info.ctl_name, UTUN_CONTROL_NAME, sizeof(ctl_info.ctl_name));

  int err = ioctl(tuntap_fd, CTLIOCGINFO, &ctl_info);
  if (err < 0) {
    close(tuntap_fd);
    return -1;
  }

  struct sockaddr_ctl sc = {
      .sc_family  = AF_SYSTEM,
      .ss_sysaddr = AF_SYS_CONTROL,
      .sc_id      = ctl_info.ctl_id,
      .sc_len     = sizeof(struct sockaddr_ctl),
      .sc_unit    = 0,
  };

  err = connect(tuntap_fd, (struct sockaddr *)&sc, sizeof(sc));
  if (err < 0) {
    close(tuntap_fd);
    return -1;
  }

  if (iface_name_out) {
    socklen_t optlen = IFNAMSIZ;
    err              = getsockopt(tuntap_fd,
                     SYSPROTO_CONTROL,
                     UTUN_OPT_IFNAME,
                     iface_name_out,
                     &optlen);
    if (err < 0) {
      close(tuntap_fd);
      return -1;
    }
  }

  return tuntap_fd;
}

void _np_tuntap_set_ipv4(struct np_tuntap *tt, const char *alias) {

  struct in_addr addr, mask, broadcast = {0};

  // Convert IP and netmask strings to network format
  if (inet_pton(AF_INET, (char *)&tt->ip[0], &addr) != 1 ||
      inet_pton(AF_INET, (char *)&tt->netmask[0], &mask) != 1) {
    tt->status = np_error;
    return;
  }
  broadcast.s_addr = addr.s_addr | ~mask.s_addr; // Calculate broadcast address

  if (alias != NULL && inet_pton(AF_INET, alias, &addr) != 1) {
    return;
  }

  // Create socket for interface configuration
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    tt->status = np_error;
    return;
  }

  struct ifreq ifr = {0};
  strncpy(ifr.ifr_name, tt->tuntap_dev, sizeof(ifr.ifr_name));

  // Configure interface address and mask
  struct ifaliasreq ifra = {0};
  strncpy(ifra.ifra_name, tt->tuntap_dev, sizeof(ifra.ifra_name));

  struct sockaddr_in *sii = NULL;

  // Set the interface address
  sii             = &ifra.ifra_addr;
  sii->sin_family = AF_INET;
  sii->sin_len    = sizeof(addr);
  memcpy(&sii->sin_addr, &addr, sizeof(addr));

  // Set the netmask
  sii             = &ifra.ifra_mask;
  sii->sin_family = AF_INET;
  sii->sin_len    = sizeof(mask);
  memcpy(&sii->sin_addr, &mask, sizeof(mask));

  // Set the broadcast address
  sii             = &ifra.ifra_broadaddr;
  sii->sin_family = AF_INET;
  sii->sin_len    = sizeof(broadcast);
  memcpy(&sii->sin_addr, &broadcast, sizeof(broadcast));

  // Set the destination address
  struct in_addr dest = {0};
  dest.s_addr         = addr.s_addr & mask.s_addr;
  sii                 = &ifra.ifra_dstaddr;
  sii->sin_family     = AF_INET;
  sii->sin_len        = sizeof(addr);
  memcpy(&sii->sin_addr, &addr, sizeof(addr));

  // Set the address on the interface without removing existing addresses
  if (ioctl(s, SIOCAIFADDR, &ifra) < 0) {
    tt->status = np_error;
  }
  close(s);
}

void np_tuntap_route_add(struct np_tuntap *tt,
                         const char       *gateway,
                         const char       *ip,
                         const char       *netmask) {
  // initial cursor AI prompt:
  // the code should open the device specifiy with the argument device_name, and
  // assign the ip address with te given netmask, given in the argument nm, to
  // it. Afterwards, the code should set the route to this network and activate
  // the interface. The code should be running under osx / darwin only
  struct sockaddr_in *sin;

  // delete existing routing information
  np_tuntap_route_delete(tt, gateway, ip, netmask);

  struct in_addr gw, addr, mask;

  // Convert IP and netmask strings to network format
  if (inet_pton(AF_INET, gateway, &gw) != 1 ||
      inet_pton(AF_INET, ip, &addr) != 1 ||
      inet_pton(AF_INET, netmask, &mask) != 1) {
    return;
  }

  // Add route to the network
  struct rt_msghdr *rtm;
  char              buf[512];
  int               seq = 0;

  memset(buf, 0, sizeof(buf));
  rtm = (struct rt_msghdr *)buf;

  rtm->rtm_version = RTM_VERSION;
  rtm->rtm_type    = RTM_ADD;
  rtm->rtm_index   = if_nametoindex(tt->tuntap_dev);
  rtm->rtm_flags   = RTF_UP | RTF_STATIC | RTF_GATEWAY;
  rtm->rtm_addrs   = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
  rtm->rtm_pid     = getpid();
  rtm->rtm_seq     = ++seq;

  // Position after header for sockaddr data
  sin = (struct sockaddr_in *)(rtm + 1);

  // Set destination network
  sin->sin_family      = AF_INET;
  sin->sin_len         = sizeof(*sin);
  sin->sin_addr.s_addr = addr.s_addr & mask.s_addr;

  // Set gateway (interface address)
  sin             = (struct sockaddr_in *)((char *)sin + sizeof(*sin));
  sin->sin_family = AF_INET;
  sin->sin_len    = sizeof(*sin);
  sin->sin_addr   = gw;

  // Set netmask
  sin             = (struct sockaddr_in *)((char *)sin + sizeof(*sin));
  sin->sin_family = AF_INET;
  sin->sin_len    = sizeof(*sin);
  sin->sin_addr   = mask;

  rtm->rtm_msglen = sizeof(struct rt_msghdr) + 3 * sizeof(struct sockaddr_in);

  // Open routing socket
  int route_sock = socket(PF_ROUTE, SOCK_RAW, AF_INET);
  if (route_sock < 0) {
    return;
  }

  // Write route message
  if (write(route_sock, rtm, rtm->rtm_msglen) < 0) {
    // nothing to do
  }
  close(route_sock);
}

void np_tuntap_route_delete(NP_UNUSED struct np_tuntap *tt,
                            const char                 *gateway,
                            const char                 *ip,
                            const char                 *netmask) {

  struct sockaddr_in *sin;
  struct in_addr      gw, addr, mask;

  // Convert IP and netmask strings to network format
  if (inet_pton(AF_INET, gateway, &gw) != 1 ||
      inet_pton(AF_INET, ip, &addr) != 1 ||
      inet_pton(AF_INET, netmask, &mask) != 1) {
    return;
  }

  struct sockaddr sii;
  sii.sa_family = AF_INET;
  sii.sa_len    = sizeof(addr);

  // remove route from  network
  struct rt_msghdr *rtm;
  char              buf[512];
  int               seq = 0;

  memset(buf, 0, sizeof(buf));
  rtm = (struct rt_msghdr *)buf;

  rtm->rtm_msglen  = sizeof(struct rt_msghdr) + 3 * sizeof(struct sockaddr_in);
  rtm->rtm_version = RTM_VERSION;
  rtm->rtm_type    = RTM_DELETE;
  rtm->rtm_index   = 0;
  rtm->rtm_flags   = RTF_UP | RTF_GATEWAY | RTF_STATIC;
  rtm->rtm_addrs   = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
  rtm->rtm_pid     = getpid();
  rtm->rtm_seq     = ++seq;

  // Position after header for sockaddr data
  sin = (struct sockaddr_in *)(rtm + 1);

  // Set destination network
  sin->sin_family      = AF_INET;
  sin->sin_len         = sizeof(*sin);
  sin->sin_addr.s_addr = addr.s_addr & mask.s_addr;

  // Set gateway (interface address)
  sin             = (struct sockaddr_in *)((char *)sin + sizeof(*sin));
  sin->sin_family = AF_INET;
  sin->sin_len    = sizeof(*sin);
  sin->sin_addr   = gw;

  // Set netmask
  sin             = (struct sockaddr_in *)((char *)sin + sizeof(*sin));
  sin->sin_family = AF_INET;
  sin->sin_len    = sizeof(*sin);
  sin->sin_addr   = mask;

  // Open routing socket
  int route_sock = socket(PF_ROUTE, SOCK_RAW, AF_INET);
  if (route_sock < 0) {
    return;
  }

  // Write route message
  if (write(route_sock, rtm, rtm->rtm_msglen) < 0) {
    // nothing to do
  }
  close(route_sock);
}

void np_tuntap_dns_add(NP_UNUSED struct np_tuntap *tt,
                       const char                 *domain,
int _np_tuntap_if_up(const struct np_tuntap *tt) {
  // Create socket for interface configuration
  int cfg_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (cfg_sock < 0) {
    return -1;
  }

  // Bring up interface
  struct ifreq ifr = {0};
  strncpy(ifr.ifr_name, tt->tuntap_dev, sizeof(ifr.ifr_name));
  // Get interface flags
  if (ioctl(cfg_sock, SIOCGIFFLAGS, &ifr) < 0) {
    close(cfg_sock);
    return -1;
  }

  // Set interface up and running
  ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
  if (ioctl(cfg_sock, SIOCSIFFLAGS, &ifr) < 0) {
    return -1;
  }

  ifr.ifr_mtu = tt->mtu;
  int ret     = ioctl(cfg_sock, SIOCSIFMTU, &ifr);
  if (-1 == ret) {
    // ignore
  }

  // set non blocking
  int current_flags = fcntl(tt->tuntap_fd, F_GETFL);
  current_flags |= O_NONBLOCK;
  fcntl(tt->tuntap_fd, F_SETFL, current_flags);

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
  // Get interface flags
  if (ioctl(cfg_sock, SIOCGIFFLAGS, &ifr) < 0) {
    close(cfg_sock);
    return -1;
  }

  // Set interface up and running
  ifr.ifr_flags = 0;
  if (ioctl(cfg_sock, SIOCSIFFLAGS, &ifr) < 0) {
    close(cfg_sock);
    return -1;
  }

  close(cfg_sock);
  return 0;
}
