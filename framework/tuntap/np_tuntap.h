//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#ifndef NP_TUNTAP_H
#define NP_TUNTAP_H

#include <inttypes.h>
#include <stdio.h>

#include "event/ev.h"

#include "neuropil.h"

#include "util/np_cupidtrie.h"

#include "np_network.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The struct np_tuntap is responsible to hold all configuration about the
 * tun/tap device to establish IP based vpn tunnels on top of the neuropil
 * cybersecurity mesh.
 * Each participant will create at least two neuropil subjects. On virtual
 * subject where all participants of the vpn will meet and exchange their IP
 * addresses. The second one will be the own incoming IP address channel that
 * can be used by peers to connect and send data packets. When VPN participants
 * discover peers by means of the virtual data channel, they will first check
 * whether the contained IP information (ipv4, netmask,domain) match their own.
 * Only if the information is sound, the authorization callback will be called,
 * and on success a client data channel will be established. Peers may specify
 * additional routing entries and DNS settings if they act as a proxy to a
 * larger network.
 */
struct np_tuntap {

  // status of the tuntap system
  enum np_status status;

  // own network properties
  char domain[255];
  char ip[16];
  char netmask[16];

  // addon information (routing table, dns, ...)
  char routing[16];
  char dns[16];

  // internal properties
  char tuntap_dev[16];
  int  tuntap_fd;
  int  local_raw_socket;

  size_t mtu;

  // io loop structures
  np_subject   tt_subject[2];
  struct ev_io watcher_in;
  struct ev_io watcher_out;
  bool         has_data;

  // storage of additional information in a cupidtrie
  struct np_cupidtrie addon_data;

  // statistical data
  // struct np_cupidtrie statistics;
};

/**  add a routing entry to go through the tuntap device. The implementation
 will first destroy to delete existing entries in the routing table before
 setting up the new entry. In case of an error the tuntap will continue to work
 without the additional entry.
*/
NP_API_EXPORT
void np_tuntap_route_add(struct np_tuntap *tt,
                         const char       *gateway,
                         const char       *ip,
                         const char       *netmask);
/** remove a routing entry that is currently handled by the tuntap device. In
 * case of an error the tuntap will continue to work without the additional
 * entry.*/
NP_API_EXPORT
void np_tuntap_route_delete(struct np_tuntap *tt,
                            const char       *gateway,
                            const char       *ip,
                            const char       *netmask);

/** Initialize the tuntap driver. Calling this function will result in the tun
 * device being allocated, taking the ip/netmask/routing information of the
 * structure np_tuntap. However, no traffic can pass the tuntap device after
 * calling this function, the tuntap needs to be started (see below).
 */
NP_API_EXPORT
void np_tuntap_init(np_context *ac, struct np_tuntap *tt);
/** Start processing traffic through the tun device. Calling thus function will
 * bring the configured interface up, enable the corresponding neuropil subjects
 * and io-loop to process the traffic.  */
NP_API_EXPORT
void np_tuntap_start(np_context *ac, struct np_tuntap *tt);
/** Stop processing traffic through the tunt/tap device. A call to this function
 * will stop the data neuropil channels and io-loop. Next the interface is taken
 * down. */
NP_API_EXPORT
void np_tuntap_stop(np_context *ac, struct np_tuntap *tt);
/** Destroy the tuntap interface and free the tuntap device. Also clears the
 * routing table entries. */
NP_API_EXPORT
void np_tuntap_destroy(np_context *ac, struct np_tuntap *tt);

#ifdef __cplusplus
}
#endif

#endif // NP_TUNTAP_H
