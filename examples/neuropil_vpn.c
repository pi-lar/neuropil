//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include <arpa/inet.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "daemonize.c"

#include "neuropil.h"
#include "neuropil_log.h"

#include "tuntap/np_tuntap.h"

#include "np_network.h"

static np_context *ac           = NULL;
static uint16_t    default_port = 31415;

bool authenticate(np_context *ac, struct np_token *);
bool authorize(np_context *ac, struct np_token *);
bool install_network_interfaces(np_context *ac, uint16_t port);
bool install_tuntap_interfaces(np_context *ac,
                               const char *device,
                               const char *ip,
                               const char *netmask,
                               const char *name,
                               const char *routing,
                               const char *dns);

void usage(char *argv[]) {
  fprintf(stderr,
          "Usage: %s [-r realm] [-l leafset_size] [-v log_level] [-f "
          "log_file] [-t n_threads] [-b bootstrap_url] [-d] [-i IPv4] [-m "
          "netmask] [-n DNS-IP(v4)] [-z add-on routing] [-w device_name] -o "
          "name \n",
          argv[0]);
}

// a signal handler to reload the interfaces
void sighup_handler(int signum) {
  fprintf(stdout, "Received SIGHUP. Reloading interfaces ...\n");
  fflush(stdout);
  install_network_interfaces(ac, default_port);
  fprintf(stdout, "Interface reload complete ...\n");
  fflush(stdout);
}

void sigterm_handler(int signum) {
  fprintf(stdout, "Received SIGTERM. Shutdown initiated ...\n");
  fflush(stdout);
  np_destroy(ac, true);
  fprintf(stdout, "Shutdown complete ...\n");
  exit(0);
}

int main(int argc, char *argv[]) {

  bool     mandatory_realm = false;
  bool     run_as_daemon   = false;
  np_id    realm           = {0};
  char    *bootstrap_url   = "*:udp4:demo.neuropil.io:3400";
  char    *log_file        = "./np_vpn_relay.log";  // Default value
  uint8_t  leafset_size    = 17;                    // Default value
  uint8_t  n_threads       = 5;                     // Default value
  uint64_t log_level       = LOG_GLOBAL | LOG_MISC; // Default value

  // device name to use. if NULL the device name will be auto-generated
  char *device = NULL;
  // (domain-) name for this network
  char *name = "some.example.org";
  // vpn network local ip address (currently no dhcp)
  char *local_ip = "10.3.14.15";
  // vpn network local netmask (currently no dhcp)
  char *netmask = "255.255.255.0";
  // vpn network local netmask (currently no dhcp)
  char *routing = NULL;
  // vpn network local netmask (currently no dhcp)
  char *dns = NULL;

  fprintf(stdout, "\n");
  fprintf(stdout,
          "neuropil(TM) CyberSecurity Mesh (%s) - tun/tap vpn relay"
          "\n%s\n%s\n",
          NEUROPIL_RELEASE,
          NEUROPIL_TRADEMARK,
          NEUROPIL_COPYRIGHT);

  int opt;
  while ((opt = getopt(argc, argv, "r:l:v:f:t:b:p:di:m:n:z:o:")) != -1) {
    switch (opt) {
    case 'b':
      bootstrap_url = strndup(optarg, 255);
      break;
    case 'd':
      run_as_daemon = true;
      break;
    case 'f':
      log_file = strndup(optarg, 255);
      break;
    case 'i':
      local_ip = strndup(optarg, 16);
      break;
    case 'l':
      leafset_size = atoi(optarg);
      break;
    case 'n':
      dns = strndup(optarg, INET_ADDRSTRLEN);
      break;
    case 'm':
      netmask = strndup(optarg, INET_ADDRSTRLEN);
      break;
    case 'o':
      name = strndup(optarg, 255);
      break;
    case 'p':
      default_port = atoi(optarg);
      break;
    case 'r':
      np_str_id(&realm, optarg);
      mandatory_realm = true;
      break;
    case 't':
      n_threads = atoi(optarg);
      break;
    case 'v': {
      uint16_t _log_level = atoi(optarg);
      if (_log_level > 0) log_level |= LOG_ERROR;
      if (_log_level > 1) log_level |= LOG_WARNING;
      if (_log_level > 2) log_level |= LOG_INFO;
      if (_log_level > 3) log_level |= LOG_DEBUG;
      if (_log_level > 4) log_level |= LOG_TRACE;
    } break;
    case 'w':
      device = strndup(optarg, 255);
      break;
    case 'z':
      routing = strndup(optarg, 255);
      break;
    default:
      usage(argv);
      exit(1);
    }
  }
  if (strncmp(name, "some.example.org", 16) == 0) {
    fprintf(stdout, "\n");
    fprintf(stderr,
            "please specify your own name as an argument (e.g. use your own "
            "domain name)!\n");
    fprintf(stdout, "\n");
    usage(argv);
    exit(1);
  }

  fprintf(stdout, "\n");

  char realm_buffer[65] = {0};
  fprintf(stdout,
          "%-20s: %s\n",
          "realm",
          mandatory_realm ? np_id_str(realm_buffer, realm) : "not specified");
  fprintf(stdout, "%-20s: %" PRIu8 "\n", "leafset size", leafset_size);
  fprintf(stdout, "%-20s: %" PRIx64 "\n", "log level", log_level);
  fprintf(stdout, "%-20s: %s\n", "log file", log_file);
  fprintf(stdout, "%-20s: %" PRIu8 "\n", "number of threads", n_threads);
  fprintf(stdout, "%-20s: %" PRIu16 "\n", "port number", default_port);
  fprintf(stdout, "\n");
  fprintf(stdout, "VPN specific settings:\n");
  fprintf(stdout, "\n");
  fprintf(stdout, "%-20s: %s\n", "name", name);
  fprintf(stdout, "%-20s: %s\n", "ip", local_ip);
  fprintf(stdout, "%-20s: %s\n", "netmask", netmask);
  fprintf(stdout, "%-20s: %s\n", "routing", routing);
  fprintf(stdout, "%-20s: %s\n", "dns", dns);

  fprintf(stdout,
          "%-20s: %s\n",
          "bootstrap url",
          bootstrap_url ? bootstrap_url : "not specified");
  fprintf(stdout, "\n");
  fprintf(stdout,
          "startup in %s mode \n",
          run_as_daemon == true ? "daemon" : "console");
  fprintf(stdout, "\n");

  // Signal handling setup

  // SIGTERM handler
  struct sigaction sa = {0};
  sa.sa_flags         = 0;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGQUIT);
  sigaddset(&sa.sa_mask, SIGHUP);
  sa.sa_handler = sigterm_handler;
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);

  sa.sa_handler = sighup_handler;
  sigaction(SIGHUP, &sa, NULL);

  // run as daemon ?
  if (run_as_daemon) {
    np_daemonize(NP_DAEMON_NO_CHROOT);
  }
  // setup and init neuropil base structures
  struct np_settings cfg;
  np_default_settings(&cfg);

  cfg.log_level    = log_level;
  cfg.leafset_size = leafset_size;
  cfg.n_threads    = n_threads;
  strncpy(cfg.log_file, log_file, 255);

  ac = np_new_context(&cfg);

  install_network_interfaces(ac, default_port);

  // install a first tunnel device
  install_tuntap_interfaces(ac, device, local_ip, netmask, name, routing, dns);
  // you may install additional interfaces and networks to route traffic through
  // install_tuntap_interfaces(ac, "192.168.112.3", NULL, NULL);

  np_set_authenticate_cb(ac, authenticate);
  np_set_authorize_cb(ac, authorize);

  // set the realm to forward aaa request to it
  // np_realm_set(ac, realm);
  // np_realm_enable_authentication(ac);
  // np_realm_enable_authorization(ac);
  // np_realm_enable_accounting(ac);

  char address[256];
  assert(np_ok == np_get_address(ac, address, sizeof(address)));
  fprintf(stdout,
          "\nThis vpn-relay was started with the following main "
          "address: %s\n",
          address);

  assert(np_ok == np_run(ac, 0.0));

  if (bootstrap_url != NULL) {
    assert(np_ok == np_join(ac, bootstrap_url));
  }

  fprintf(stdout, "entering vpn-relay endless loop ...\n");
  fflush(stdout);

  enum np_return status;
  do {
    status = np_run(ac, 5.0);
  } while (np_ok == status);

  return status;
}

bool authenticate(NP_UNUSED np_context *ac, struct np_token *token) {
  // TODO: Make sure that id->public_key is an authenticated peer!
  char issuer_buffer[65] = {0};
  char uuid_buffer[33]   = {0};
  sodium_bin2hex(uuid_buffer, 33, (const unsigned char *)token->uuid, 16);

  fprintf(stdout,
          "new node joined (i: %s, s: %s, u: %s\n",
          np_id_str(issuer_buffer, (const unsigned char *)token->issuer),
          token->subject,
          uuid_buffer);
  return true;
}

bool authorize(NP_UNUSED np_context *ac, struct np_token *token) {
  // TODO: Make sure that id->public_key is an authenticated peer!
  char issuer_buffer[65] = {0};
  char uuid_buffer[33]   = {0};
  sodium_bin2hex(uuid_buffer, 33, (const unsigned char *)token->uuid, 16);
  fprintf(stdout,
          "new vpn peer joined (i: %s, s: %s, u: %s\n",
          np_id_str(issuer_buffer, (const unsigned char *)token->issuer),
          token->subject,
          uuid_buffer);
  return true;
}

bool install_network_interfaces(np_context *ac, uint16_t port) {
  struct ifaddrs *ifaddr, *ifa;
  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    return false;
  }
  // Arrays to store IP addresses
  char    public_ips[8][64]   = {0};
  char    private_ips[16][64] = {0};
  uint8_t public_count = 0, private_count = 0;

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) continue;

    int  family = ifa->ifa_addr->sa_family;
    char host[64];

    if (family == AF_INET || family == AF_INET6) {
      if (ifa->ifa_addr->sa_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop(AF_INET, &s->sin_addr, host, INET_ADDRSTRLEN);
      } else if (ifa->ifa_addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)ifa->ifa_addr;
        inet_ntop(AF_INET6, &s->sin6_addr, host, INET6_ADDRSTRLEN);
      }

      if (_np_network_is_private_address(NULL, host) && private_count < 16) {
        // Check if it's a public IP (simplified check, might need refinement)
        fprintf(stdout, "adding ip %s to private interface list\n", host);
        strncpy(private_ips[private_count], host, 64);
        private_count++;
        continue;
      } else if (_np_network_is_private_address(NULL, host)) {
        continue;
      }

      if (!_np_network_is_loopback_address(NULL, host) && public_count < 8) {
        fprintf(stdout, "adding ip %s to public interface list\n", host);
        strncpy(public_ips[public_count], host, 64);
        public_count++;
        continue;
      } else {
        // fprintf(stderr,
        //         "private (%" PRIu8 " ) / public ( %" PRIu8
        //         ") interfaces exceeded or loopback ip %s\n",
        //         private_count,
        //         public_count,
        //         host);
      }
    }
  }
  freeifaddrs(ifaddr);

  // Listen on a passive localhost connection so that we are always able to
  // create connectivity with the outside world (populate main interface)
  // prefer ipv6 connectivity
  // if (np_ok != np_listen(ac, "pas6", "localhost", port)) {
  //   fprintf(stderr, "Failed to listen on pas6:localhost:%d\n", port);
  // }
  if (np_ok != np_listen(ac, "pas4", "localhost", port)) {
    fprintf(stderr, "Failed to listen on pas4:localhost:%d\n", port);
  }
  fprintf(stdout, "\nsetup of passive localhost interfaces done\n\n");

  // Then listen on our public IPs
  for (int16_t i = 0; i < public_count; i++) {
    const char *proto = (strchr(public_ips[i], ':') == NULL) ? "udp4" : "udp6";
    if (np_ok != np_listen(ac, proto, public_ips[i], port)) {
      fprintf(stderr,
              "Failed to listen on public ip %s:%s\n",
              proto,
              public_ips[i]);
    } else {
      fprintf(stdout, "Listening on public ip %s:%s\n", proto, public_ips[i]);
      memset(public_ips[i], 0, 64);
    }
  }
  fprintf(stdout, "\nsetup of public network interfaces done\n\n");

  // Then listen on private IPs
  for (uint8_t i = 0; i < private_count; i++) {
    const char *proto = (strchr(private_ips[i], ':') == NULL) ? "udp4" : "udp6";
    if (np_ok != np_listen(ac, proto, private_ips[i], port)) {
      fprintf(stderr,
              "Failed to listen on private ip %s:%s\n",
              proto,
              private_ips[i]);
    } else {
      fprintf(stdout, "Listening on private ip %s:%s\n", proto, private_ips[i]);
      memset(private_ips[i], 0, 64);
    }
  }
  fprintf(stdout, "\nsetup of network private interfaces done\n");

  return true;
}

bool install_tuntap_interfaces(np_context *context,
                               const char *device,
                               const char *ip,
                               const char *netmask,
                               const char *name,
                               const char *routing,
                               const char *dns) {

  struct np_tuntap *tun_device = calloc(1, sizeof(struct np_tuntap));
  tun_device->status           = np_uninitialized;

  strncpy((char *)&tun_device->ip[0], ip, 16);
  strncpy((char *)&tun_device->netmask[0], netmask, 16);
  strncpy((char *)&tun_device->domain[0], name, 255);

  if (device) strncpy((char *)&tun_device->tuntap_dev[0], device, 16);
  if (routing != NULL) strncpy((char *)&tun_device->routing[0], routing, 16);
  if (dns != NULL) strncpy((char *)&tun_device->dns[0], dns, 16);

  np_tuntap_init(context, tun_device);

  if (tun_device->status == np_error) {
    np_tuntap_destroy(ac, tun_device);
    exit(1);
  }
  fflush(stdout);

  np_tuntap_start(context, tun_device);
  return true;
}
