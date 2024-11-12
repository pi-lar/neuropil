//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include <assert.h>
#include <criterion/criterion.h>
#include <stdlib.h>

#include "../test_macros.c"

#include "neuropil.h"

#include "np_network.h"

TestSuite(network_h);

Test(network_h,
     _np_network_get_outgoing_ip,
     .description = "test the retrieval of the outgoing IP address") {
  CTX() {}

  char           outgoing_ip[255];
  char           local_ip[255];
  enum np_return ret;

  // Test with valid external hostname (e.g., Google's DNS)
  ret =
      _np_network_get_outgoing_ip(context, "8.8.8.8", UDP | IPv4, outgoing_ip);
  cr_expect_eq(ret, np_ok, "Failed to get outgoing IPv4 address for 8.8.8.8");
  cr_expect_str_neq(outgoing_ip,
                    "",
                    "Outgoing IPv4 address should not be empty");

  // Compare with local IP
  ret = _np_network_get_local_ip(context, outgoing_ip, UDP | IPv4, local_ip);
  cr_expect_eq(ret, np_ok, "Failed to get local IPv4 address");
  cr_expect_str_eq(outgoing_ip,
                   local_ip,
                   "Outgoing IP should match local IP for external target");

  // Test with localhost
  ret = _np_network_get_outgoing_ip(context,
                                    "localhost",
                                    UDP | IPv4,
                                    outgoing_ip);
  cr_expect_eq(ret, np_ok, "Failed to get outgoing IPv4 address for localhost");
  cr_expect_str_eq(outgoing_ip,
                   "127.0.0.1",
                   "Outgoing IP for localhost should be 127.0.0.1");

  // Test with invalid hostname
  ret = _np_network_get_outgoing_ip(context,
                                    "invalid.example.com",
                                    UDP | IPv4,
                                    outgoing_ip);
  cr_expect_eq(ret, np_invalid_argument, "Should fail with invalid hostname");

  // Test with IPv6 - currently not supported in build pipeline
  //   ret = _np_network_get_outgoing_ip(context,
  //                                     "2001:4860:4860::8888",
  //                                     UDP | IPv6,
  //                                     outgoing_ip);
  //   cr_expect_eq(ret, np_ok, "Failed to get outgoing IPv6 address");
  //   cr_expect_str_neq(outgoing_ip,
  //                     "",
  //                     "Outgoing IPv6 address should not be empty");

  // Compare with local IPv6 - currently not supported in build pipeline
  //   ret = _np_network_get_local_ip(context, outgoing_ip, UDP | IPv6,
  //   local_ip); cr_expect_eq(ret, np_ok, "Failed to get local IPv6 address");
  //   cr_expect_str_eq(outgoing_ip,
  //                    local_ip,
  //                    "Outgoing IPv6 should match local IPv6 for external
  //                    target");

  // Test with invalid protocol
  //   ret = _np_network_get_outgoing_ip(context, "8.8.8.8", 0, outgoing_ip);
  //   cr_expect_eq(ret, np_invalid_argument, "Should fail with invalid
  //   protocol");
}

Test(network_h,
     _np_network_get_remote_ip,
     .description = "test the retrieval of remote IP addresses") {
  CTX() {}

  char           remote_ip[255];
  enum np_return ret;

  // Test with valid hostname (IPv4)
  ret =
      _np_network_get_remote_ip(context, "example.com", UDP | IPv4, remote_ip);
  cr_expect_eq(ret, np_ok, "Failed to get remote IPv4 address for example.com");
  cr_expect_str_neq(remote_ip, "", "Remote IPv4 address should not be empty");

  // Test with valid hostname (IPv6) - currently not supported in build pipeline
  //   ret =
  //       _np_network_get_remote_ip(context, "example.com", UDP | IPv6,
  //       remote_ip);
  //   cr_expect_eq(ret, np_ok, "Failed to get remote IPv6 address for
  //   example.com"); cr_expect_str_neq(remote_ip, "", "Remote IPv6 address
  //   should not be empty");

  // Test with valid IP address input (IPv4)
  ret = _np_network_get_remote_ip(context,
                                  "93.184.216.34",
                                  UDP | IPv4,
                                  remote_ip);
  cr_expect_eq(ret,
               np_ok,
               "Failed to get remote IPv4 address for 93.184.216.34");
  cr_expect_str_eq(remote_ip,
                   "93.184.216.34",
                   "Remote IPv4 address should match input");

  // Test with valid IP address input (IPv6) - currently not supported in build
  // pipeline
  //   ret = _np_network_get_remote_ip(context,
  //                                   "2606:2800:220:1:248:1893:25c8:1946",
  //                                   UDP | IPv6,
  //                                   remote_ip);
  //   cr_expect_eq(ret,
  //                np_ok,
  //                "Failed to get remote IPv6 address for "
  //                "2606:2800:220:1:248:1893:25c8:1946");
  //   cr_expect_str_eq(remote_ip,
  //                    "2606:2800:220:1:248:1893:25c8:1946",
  //                    "Remote IPv6 address should match input");

  // Test with invalid hostname
  ret = _np_network_get_remote_ip(context,
                                  "invalid.example.com",
                                  UDP | IPv4,
                                  remote_ip);
  cr_expect_eq(ret, np_operation_failed, "Should fail with invalid hostname");

  // Test with invalid IP address input
  ret = _np_network_get_remote_ip(context,
                                  "999.999.999.999",
                                  UDP | IPv4,
                                  remote_ip);
  cr_expect_eq(ret,
               np_operation_failed,
               "Should fail with invalid IP address input");

  // Test with invalid protocol
  // ret = _np_network_get_remote_ip(context, "example.com", 0, remote_ip);
  // cr_expect_eq(ret, np_invalid_argument, "Should fail with invalid
  // protocol");
}

Test(network_h,
     _np_network_get_local_ip,
     .description = "test the retrieval of the local ip address") {
  CTX() {}

  char           local_ip[255];
  char           hostname[255];
  enum np_return ret;

  gethostname(hostname, 255);

  // Test IPv4 UDP with hostname
  ret = _np_network_get_local_ip(context, "localhost", UDP | IPv4, local_ip);
  cr_expect_eq(ret,
               np_ok,
               "Failed to get local IPv4 UDP address with hostname");
  cr_expect_str_neq(local_ip, "", "IPv4 UDP address should not be empty");
  cr_expect_str_eq(local_ip,
                   "127.0.0.1",
                   "IPv4 UDP address should be 127.0.0.1");

  // Test IPv4 TCP with hostname
  ret = _np_network_get_local_ip(context, hostname, TCP | IPv4, local_ip);
  cr_expect_eq(ret,
               np_ok,
               "Failed to get local IPv4 TCP address with hostname");
  cr_expect_str_neq(local_ip, "", "IPv4 TCP address should not be empty");

  // Test IPv6 UDP with hostname - currently not supported in build pipeline
  //   ret = _np_network_get_local_ip(context, "localhost", UDP | IPv6,
  //   local_ip); cr_expect_eq(ret,
  //                np_ok,
  //                "Failed to get local IPv6 UDP address with hostname");
  //   cr_expect_str_neq(local_ip, "", "IPv6 UDP address should not be empty");

  // Test IPv6 UDP with hostname - currently not supported in build pipeline
  //   ret = _np_network_get_local_ip(context, hostname, UDP | IPv6, local_ip);
  //   cr_expect_eq(ret,
  //                np_ok,
  //                "Failed to get local IPv6 UDP address with hostname");
  //   cr_expect_str_neq(local_ip, "", "IPv6 UDP address should not be empty");

  // Test IPv6 TCP with hostname
  ret = _np_network_get_local_ip(context, "localhost", TCP | IPv6, local_ip);
  cr_expect_eq(ret,
               np_ok,
               "Failed to get local IPv6 TCP address with hostname");
  cr_expect_str_neq(local_ip, "", "IPv6 TCP address should not be empty");

  // Test with IPv4 address input
  ret = _np_network_get_local_ip(context, "127.0.0.1", UDP | IPv4, local_ip);
  cr_expect_eq(ret, np_ok, "Failed to get local IPv4 address with IP input");
  cr_expect_str_eq(local_ip, "127.0.0.1", "IPv4 address should match input");

  // Test with IPv6 address input
  ret = _np_network_get_local_ip(context, "::1", UDP | IPv6, local_ip);
  cr_expect_eq(ret, np_ok, "Failed to get local IPv6 address with IP input");
  cr_expect_str_eq(local_ip, "::1", "IPv6 address should match input");

  // Test with NULL context (should still work)
  ret = _np_network_get_local_ip(NULL, "localhost", UDP | IPv4, local_ip);
  cr_expect_eq(ret, np_ok, "Failed to get local IP with NULL context");
  cr_expect_str_neq(local_ip,
                    "",
                    "IP address with NULL context should not be empty");

  // Test with invalid protocol
  ret = _np_network_get_local_ip(context, "localhost", 0, local_ip);
  cr_expect_eq(ret, np_invalid_argument, "Should fail with invalid protocol");

  // Test with invalid hostname
  ret = _np_network_get_local_ip(context,
                                 "invalid_hostname",
                                 UDP | IPv4,
                                 local_ip);
  cr_expect_eq(ret, np_operation_failed, "Should fail with invalid hostname");

  // Test with invalid IP address input
  ret = _np_network_get_local_ip(context,
                                 "999.999.999.999",
                                 UDP | IPv4,
                                 local_ip);
  cr_expect_eq(ret,
               np_operation_failed,
               "Should fail with invalid IP address input");
}

Test(network_h,
     _np_network_count_common_tuples,
     .description = "test the retrieval of the local ip address") {
  // a test case that is testing the function _np_network_count_common_tuples.
  // The test covers IPv4, IPv6 and mixed combinations.

  np_network_t *ng = NULL;

  // Test IPv4 addresses with common prefixes
  uint8_t common =
      _np_network_count_common_tuples(ng, "192.168.1.1", "192.168.1.2");
  cr_expect_eq(common,
               3,
               "IPv4 addresses with 3 common octets should return 3");

  common = _np_network_count_common_tuples(ng, "192.168.1.1", "192.168.2.1");
  cr_expect_eq(common,
               2,
               "IPv4 addresses with 2 common octets should return 2");

  common = _np_network_count_common_tuples(ng, "192.168.1.1", "192.169.1.1");
  cr_expect_eq(common, 1, "IPv4 addresses with 1 common octet should return 1");

  common = _np_network_count_common_tuples(ng, "192.168.1.1", "172.168.1.1");
  cr_expect_eq(common,
               0,
               "IPv4 addresses with no common octets should return 0");

  // Test IPv6 addresses with common prefixes
  common =
      _np_network_count_common_tuples(ng,
                                      "2001:db8:85a3:8d3:1319:8a2e:370:7348",
                                      "2001:db8:85a3:8d3:1319:8a2e:370:7349");
  cr_expect_eq(common,
               7,
               "IPv6 addresses with 7 common blocks should return 7");

  common =
      _np_network_count_common_tuples(ng,
                                      "2001:db8:85a3:8d3:1319:8a2e:370:7348",
                                      "2001:db8:85a3:8d3:1319:8a2e:371:7348");
  cr_expect_eq(common,
               6,
               "IPv6 addresses with 6 common blocks should return 6");

  common =
      _np_network_count_common_tuples(ng,
                                      "2001:db8:85a3:8d3:1319:8a2e:370:7348",
                                      "2001:db8:85a3:8d3:1319:8a2f:370:7348");
  cr_expect_eq(common,
               5,
               "IPv6 addresses with 5 common blocks should return 5");

  // Test mixed IPv4/IPv6 combinations
  common = _np_network_count_common_tuples(ng, "192.168.1.1", "2001:db8::1");
  cr_expect_eq(common, 0, "Mixed IPv4/IPv6 addresses should return 0");

  common = _np_network_count_common_tuples(ng, "2001:db8::1", "192.168.1.1");
  cr_expect_eq(common, 0, "Mixed IPv6/IPv4 addresses should return 0");

  // Test invalid inputs
  common = _np_network_count_common_tuples(ng, "invalid", "192.168.1.1");
  cr_expect_eq(common, 0, "Invalid IP address should return 0");

  common = _np_network_count_common_tuples(ng, "192.168.1.1", "invalid");
  cr_expect_eq(common, 0, "Invalid IP address should return 0");

  common = _np_network_count_common_tuples(ng, "invalid1", "invalid2");
  cr_expect_eq(common, 0, "Invalid IP addresses should return 0");
}
