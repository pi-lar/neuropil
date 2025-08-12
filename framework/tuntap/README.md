#
# SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0
#

framework module tun/tap driver
-------------------------------

This directory contains a tun/tap implementation which is used in he example application neuropil_vpn.c

Our main intent is to deliver a proxy that can be used as a sidecar component for kubernetes environments or for freebsd jails. 
The VPN example application is mainly developed for testing purposes. The module only covers the setup of the tun/tap devices, 
firewall rules and NAT configuration still have to be done manually or would need an implementation in a different module. However, 
since neuropil embraces ABAC, access to devices can still be controlled based on user attributes and token. Therefore the provided 
module already acts as a firewall for connected systems.

The current implementation only supports IPv4 as for smaller SME the address range is sufficiently large. Adding IPv6 is just a matter of effort,
the core principles stay the same.

The status of tun/tap implementation varies between the platforms.

| Platform | Maturity | Description                                                                                                              |
| -------- | -------- | ------------------------------------------------------------------------------------------------------------------------ |
| Linux    | Alpha    | Opening tun/tap device works. setting of routes, no extensive tests so far                                               |
| FreeBSD  | Beta     | Opening tun/tap device works. setting of routes, partially already tested with additional NAT forwarding                 |
| Darwin   | Beta     | Opening tun/tap device works. setting of routes, setting fo additional DNS entries works. Mostly tested as a VPN client. |
| *        | Beta     | Common data structures, setup of subnets and io-loop handling.                                                           |
| -------- | -------- | ------------------------------------------------------------------------------------------------------------------------ |

Feel free to contribute and to improve the implementations.
