//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include "neuropil_log.h"
#include "np_log.h"
#include "np_network.h"

int main(int argc, char **argv) {

	char log_file[256];
	sprintf(log_file, "%s.log", "./ipv6_addrinfo");
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_NETWORK | LOG_KEY;

	np_context * context = np_new_context(NULL);

	uint8_t type = UDP | IPv4;
	char hostname[256];
	gethostname(hostname, 255);
	char* service = "31415";
	int err;

	struct addrinfo *ai;
	struct addrinfo *ai_head;
	struct addrinfo hints = { .ai_flags = AI_PASSIVE & AI_CANONNAME & AI_NUMERICSERV};

	if (0 < (type & IPv4) ) {
		hints.ai_family = PF_INET;
	}
	if (0 < (type & IPv6) ) {
		hints.ai_family = PF_INET6;
	}
	if (0 < (type & UDP) ) {
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	}
	if (0 < (type & TCP) ) {
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
	}

	if ( 0 != ( err = getaddrinfo( hostname, service, &hints, &ai_head ) ))
	{
		log_msg(LOG_ERROR, "%s: error getting address info", gai_strerror( err ) );
	}
	for ( ai = ai_head; ai != NULL; ai = ai->ai_next )
	{
		log_msg(LOG_INFO,
				"Setting up a passive socket based on the following address info:\n"
				"   ai_canonname = %s\n"
				"   ai_flags     = 0x%02X\n"
				"   ai_family    = %d (PF_INET = %d, PF_INET6 = %d)\n"
				"   ai_socktype  = %d (SOCK_STREAM = %d, SOCK_DGRAM = %d)\n"
				"   ai_protocol  = %d (IPPROTO_TCP = %d, IPPROTO_UDP = %d)\n"
				"   ai_addrlen   = %d (sockaddr_in = %lu, "
				"sockaddr_in6 = %lu)\n",
				ai->ai_canonname,
				ai->ai_flags,
				ai->ai_family,
				PF_INET,
				PF_INET6,
				ai->ai_socktype,
				SOCK_STREAM,
				SOCK_DGRAM,
				ai->ai_protocol,
				IPPROTO_TCP,
				IPPROTO_UDP,
				ai->ai_addrlen,
				sizeof( struct sockaddr_in ),
				sizeof( struct sockaddr_in6 ) );
	}
}
