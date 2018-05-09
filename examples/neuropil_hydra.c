//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/**
 *.. NOTE::
 *
 *   If you are not yet familiar with the neuropil initialization procedure please refer to the :ref:`tutorial`
 */

#include <stdio.h>

#include "np_interface.h"
#include "np_log.h"

#define SIZE(ARRAY) (sizeof(ARRAY) / sizeof(ARRAY[0]))

int main(int argc, char **argv)
{
	np_context* nodes[2] = { 0 };

	char addr[500];
	uint16_t tmp;
	for (int i=0; i < SIZE(nodes); i++) {
		printf("INFO: Starting Node %d\n", i);
		fflush(NULL);

		int port = 3000 + i;
		struct np_settings * settings = np_default_settings(NULL);		
		sprintf(settings->log_file, "neuropil_hydra_%d.log", port);
		settings->log_level |= LOG_MESSAGE;
		settings->log_level |= LOG_ROUTING;
		settings->log_level |= LOG_NETWORK;

		nodes[i] = np_new_context(settings); // use default settings
		
		if (np_ok != (tmp = np_listen(nodes[i], "udp4", "localhost", port))) {
			printf("ERROR: Node %d could not listen. %s\n", i, np_error_str[tmp]);
		}
		else {
			if (np_ok != (tmp = np_get_address(nodes[i], addr, SIZE(addr)))) {
				printf("ERROR: Could not get address of node %d. %s\n", i, np_error_str[tmp]);
			}
			printf("INFO: Node %d aka  (%s) listens\n", i, addr);

			if (i > 0) {
				// get connection str of previous node
				if (np_ok != (tmp = np_get_address(nodes[i - 1], addr, SIZE(addr)))) {
					printf("ERROR: Could not get address of node %d. %s\n", i, np_error_str[tmp]);
				}
				// join previous node			
				if (np_ok != (tmp=np_join(nodes[i], addr)) ){
					printf("ERROR: Node %d could not join. %s\n", i, np_error_str[tmp]);
				}
				else {
					printf("INFO: Node %d joins %s\n", i, addr);
				}
			}
		}
	}

	while (true)
	{		
		for (int i = 0; i < SIZE(nodes); i++) {			
			if (np_ok != (tmp = np_run(nodes[i], 0.001))) {
				printf("ERROR: Node %d could not run. %s\n", i, np_error_str[tmp]);
			}
		}
	}
}