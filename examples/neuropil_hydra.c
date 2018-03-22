//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/**
 *.. NOTE::
 *
 *   If you are not yet familiar with the neuropil initialization procedure please refer to the :ref:`tutorial`
 */

#include <stdio.h>

#include "np_interface.h"

#define SIZE(ARRAY) (sizeof(ARRAY) / sizeof(ARRAY[0]))

int main(int argc, char **argv)
{
	np_context* nodes[10] = { 0 };

	char addr[500];
	for (int i=0; i < SIZE(nodes); i++) {

		nodes[i] = np_new_context(NULL); // use default settings
		
		if (np_ok != np_listen(nodes[i], "udp3", "localhost", 3000 + i)) {
			printf("ERROR: Node %d could not listen", i);
		}
		if (i > 0) {
			// get connection str of previous node
			if (np_ok != np_get_address(nodes[i - 1], addr, SIZE(addr))) {
				printf("ERROR: Could not get address of node %d", i);
			}
			// join previous node			
			if (np_ok != np_join(nodes[i], addr)) {
				printf("ERROR: Node %d could not join", i);
			}
		}		
	}

	while (true)
	{		
		for (int i = 0; i < SIZE(nodes); i++) {			
			if (np_ok != np_run(nodes[i], 0.001)) {
				printf("ERROR: Node %d could not run", i);
			}
		}
	}
}