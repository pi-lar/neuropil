//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "np_log.h"
#include "np_legacy.h"
#include "np_types.h"

#include "example_helper.c"

 
int main(int argc, char **argv)
{
	int no_threads = 8;
	char *j_key = NULL;
	char* proto = "udp4";
	char* port = NULL;
	char* publish_domain = NULL;
	int level = -2;
	char* logpath = ".";

	if (parse_program_args(
		__FILE__,
		argc,
		argv,
		&no_threads,
		&j_key,
		&proto,
		&port,
		&publish_domain,
		&level,
		&logpath,
		NULL,
		NULL
	) == false) {
		exit(EXIT_FAILURE);
	}

	/**
	for the general initialisation of a node please look into the neuropil_node example
	*/
	

	struct np_settings *settings = np_default_settings(NULL);
	settings->n_threads = no_threads;

	snprintf(settings->log_file, 255, "%s%s_%s.log", logpath, "/neuropil_node", port);
	fprintf(stdout, "logpath: %s\n", settings->log_file);
	settings->log_level = level;

	np_context * context = np_new_context(settings);

	if (np_ok != np_listen(context, proto, publish_domain, atoi(port))) {
		printf("ERROR: Node could not listen");
		exit(EXIT_FAILURE);
	}
	if (np_ok != np_run(context, 0)) {
		printf("ERROR: Node could not start");
		exit(EXIT_FAILURE);
	}

	/**
	\endcode
	*/

	if (NULL != j_key)
	{
		np_join(context, j_key);
	}
	np_waitforjoin(context);

	while (1)
	{
		np_time_sleep(0.9);
		char* testdata;

		uint32_t real_seq = np_receive_text(context, "this.is.a.test", &testdata);
		if (0 < real_seq)
			log_msg(LOG_INFO, "received message %u: %s", real_seq, testdata);
		else
			log_debug_msg(LOG_DEBUG, "message receive failed ...");

		free(testdata);
	}
}
