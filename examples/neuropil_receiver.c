//
// neuropil is copyright 2016 by pi-lar GmbH
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
#include "neuropil.h"
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

	int opt;
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
	) == FALSE) {
		exit(EXIT_FAILURE);
	}

	/**
	for the general initialisation of a node please look into the neuropil_node example
	*/

	char log_file[256];
	sprintf(log_file, "%s%s_%s.log", logpath, "/neuropil_node", port);
	np_log_init(log_file, level);

	np_init(proto, port, publish_domain);

	log_debug_msg(LOG_DEBUG, "starting job queue");
	np_start_job_queue(no_threads);

	if (NULL != j_key)
	{
		np_send_join(j_key);
	}
	np_waitforjoin();


	while (1)
	{
		ev_sleep(0.9);
		char* testdata;

		uint32_t real_seq = np_receive_text("this.is.a.test", &testdata);
		if (0 < real_seq)
			log_debug_msg(LOG_DEBUG, "received message %u: %s", real_seq, testdata);
		else
			log_debug_msg(LOG_DEBUG, "message receive failed ...");

		free(testdata);
	}
}
