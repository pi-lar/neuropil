//
// neuropil is copyright 2016-2017 by pi-lar GmbH
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
#include "np_aaatoken.h"
#include "np_keycache.h"
#include "np_tree.h"
#include "np_types.h"
#include "np_sysinfo.h"

#include "example_helper.c"


int main(int argc, char **argv)
{
	char* realm = NULL;
	char* code = NULL;

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
		"[-r realmname] [-c code]",
		"r:c:",
		&realm,
		&code
	) == FALSE) {
		exit(EXIT_FAILURE);
	}

	struct np_settings *settings = np_new_settings(NULL);
	settings->n_threads = no_threads;

	sprintf(settings->log_file, "%s%s_%s.log", logpath, "/neuropil_node", port);
	fprintf(stdout, "logpath: %s\n", settings->log_file);
	settings->log_level = level;

	context = np_new_context(settings); // use default settings

	
	if (NULL != realm)
	{
		np_set_realm_name(context, realm);
		np_enable_realm_slave(context);
		if (NULL != code)
		{
			np_tree_insert_str(context->my_node_key->aaa_token->extensions,
				"passcode",
				np_treeval_new_hash(code));
		}
	}
	if (np_ok != np_listen(context, proto, publish_domain, atoi(port))) {
		printf("ERROR: Node could not listen");
	}
	else {

		if (NULL != j_key)
		{
			fprintf(stdout, "try to join %s\n", j_key);
			// join previous node			
			if (np_ok != np_join(context, j_key)) {
				printf("ERROR: Node could not join");
			}
		}

		log_debug_msg(LOG_DEBUG, "starting job queue");

		if (np_ok != np_run(context, 0.001)) {
			printf("ERROR: Node could not run");
		}
		else {
			__np_example_helper_run_info_loop();
		}
	}
}
