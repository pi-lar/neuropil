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
	char* http_domain = NULL;
	char* sysinfo_opt = NULL;
	int sysinfo_Mode = 1;

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
		"[-r realmname] [-c code] [-w http domain] [-i sysinfo 0=none,1=auto,2=master,3=slave]",
		"r:c:w:i:",
		&realm,
		&code,
		&http_domain,
		&sysinfo_opt
	) == FALSE) {
		exit(EXIT_FAILURE);
	}

	if (sysinfo_opt != NULL) {
		sysinfo_Mode = atoi(sysinfo_opt);
	}
	char log_file[256];
	sprintf(log_file, "%s%s_%s.log", logpath, "/neuropil_node", port);
	fprintf(stdout, "logpath: %s\n", log_file);
	np_log_init(log_file, level);

	np_state_t* state = np_init(proto, port, publish_domain);

	if (NULL != realm)
	{
		np_set_realm_name(realm);
		np_enable_realm_slave();
		if (NULL != code)
		{
			np_tree_insert_str(state->my_node_key->aaa_token->extensions,
							"passcode",
							np_treeval_new_hash(code));
		}
	}

	// starting the example http server to support the http://view.neuropil.io application	
	example_http_server_init(http_domain, sysinfo_Mode);

	np_sysinfo_enable_slave();


	np_statistics_add_watch_internals();
	np_statistics_add_watch(_NP_SYSINFO_REQUEST);
	np_statistics_add_watch(_NP_SYSINFO_REPLY);


	log_debug_msg(LOG_DEBUG, "starting job queue");
	np_start_job_queue(no_threads);

	if (NULL != j_key)
	{
		fprintf(stdout, "try to join %s\n", j_key);
		np_send_join(j_key);
		fprintf(stdout, "wait for join acceptance...");
	}
	else {
		fprintf(stdout, "wait for nodes to join...");
	}
	
	fflush(NULL);
	np_waitforjoin();
	fprintf(stdout, "Connected\n");

	__np_example_helper_run_info_loop();
}