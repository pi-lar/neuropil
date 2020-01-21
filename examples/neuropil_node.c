//
// neuropil is copyright 2016-2019 by pi-lar GmbH
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
#include "np_aaatoken.h"
#include "np_keycache.h"
#include "np_tree.h"
#include "np_types.h"

#include "example_helper.c"


int main(int argc, char **argv)
{
	int ret = 0;

	char* realm = NULL;
	char* code = NULL;

	int no_threads = 8;
	char *j_key = NULL;
	char* proto = "udp4";
	char* port = NULL;
	char* publish_domain = NULL;
	int level = -2;
	char* logpath = ".";

	example_user_context* user_context;
	if ((user_context = parse_program_args(
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
		"[-r realmname]",
		"r:",
		&realm,
		&code
	)) == NULL) {
		exit(EXIT_FAILURE);
	}

	struct np_settings settings;
	np_default_settings(&settings);
	settings.n_threads = no_threads;

	snprintf(settings.log_file, 255, "%s%s_%s.log", logpath, "/neuropil_node", port);
	settings.log_level = level;

	np_context * ac = np_new_context(&settings);
	np_set_userdata(ac, user_context);
	np_ctx_cast(ac);

	np_example_print(context, stdout, "logpath: %s\n", settings.log_file);

	np_example_save_and_load_identity(context);

	if (NULL != realm)
	{
		np_set_realm_name(context, realm);
		np_enable_realm_client(context);
	}

	if (np_ok != np_listen(context, proto, publish_domain, atoi(port))) {
		np_example_print(context, stderr, "ERROR: Node could not listen to %s:%s:%s",proto, publish_domain, port);
	}
	else {
		__np_example_helper_loop(context); // for the fancy ncurse display

		if (NULL != j_key)
		{
			np_example_print(context, stdout, "try to join %s\n", j_key);
			// join previous node			
			if (np_ok != np_join(context, j_key)) {
				np_example_print(context, stderr, "ERROR: Node could not join");
			}
		}

		log_debug_msg(LOG_DEBUG, "starting job queue");

		if (np_ok != np_run(context, 0.001)) {
			np_example_print(context, stderr, "ERROR: Node could not run");
		}
		else { 
			__np_example_helper_run_info_loop(context);
		}
		np_example_print(context, stderr, "Closing Node");
	}

	return ret;
}
