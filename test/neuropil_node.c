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
#include "np_aaatoken.h"
#include "np_keycache.h"
#include "np_tree.h"
#include "np_types.h"

#define USAGE "neuropil_node [ -j key:proto:host:port ] [ -p protocol] [-b port] [-t worker_thread_count] [-r realmname] [-c code]"
#define OPTSTR "j:p:b:t:r:c:"

extern char *optarg;
extern int optind;

int main(int argc, char **argv)
{
	int opt;
	int no_threads = 2;
	char* j_key = NULL;
	char* proto = NULL;
	char* port = NULL;
	char* realm = NULL;
	char* code = NULL;

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
	{
		switch ((char) opt)
		{
		case 'j':
			j_key = optarg;
			break;
		case 't':
			no_threads = atoi(optarg);
			if (no_threads <= 0) no_threads = 8;
			break;
		case 'p':
			proto = optarg;
			break;
		case 'b':
			port = optarg;
			break;
		case 'r':
			realm = optarg;
			break;
		case 'c':
			code = optarg;
			break;
		default:
			fprintf(stderr, "invalid option %c\n", (char) opt);
			fprintf(stderr, "usage: %s\n", USAGE);
			exit(1);
		}
	}

	char log_file[256];
	sprintf(log_file, "%s_%s.log", "./neuropil_node", port);
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_ROUTING | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_AAATOKEN;
	np_log_init(log_file, level);

	np_state_t* state = np_init(proto, port, FALSE);

	if (NULL != realm)
	{
		np_set_realm_name(realm);
		np_enable_realm_slave();
		if (NULL != code)
		{
			tree_insert_str(state->my_node_key->aaa_token->extensions,
							"passcode",
							new_val_hash(code));
		}
	}

	log_msg(LOG_DEBUG, "starting job queue");
	np_start_job_queue(no_threads);

	if (NULL != j_key)
	{
		np_send_join(j_key);
	}
	np_waitforjoin();

	while (1) {
		ev_sleep(1.0);
		// dsleep(0.1);
	}
}
