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

#define USAGE "neuropil_node [ -j key:proto:host:port ] [ -p protocol] [-b port] [-t worker_thread_count]"
#define OPTSTR "j:p:b:t:"

extern char *optarg;
extern int optind;

int main(int argc, char **argv)
{
	int opt;
	int no_threads = 2;
	char* j_key = NULL;
	char* proto = NULL;
	char* port = NULL;

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF) {
		switch ((char) opt) {
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
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG;
	np_log_init(log_file, level);

	np_init(proto, port, FALSE);

	log_msg(LOG_DEBUG, "starting job queue");
	np_start_job_queue(no_threads);

	while (1) {
		ev_sleep(1.0);
		// dsleep(0.1);
	}
}
