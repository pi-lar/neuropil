#include <errno.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "np_memory.h"
#include "neuropil.h"
#include "log.h"
#include "dtime.h"
#include "np_jobqueue.h"
#include "np_message.h"

#include "include.h"



#define USAGE "neuropil_node [ -b bootstrap:port ] port"
#define OPTSTR "b::"

#define DEBUG 0
#define NUM_HOST 120

extern char *optarg;
extern int optind;

np_state_t *state;

int main(int argc, char **argv) {

	int opt;
	char *hn = NULL;
	int port, joinport;
	int i;

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF) {
		switch ((char) opt) {
		case 'b':
			for (i = 0; optarg[i] != ':' && i < strlen(optarg); i++);
			optarg[i] = 0;
			hn = optarg;
			sscanf(optarg + (i + 1), "%d", &joinport);
			break;
		default:
			fprintf(stderr, "invalid option %c\n", (char) opt);
			fprintf(stderr, "usage: %s\n", USAGE);
			exit(1);
		}
	}

	if ((argc - optind) != 1) {
		fprintf(stderr, "usage: %s\n", USAGE);
		exit(1);
	}

	port = atoi(argv[optind]);

	char log_file[256];
	sprintf(log_file, "%s_%d.log", "./neuropil_node", port);
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_ROUTING | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	log_init(log_file, level);

	state = np_init(port);

	log_msg(LOG_DEBUG, "starting job queue");
	np_start_job_queue(state, 8);

	while (1) {
		dsleep(0.1);
	}
}
