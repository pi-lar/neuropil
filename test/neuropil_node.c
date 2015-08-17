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



#define USAGE "neuropil [ -b bootstrap:port ] port"
#define OPTSTR "b::"

#define DEBUG 0
#define NUM_HOST 120

extern char *optarg;
extern int optind;

np_node_t *driver;
np_state_t *state;

np_key_t* key;
np_key_t* destinations[100];

int seq = -1;
int joinComplete = 0;


void deliver(np_key_t* key, np_message_t* msg)
{
	// char s[256];
	// np_message_t *message;

	char* subject = jrb_find_str(msg->header, "subject")->val.value.s;

	//  unsigned long dest;
	// TODO: lookup software hook
	// TODO: only when no software hook is present, try to send directly to closest host
	// np_node_t* host = np_node_lookup(state->nodes, subject);
	// np_node_t* host = np_node_decode_from_str(state->nodes, subject);
	// message_send(state->messages, host, m, TRUE, 1);

	log_msg(LOG_DEBUG, "DELIVER: %s", subject);
	// np_key_t* 

	// log_msg(LOG_DEBUG, "message %d to %s delivered to %s", seq, key_get_as_string(dest), key_get_as_string(key));
}


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

	// np_waitforjoin(state);

	while (1) {
		dsleep(0.1);
	}
	// pthread_exit(NULL);
}
