#include <errno.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "np_memory.h"
#include "neuropil.h"
#include "log.h"
#include "dtime.h"
#include "np_jobqueue.h"
#include "np_jtree.h"
#include "np_message.h"
#include "np_node.h"
#include "np_threads.h"

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
	// int seq;

	char* subject = (char*) jrb_find_str(msg->body, "subject")->val.value.s;
	// pn_data_t* inst = pn_message_instructions(m);
	// int msgtype = pn_data_get_int(inst);

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
	sprintf(log_file, "%s_%d.log", "./neuropil_controller", port);
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_ROUTING | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO;
	log_init(log_file, level);

	state = np_init(port);
	state->my_key->node->joined_network = 1;

	// dsleep(50);
	log_msg(LOG_DEBUG, "starting job queue");
	np_start_job_queue(state, 8);

	np_message_t* msg_out;

	while (1) {
		size_t nbytes = 255;
		char* my_string = (char *) malloc (nbytes);
		printf("enter a node to start (key:host:port)\n");
		int bytes_read = getline (&my_string, &nbytes, stdin);
		if (bytes_read > 255 || bytes_read < 64) {
			printf("given identifier too long or to small, skipping invitation ...\n");
			continue;
		}
		log_msg(LOG_DEBUG, "creating internal structure");

		np_key_t* node_key = NULL;

		LOCK_CACHE(state) {
			node_key = np_node_decode_from_str(state, my_string);
		}
		log_msg(LOG_DEBUG, "creating welcome message");
		np_new_obj(np_message_t, msg_out);

		np_jtree_t* jrb_me = make_jtree();
		np_node_encode_to_jrb(jrb_me, state->my_key);
		np_message_create(msg_out, node_key, state->my_key , NP_MSG_JOIN_REQUEST, jrb_me);

		log_msg(LOG_DEBUG, "submitting welcome message");
		np_msgproperty_t* prop = np_message_get_handler(state, OUTBOUND, NP_MSG_JOIN_REQUEST);
		job_submit_msg_event(state->jobq, prop, node_key, msg_out);

		dsleep(1.0);
	}
	// pthread_exit(NULL);
}
