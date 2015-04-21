#include <errno.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "proton/message.h"

#include "include.h"

#include "neuropil.h"
#include "log.h"
#include "dtime.h"
#include "job_queue.h"
#include "network.h"
#include "message.h"
#include "route.h"
#include "node.h"


#define USAGE "neuropil [ -b bootstrap:port ] port"
#define OPTSTR "b::"

#define DEBUG 0
#define NUM_HOST 120

extern char *optarg;
extern int optind;

np_node_t *driver;
np_state_t *state;

Key key;
Key destinations[100];

int seq = -1;
int joinComplete = 0;


void deliver(Key * k, pn_message_t * m) {

	char s[256];
	pn_message_t *message;
	int seq;

	const unsigned char* subject = (unsigned char*) pn_message_get_subject(m);
	pn_data_t* inst = pn_message_instructions(m);
	int msgtype = pn_data_get_int(inst);

	//  unsigned long dest;
	// TODO: lookup software hook
	// TODO: only when no software hook is present, try to send directly to closest host

	// np_node_t* host = np_node_lookup(state->nodes, subject);
	// np_node_t* host = np_node_decode_from_str(state->nodes, subject);
	// message_send(state->messages, host, m, TRUE, 1);

	log_msg(LOG_DEBUG, "DELIVER: %s", subject);

	Key* dest = key_create_from_hash(subject);
	// log_msg(LOG_DEBUG, "message %d to %s delivered to %s", seq, key_get_as_string(dest), key_get_as_string(key));
}


int main(int argc, char **argv) {

	int opt;
	char *hn = NULL;
	int port, joinport;
	np_node_t *join = NULL;
	char tmp[256];
	int i, j;
	pn_message_t *hello;
	char dest[16];
	char msg[200];
	char m[200];
	np_node_t ch;
	double wtime;
	int type;
	int x;

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
	type = atoi(argv[optind + 1]);

	char log_file[256];
	sprintf(log_file, "%s_%d.log", "./neuropil_controller", port);
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_ROUTING | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	log_init(&log_file, level);

	state = np_init(port);

	state->joined_network = 1;
	state->neuropil->bootstrap = state->neuropil->me;

	// dsleep(50);
	log_msg(LOG_DEBUG, "starting job queue");
	np_start_job_queue(state, 8);

	while (1) {
		size_t nbytes = 255;
		char* my_string = (char *) malloc (nbytes);
		printf("enter a node to start (key:host:port)\n");
		int bytes_read = getline (&my_string, &nbytes, stdin);
		if (bytes_read > 255) {
			printf("given identifier too long, skipping invitation ...\n");
			continue;
		}
		char* skey = strtok(my_string, ":");
		char* host = strtok(NULL, ":");
		char* port = strtok(NULL, ":");

		log_msg(LOG_DEBUG, "creating internal structure");
		Key* key = (Key*) malloc(sizeof(Key));
		str_to_key(key, skey);
		np_node_t* node = np_node_lookup(state->nodes, key, 0);
		np_node_update(node, host, atoi(port));

		log_msg(LOG_DEBUG, "creating welcome message");
		pn_data_t* me = pn_data(4);
		np_node_encode_to_amqp(me, state->neuropil->me);
		np_msgproperty_t* prop = np_message_get_handler(state->messages, OUTBOUND, NP_MSG_JOIN_REQUEST);
		pn_message_t* msg = np_message_create(state->messages,node->key, state->neuropil->me->key , NP_MSG_JOIN_REQUEST, me);
		log_msg(LOG_DEBUG, "submitting welcome message");
		job_submit_msg_event(state->jobq, prop, key, msg);

		dsleep(0.01);
	}
	// pthread_exit(NULL);
}
