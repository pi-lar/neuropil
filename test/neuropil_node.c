#include <errno.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "include.h"

#include "neuropil.h"
#include "log.h"
#include "dtime.h"
#include "job_queue.h"
#include "jrb.h"
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
	// np_node_t *join = NULL;
	// char tmp[256];
	int i;
	// np_message_t *hello;
	// char dest[16];
	// char msg[200];
	// char m[200];
	// np_node_t ch;
	// double wtime;
	int type;
	// int x;

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
	sprintf(log_file, "%s_%d.log", "./neuropil_node", port);
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_ROUTING | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	log_init(&log_file, level);

	state = np_init(port);

	// chimera_forward(state, forward);
	// chimera_deliver(state, deliver);
	// chimera_register(state, 20, 1);
	// chimera_register(state, 21, 1);
	// chimera_register(state, 22, 1);
	// chimera_register(state, 23, 1);

	// np_msgproperty_t* prop = (np_msgproperty_t*) malloc(sizeof(np_msgproperty_t));
	// {"_NEUROPIL.BOOTSTRAP.REQUEST.TO.JOIN.NETWORK", "in", 1, 4, 0, "%s %s", init };
//	prop->msg_subject = "SOME.SILLY.MESSAGE";
//	prop->msg_mode = 1;
//	prop->priority = 4;
//	prop->ack_mode = 1;
//	prop->retry = 0;
//	prop->msg_format = "%s %s";
//	prop->msg_handler = init;

	// log_msg(LOG_DEBUG, "registering additional user msg handlers %s", prop->msg_subject);
	// np_message_register_handler(state->messages, prop);

	// load_destinations();
	// driver = host_get(state, "marrow", 11110);

	// if (join != NULL ) {
	// 	chimera_join(state, join);
	// 	sprintf(tmp, "%d %s joining with %s:%d", port, key.keystr, hn, joinport);
	// } else {
	// 	sprintf(tmp, "%d %s starting system", port, key.keystr, hn, joinport);
	// }
	// hello = message_create(driver->key, PYMERA_CONTACT_BOOTSTRAP, strlen(tmp) + 1, tmp);
	// message_send(state, driver, hello, TRUE);
	// free(hello);

	// dsleep(50);
	log_msg(LOG_DEBUG, "starting job queue");
	np_start_job_queue(state, 8);
	np_waitforjoin(state);

	// unsigned long k = 1;
	while (1) {

		dsleep(0.1);
		// char* testdata;

		// np_send(state, "this.is.a.test", "testdata", k);
		// np_receive(state, "this.is.a.test", &testdata, k, 1);
		// log_msg(LOG_DEBUG, "send message %lu: %s", k, testdata);

		// k++;
	}
	// pthread_exit(NULL);
}
