//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "event/ev.h"

#include "np_log.h"
#include "np_types.h"
#include "np_list.h"
#include "np_util.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_keycache.h"
#include "np_tree.h"

#include "neuropil.h"

#define USAGE "neuropil_echo_server [ -p protocol] [-t worker_thread_count] [-l path_to_log_folder] [-u publish_domain] "
#define OPTSTR "p:t:l:u:"

NP_SLL_GENERATE_PROTOTYPES(int);
NP_SLL_GENERATE_IMPLEMENTATION(int);

#define DEBUG 0

extern char *optarg;
extern int optind;

np_bool receive_echo_message(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body);

np_bool receive_echo_message(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body) {
  	np_tree_t* header = msg->header;
	fprintf(stdout, "%f - RECEIVED", ev_time());

	char* reply_to = NULL; // All
	np_tree_elem_t* repl_to = np_tree_find_str(header, _NP_MSG_HEADER_FROM);
	if (NULL != repl_to) {
		reply_to = repl_to->val.value.s;

		char* text;
		np_tree_elem_t* txt = np_tree_find_str(body, NP_MSG_BODY_TEXT);
		if (NULL != txt) {
			text = txt->val.value.s;

		} else {
			text = "<NON TEXT MSG>";
		}
		fprintf(stdout, ": \"%s\" from: %s \n", text, reply_to);
		np_send_text("echo", text, 0, reply_to);
	}
	return TRUE;
}

int main(int argc, char **argv) {

	int opt;

	char* proto = "udp4";
	char* logpath = ".";
	char* publish_domain = "localhost";
	int no_threads = 8;
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG;
	char* port = "3333";

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF) {
		switch ((char) opt) {
		case 't':
			no_threads = atoi(optarg);
			if (no_threads <= 0)
				no_threads = 2;
			break;
		case 'p':
			proto = optarg;
			break;
		case 'u':
			publish_domain = optarg;
			break;
		case 'l':
			if (optarg != NULL) {
				logpath = optarg;
			} else {
				fprintf(stderr, "invalid option value\n");
				fprintf(stderr, "usage: %s\n", USAGE);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			fprintf(stderr, "invalid option %c\n", (char) opt);
			fprintf(stderr, "usage: %s\n", USAGE);
			exit(EXIT_FAILURE);
		}
	}
	// Get the current pid and shift it to be a viable port.
	// This way the application may be used for multiple instances on one system

	char log_file_host[256];
	sprintf(log_file_host, "%s%s_%s.log", logpath, "/neuropil_echo_server",
			port);
	fprintf(stdout, "logpath: %s\n", log_file_host);

	np_log_init(log_file_host, level);
	np_init(proto, port, TRUE, publish_domain);
	np_start_job_queue(no_threads);

	np_msgproperty_t* msg_props = NULL;
	np_new_obj(np_msgproperty_t, msg_props);
	msg_props->msg_subject = "echo";
	msg_props->ack_mode = ACK_NONE;
	msg_props->ttl = 20.0;
	np_msgproperty_register(msg_props);
	np_set_listener(receive_echo_message, "echo");

	while (TRUE) {
		ev_sleep(0.1);
	}
}
