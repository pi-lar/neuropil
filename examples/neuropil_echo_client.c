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

#define USAGE "neuropil_echo_client [-j key:proto:host:port] [ -p protocol] [-t worker_thread_count] [-l path_to_log_folder] [-u publish_domain] [-m message_to_send]"
#define OPTSTR "j:p:t:l:u:m:"

NP_SLL_GENERATE_PROTOTYPES(int);
NP_SLL_GENERATE_IMPLEMENTATION(int);

#define DEBUG 0

extern char *optarg;
extern int optind;

np_bool receive_message(np_message_t* msg, np_tree_t* properties, np_tree_t* body) {
 	 np_tree_t* header = msg->header;

	fprintf(stdout, "properties: %s\n", np_json_to_char( np_tree_to_json(properties), FALSE) );
	fprintf(stdout, "body: %s\n", np_json_to_char( np_tree_to_json(body), FALSE) );

	char* reply_to = NULL; // All
	np_tree_elem_t* repl_to = np_tree_find_str(header, _NP_MSG_HEADER_FROM);
	if (NULL != repl_to) {
		reply_to = repl_to->val.value.s;
	}

	char* text;
	np_tree_elem_t* txt = np_tree_find_str(body, NP_MSG_BODY_TEXT);
	if (NULL != txt) {
		text = txt->val.value.s;

	}else{
		text = "<NON TEXT MSG>";
	}
	fprintf(stdout, "RECEIVED: \"%s\" from: %s \n", text, reply_to);

	return TRUE;
}

int main(int argc, char **argv) {
	int opt;

	char* proto = "udp4";
	char* logpath = ".";
 	char j_key[256];
	char* publish_domain = "localhost";
	char* message_to_send = "Hello World!";
	int no_threads = 8;
	int retry_connection = 3;
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_AAATOKEN | LOG_DEBUG;
	np_bool j_key_provided = FALSE;

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF) {
		switch ((char) opt) {
		case 'j':
			j_key_provided = TRUE;
			sprintf(j_key, "%s", optarg);
			break;
		case 't':
			no_threads = atoi(optarg);
			if (no_threads <= 0)
				no_threads = 2;
			break;
		case 'm':
			message_to_send = optarg;
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

	char port[7];
	// Get the current pid and shift it to be a viable port.
	// This way the application may be used for multiple instances on one system
	int current_pid = getpid();
	fprintf(stdout, "%d\n", current_pid);

	if (current_pid > 65535) {
		sprintf(port, "%d", (current_pid >> 1));
	} else {
		sprintf(port, "%d", current_pid);
	}

	char log_file_host[256];
	sprintf(log_file_host, "%s%s_%s.log", logpath, "/neuropil_echo_client",
			port);
	fprintf(stdout, "logpath: %s\n", log_file_host);

	np_log_init(log_file_host, level);
	np_state_t* status = np_init(proto, port, FALSE,
			strcmp(publish_domain, "localhost") == 0 ? publish_domain : NULL);
	np_start_job_queue(no_threads);

	np_key_t* bootstrap_node =NULL;
	while (TRUE) {
		fprintf(stdout, "try to join bootstrap node\n");
		if (TRUE == j_key_provided) {
			np_send_join(j_key);
		} else {
 			//sprintf(j_wildcard_key, "%s:echo.neuropil.org:3333", proto);
			sprintf(j_key, "%s:localhost:3333", proto);
			np_send_wildcard_join(j_key);
		}

		int timeout = 100;
		while (timeout > 0
				&& FALSE == status->my_node_key->node->joined_network) {
			// wait for join acceptance
			ev_sleep(0.1);
			timeout--;
		}

		if (TRUE == status->my_node_key->node->joined_network) {
			bootstrap_node = _np_keycache_find_by_details(j_key,FALSE,HANDSHAKE_COMPLETE,TRUE,TRUE,TRUE,FALSE);
			fprintf(stdout, "%s joined network!\n", port);
			break;
		} else {
			fprintf(stderr, "%s could not join network!\n", port);
			if(retry_connection-- < 0){
				fprintf(stderr, "abort\n");
				break;
			}
		}
	}

	np_msgproperty_t* msg_props = NULL;
	np_new_obj(np_msgproperty_t, msg_props);
	msg_props->msg_subject = "echo";
	msg_props->ack_mode = ACK_NONE;
	msg_props->ttl = 20.0;
	np_msgproperty_register(msg_props);
	np_set_listener(receive_message, "echo");

	int i = 0;
	while (TRUE == status->my_node_key->node->joined_network) {
		if (i++ % 100 == 0) {
			fprintf(stdout, "SENDING: %s to %s\n", message_to_send,_np_key_as_str(bootstrap_node));
			log_msg(LOG_INFO, "SENDING: %s to %s", message_to_send,_np_key_as_str(bootstrap_node));

			np_send_text("echo", message_to_send, 0, _np_key_as_str(bootstrap_node));
		}
		ev_sleep(0.1);
	}
}
