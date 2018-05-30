//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/*
 * neuropil_demo_service.c
 *
 * This service is also available via *:udp4:demo.neuropil.io:31415
 *
 * It is composed out of the examples for
 *  - pingpong
 *  - echo server
 */

/**
 *.. NOTE::
 *   If you are not yet familiar with the neuropil initialization procedure please refer to the :ref:`tutorial`
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "event/ev.h"

#include "np_log.h"
#include "np_types.h"
#include "np_list.h"
#include "np_util.h"
#include "np_http.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_keycache.h"
#include "np_tree.h"
#include "np_route.h"
#include "np_key.h"
#include "np_sysinfo.h"


#include "neuropil.h"
#include "example_helper.c"

NP_SLL_GENERATE_PROTOTYPES(int);
NP_SLL_GENERATE_IMPLEMENTATION(int);

uint32_t _ping_count = 0;
uint32_t _pong_count = 0;

np_bool receive_echo_message(np_context* context, const np_message_t* const msg, np_tree_t* body);
np_bool receive_pong(np_context* context, const np_message_t* const msg, np_tree_t* body);
np_bool receive_ping(np_context* context, const np_message_t* const msg, np_tree_t* body);

int main(int argc, char **argv) {
	int no_threads = 8;
	char *j_key = NULL;
	char* proto = "udp4";
	char* port = NULL;
	char* publish_domain = NULL;
	int level = -2;
	char* logpath = ".";

	if (parse_program_args(
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
		"",
		""
	) == FALSE) {
		exit(EXIT_FAILURE);
	}

	struct np_settings *settings = np_new_settings(NULL);
	settings->n_threads = no_threads;

	sprintf(settings->log_file, "%s%s_%s.log", logpath, "/neuropil_controller", port);
	fprintf(stdout, "logpath: %s\n", settings->log_file);
	settings->log_level = level;

	np_context * context = np_new_context(settings);

	if (np_ok != np_listen(context, proto, publish_domain, atoi(port))) {
		printf("ERROR: Node could not listen");
		exit(EXIT_FAILURE);
	}
 
	np_msgproperty_t* echo_props = NULL;
	np_add_receive_listener(context, receive_echo_message, "echo");
	echo_props = np_msgproperty_get(context, INBOUND, "echo");
	echo_props->ack_mode = ACK_NONE;
	echo_props->msg_ttl = 20.0;

	np_msgproperty_t* ping_props = NULL;
	np_add_receive_listener(context, receive_ping, "ping");
	ping_props = np_msgproperty_get(context, INBOUND, "ping");
	ping_props->ack_mode = ACK_NONE;
	ping_props->msg_ttl = 20.0;
	np_msgproperty_register(ping_props);

	np_msgproperty_t* pong_props = NULL;
	np_add_receive_listener(context, receive_ping, "pong");
	pong_props = np_msgproperty_get(context, INBOUND, "pong");
	pong_props->ack_mode = ACK_NONE;
	pong_props->msg_ttl = 20.0;

	if (np_ok != np_run(context, 0)) {
		printf("ERROR: Node could not start");
		exit(EXIT_FAILURE);
	}

	double lastping = np_time_now();
	np_send_text(context, "ping", "ping", _ping_count++, NULL);

	while (TRUE) {
		__np_example_helper_loop(context);
		np_time_sleep(0.1);

		double now = np_time_now();
			// invoke a ping message every 10 seconds
			if ((now - lastping) > 10.0)
		{
			lastping = np_time_now();
			np_send_text(context, "ping", "ping", _ping_count++, NULL);
		}
	}
}

np_bool receive_echo_message(np_context* context, const np_message_t* const msg, np_tree_t* body) {
	np_tree_t* header = msg->header;

	np_id reply_to = { 0 };
	np_tree_elem_t* repl_to = np_tree_find_str(header, _NP_MSG_HEADER_FROM);
	if (NULL != repl_to) {
		np_conversion_dhkey2id(&reply_to, repl_to->val.value.dhkey);
		char* text;
		np_tree_elem_t* txt = np_tree_find_str(body, NP_MSG_BODY_TEXT);
		if (NULL != txt) {
			text = np_treeval_to_str(txt->val, NULL);

		} else {
			text = "<NON TEXT MSG>";
		}
		np_send_text(context, "echo", text, 0, &reply_to);
	}
	return TRUE;
}

np_bool receive_ping(np_context* context, const np_message_t* const msg, np_tree_t* body)
{
	char* text = np_treeval_to_str(np_tree_find_str(body, NP_MSG_BODY_TEXT)->val, NULL);
	uint32_t seq = np_tree_find_str(body, _NP_MSG_INST_SEQ)->val.value.ul;

	log_msg(LOG_INFO, "RECEIVED: %d -> %s", seq, text);
	log_msg(LOG_INFO, "SENDING: %d -> %s", _pong_count++, "pong");
	np_send_text(context, "pong", "pong", _pong_count,NULL);

	return TRUE;
}

np_bool receive_pong(np_context* context, const np_message_t* const msg, np_tree_t* body)
{
	char* text = np_treeval_to_str(np_tree_find_str(body, NP_MSG_BODY_TEXT)->val, NULL);
	uint32_t seq = np_tree_find_str(body, _NP_MSG_INST_SEQ)->val.value.ul;

	log_msg(LOG_INFO, "RECEIVED: %d -> %s", seq, text);
	log_msg(LOG_INFO, "SENDING: %d -> %s", _ping_count++, "ping");
	np_send_text(context, "ping", "ping", _ping_count,NULL);

	return TRUE;
}
