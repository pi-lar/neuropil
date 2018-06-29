//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/**
.. highlight:: c
*/

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "event/ev.h"

#include "np_types.h"
#include "np_log.h"
#include "neuropil.h"
#include "np_tree.h"
#include "np_keycache.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_threads.h"
#include "np_node.h"
#include "np_sysinfo.h"
#include "np_statistics.h"
#include "np_settings.h"

#include "gpio/bcm2835.h"

#include "example_helper.c"

#define LED_GPIO_GREEN 23
#define LED_GPIO_YELLOW 18

static np_bool is_gpio_enabled = FALSE;
static pthread_mutex_t gpio_lock = PTHREAD_MUTEX_INITIALIZER;
static double last_response_or_invokation = 0;

const double ping_pong_intervall = 0.01;

void handle_ping_pong_receive(np_context* context, char * response, int first_low, int first_high, const np_message_t * const msg, np_tree_t * body)
{
	char* text = np_tree_find_str(body, NP_MSG_BODY_TEXT)->val.value.s;
	uint32_t seq = np_tree_find_str(body, _NP_MSG_INST_SEQ)->val.value.ul;
	
	log_msg(LOG_INFO, "RECEIVED: %d -> %s", seq, text);

	if (is_gpio_enabled == TRUE)
	{
		pthread_mutex_lock(&gpio_lock);
			bcm2835_gpio_write(first_low, LOW);
			bcm2835_gpio_write(first_high, HIGH);
			np_time_sleep(ping_pong_intervall);
			bcm2835_gpio_write(first_low, LOW);
			bcm2835_gpio_write(first_high, LOW);
		pthread_mutex_unlock(&gpio_lock);
	}
	else
	{
		np_time_sleep(ping_pong_intervall);
	}

	np_send_text(context, response, response, 0, NULL);
}

np_bool receive_ping(np_context* context, const np_message_t* const msg,  np_tree_t* body)
{
	handle_ping_pong_receive(context, "pong", LED_GPIO_YELLOW, LED_GPIO_GREEN, msg, body);
	return TRUE;
}

np_bool receive_pong(np_context* context, const np_message_t* const msg, np_tree_t* body)
{
	handle_ping_pong_receive(context, "ping", LED_GPIO_GREEN, LED_GPIO_YELLOW, msg, body);
	return TRUE;
}

int main(int argc, char **argv)
{
	int no_threads = 8;
	char *j_key = NULL;
	char* proto = "udp4";
	char* port = "3333";
	char* publish_domain = NULL;
	int level = -2;
	char* logpath = ".";
	char* is_gpio_enabled_opt = "1234";

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
		"[-g 0 / 1 enables or disables GPIO support]",
		"g:",
		&is_gpio_enabled_opt
	) == FALSE) {
		exit(EXIT_FAILURE);
	}	

	is_gpio_enabled = strcmp(is_gpio_enabled_opt, "0") != 0;

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

	log_debug_msg(LOG_DEBUG, "starting job queue");
	if (np_ok != np_run(context, 0)) {
		printf("ERROR: Node could not start");
		exit(EXIT_FAILURE);
	}
	if(is_gpio_enabled == TRUE) {

		if( 1 != bcm2835_init()) {
			fprintf(stdout, "GPIO NOT initiated\n");
			is_gpio_enabled = FALSE;

		} else {
			bcm2835_gpio_set_pud(LED_GPIO_GREEN,  BCM2835_GPIO_PUD_OFF);
			bcm2835_gpio_set_pud(LED_GPIO_YELLOW, BCM2835_GPIO_PUD_OFF);
			bcm2835_gpio_fsel(LED_GPIO_GREEN,  BCM2835_GPIO_FSEL_OUTP);
			bcm2835_gpio_fsel(LED_GPIO_YELLOW, BCM2835_GPIO_FSEL_OUTP);

			int i = 5;
			while(--i>0){
				bcm2835_gpio_write(LED_GPIO_GREEN, LOW);
				bcm2835_gpio_write(LED_GPIO_YELLOW,HIGH);
				np_time_sleep(0.1);
				bcm2835_gpio_write(LED_GPIO_GREEN, HIGH);
				bcm2835_gpio_write(LED_GPIO_YELLOW,LOW);
				np_time_sleep(0.1);
			}
			bcm2835_gpio_write(LED_GPIO_GREEN, LOW);
			bcm2835_gpio_write(LED_GPIO_YELLOW,LOW);

			fprintf(stdout, "GPIO initiated\n");
		}

		np_sysinfo_enable_client(context);
	} else {

		// get public / local network interface id		
		char * http_domain= calloc(1, sizeof(char) * 255);
		CHECK_MALLOC(http_domain);
		if (np_get_local_ip(context, http_domain, 255) == FALSE) {
			free(http_domain);
			http_domain = NULL;
		}
		
		if(FALSE == np_http_init(context, http_domain))
		{
			fprintf(stderr,   "Node could not start HTTP interface\n");
			log_msg(LOG_WARN, "Node could not start HTTP interface");
			np_sysinfo_enable_client(context);
		} else {
			np_sysinfo_enable_server(context);
		}
	}


	if (NULL != j_key)
	{

		do {
			fprintf(stdout, "try to join bootstrap node\n");
			np_join(context, j_key);

			int timeout = 100;
			while (timeout > 0 && FALSE == ((np_state_t*)context)->my_node_key->node->joined_network) {
				// wait for join acceptance
				np_time_sleep(0.1);
				timeout--;
			}

			if(FALSE == ((np_state_t*)context)->my_node_key->node->joined_network ) {
				fprintf(stderr, "%s could not join network!\n",port);
			}
		} while (FALSE == ((np_state_t*)context)->my_node_key->node->joined_network) ;

	} else {
		fprintf(stdout, "Node waits for connections.\n");
		fprintf(stdout, "Please start another node with the following arguments:\n");
		fprintf(stdout, "\n\t-b %d -j %s\n", atoi(port) + 1, np_get_connection_string(context));
	}

	np_msgproperty_t* ping_props = NULL;
	//register the listener function to receive data from the sender
	np_add_receive_listener(context, receive_ping, "ping");
	ping_props = np_msgproperty_get(context, INBOUND, "ping");
	ping_props->ack_mode = ACK_NONE;
	ping_props->msg_ttl = 5.0;
	ping_props->retry = 1;
	ping_props->max_threshold = 150;
	ping_props->token_max_ttl = 60;
	ping_props->token_min_ttl = 30;

	np_msgproperty_t* pong_props = NULL;
	//register the listener function to receive data from the sender
	np_add_receive_listener(context, receive_pong, "pong");
	pong_props = np_msgproperty_get(context, INBOUND, "pong");
	pong_props->msg_subject = strndup("pong", 255);
	pong_props->ack_mode = ACK_NONE;
	pong_props->msg_ttl = 5.0;
	pong_props->retry = 1;
	pong_props->max_threshold = 150;
	pong_props->token_max_ttl = 60;
	pong_props->token_min_ttl = 30;
	
	
	np_statistics_add_watch(context, "ping");
	np_statistics_add_watch(context, "pong");
	np_statistics_add_watch(context, _NP_SYSINFO_REQUEST);
	np_statistics_add_watch(context, _NP_SYSINFO_REPLY);
	
	np_waitforjoin(context);

	fprintf(stdout, "Connection established.\n");

	fprintf(stdout, "Sending initial ping.\n");
	log_msg(LOG_INFO, "Sending initial ping");
	// send an initial ping
	np_send_text(context, "ping", "ping", 0, NULL);

	//__np_example_helper_run_loop();
	uint32_t i = 0;
	double now = np_time_now();
	last_response_or_invokation  = now;

	while (TRUE) {
		i +=1;
		np_time_sleep(0.01);
		now = np_time_now() ;
		if ((now - last_response_or_invokation ) > ping_props->msg_ttl) {
			
			log_msg(LOG_INFO, "Invoking ping (last one was at %f (before %f sec))", last_response_or_invokation, now - last_response_or_invokation);
			np_send_text(context, "ping", "ping", 0, NULL);
			last_response_or_invokation = now;
		}
	}

}
