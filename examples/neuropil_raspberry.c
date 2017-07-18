//
// neuropil is copyright 2016 by pi-lar GmbH
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

#include "np_types.h"
#include "np_log.h"
#include "neuropil.h"
#include "np_tree.h"
#include "np_keycache.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_node.h"
#include "np_sysinfo.h"
#include "np_http.h"
#include "np_settings.h"

#include "gpio/bcm2835.h"
#include "event/ev.h"
#include "example_helper.c"

#define USAGE "neuropil_raspberry [ -j key:proto:host:port ] [ -p protocol] [-b port] [-t worker_thread_count] [-g 0/1 enables or disables GPIO support ] [-u publish_domain] [-d loglevel]"
#define OPTSTR "j:p:b:t:g:u:d:"

extern char *optarg;
extern int optind;

uint32_t _ping_count = 0;
uint32_t _pong_count = 0;

#define LED_GPIO_GREEN 23
#define LED_GPIO_YELLOW 18

np_bool is_gpio_enabled = FALSE;
np_mutex_t gpio_lock;
double last_ping = 0;

const double ping_pong_intervall = 0.5;

np_bool receive_ping(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body)
{
	char* text = np_tree_find_str(body, NP_MSG_BODY_TEXT)->val.value.s;
	uint32_t seq = np_tree_find_str(properties, _NP_MSG_INST_SEQ)->val.value.ul;

	fprintf(stdout, "RECEIVED: %05d -> %s\n", seq, text);
	log_msg(LOG_INFO, "RECEIVED: %d -> %s", seq, text);
	log_msg(LOG_INFO, "SENDING: %d -> %s", _pong_count++, "pong");
	last_ping = ev_time();

	if(is_gpio_enabled == TRUE)
	{
		_LOCK_ACCESS(&gpio_lock){
			bcm2835_gpio_write(LED_GPIO_YELLOW,LOW);
			bcm2835_gpio_write(LED_GPIO_GREEN,HIGH);
			ev_sleep(ping_pong_intervall);
			bcm2835_gpio_write(LED_GPIO_YELLOW,LOW);
			bcm2835_gpio_write(LED_GPIO_GREEN,LOW);
		}
	} else
	{
		ev_sleep(ping_pong_intervall);
	}

	np_send_text("pong", "pong", _pong_count,NULL);

	return TRUE;
}

np_bool receive_pong(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body)
{
	char* text = np_tree_find_str(body, NP_MSG_BODY_TEXT)->val.value.s;
	uint32_t seq = np_tree_find_str(properties, _NP_MSG_INST_SEQ)->val.value.ul;

	fprintf(stdout, "RECEIVED: %05d -> %s\n", seq, text);
	log_msg(LOG_INFO, "RECEIVED: %d -> %s", seq, text);
	log_msg(LOG_INFO, "SENDING: %d -> %s", _ping_count++, "ping");

	if(is_gpio_enabled == TRUE)
	{
		_LOCK_ACCESS(&gpio_lock){
			bcm2835_gpio_write(LED_GPIO_YELLOW,HIGH);
			bcm2835_gpio_write(LED_GPIO_GREEN,LOW);
			ev_sleep(ping_pong_intervall);
			bcm2835_gpio_write(LED_GPIO_YELLOW,LOW);
			bcm2835_gpio_write(LED_GPIO_GREEN,LOW);
		}
	} else
	{
		ev_sleep(ping_pong_intervall);
	}
	np_send_text("ping", "ping", _ping_count,NULL);

	return TRUE;
}

int main(int argc, char **argv)
{
	_np_threads_mutex_init(&gpio_lock);

	int no_threads = 8;
	char *j_key = NULL;
	char* proto = "udp4";
	char* port = NULL;
	char* publish_domain = NULL;
	int level = -2;

	int opt;
	while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
	{
		switch ((char) opt)
		{
		case 'j':
			j_key = optarg;
			break;
		case 't':
			no_threads = atoi(optarg);
			if (no_threads <= 0) no_threads = 2;
			break;
		case 'p':
			proto = optarg;
			break;
		case 'g':
			is_gpio_enabled = atoi(optarg) == 1;
			break;
		case 'u':
			publish_domain = optarg;
			break;
		case 'd':
			level = atoi(optarg);
			break;
		case 'b':
			port = optarg;
			break;
		default:
			fprintf(stderr, "invalid option %c\n", (char) opt);
			fprintf(stderr, "usage: %s\n", USAGE);
			exit(EXIT_FAILURE);
		}
	}
	if(level == -1){	   // production client
		level = LOG_ERROR;
	}else if(level == -2){ // production server
		level = LOG_ERROR | LOG_WARN | LOG_INFO;
	}else if(level <= -3){ // debug
		level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG
				  //| LOG_MUTEX | LOG_TRACE
				  //| LOG_ROUTING
				  //| LOG_HTTP
				  //| LOG_KEY
				  | LOG_NETWORK
				  | LOG_AAATOKEN
				  | LOG_MESSAGE
				//  | LOG_MEMORY
				   ;
	}

	if (port == NULL){
		int current_pid = getpid();

		port = calloc(1,sizeof(char)*7);

		if (current_pid > 65535) {
			sprintf(port, "%d", (current_pid >> 1));
		} else {
			sprintf(port, "%d", current_pid);
		}
	}


	char log_file[256];
	sprintf(log_file, "%s_%s.log", "./neuropil_raspberry", port);
	np_log_init(log_file, level);

	np_state_t* state = np_init(proto, port, publish_domain);

	port =  state->my_node_key->node->port;

	log_debug_msg(LOG_DEBUG, "starting job queue");
	np_start_job_queue(no_threads);


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
				ev_sleep(0.1);
				bcm2835_gpio_write(LED_GPIO_GREEN, HIGH);
				bcm2835_gpio_write(LED_GPIO_YELLOW,LOW);
				ev_sleep(0.1);
			}
			bcm2835_gpio_write(LED_GPIO_GREEN, LOW);
			bcm2835_gpio_write(LED_GPIO_YELLOW,LOW);

			fprintf(stdout, "GPIO initiated\n");
		}

		np_sysinfo_enable_slave();
	} else {
		if(FALSE == _np_http_init())
		{
			fprintf(stderr,   "Node could not start HTTP interface");
			log_msg(LOG_WARN, "Node could not start HTTP interface");
			np_sysinfo_enable_master();
		} else {
			np_sysinfo_enable_slave();
		}
	}


	if (NULL != j_key)
	{

		do {
				fprintf(stdout, "try to join bootstrap node\n");
				np_send_join(j_key);

			int timeout = 100;
			while (timeout > 0 && FALSE == state->my_node_key->node->joined_network) {
				// wait for join acceptance
				ev_sleep(0.1);
				timeout--;
			}

			if(FALSE == state->my_node_key->node->joined_network ) {
				fprintf(stderr, "%s could not join network!\n",port);
			}
		} while (FALSE == state->my_node_key->node->joined_network) ;

	} else {
		fprintf(stdout, "Node waits for connections.\n");
		fprintf(stdout, "Please start another node with the following arguments:\n");
		fprintf(stdout, "\n\t-b %d -j %s\n", atoi(port) + 1, np_get_connection_string());
	}


	np_msgproperty_t* ping_props = NULL;
	np_new_obj(np_msgproperty_t, ping_props);
	ping_props->msg_subject = strndup("ping", 255);
	ping_props->ack_mode = ACK_DESTINATION;
	ping_props->msg_ttl = 20.0;
	ping_props->max_threshold = UINT16_MAX;
	np_msgproperty_register(ping_props);
	//register the listener function to receive data from the sender
	np_set_listener(receive_ping, "ping");

	np_msgproperty_t* pong_props = NULL;
	np_new_obj(np_msgproperty_t, pong_props);
	pong_props->msg_subject = strndup("pong", 255);
	pong_props->ack_mode = ACK_DESTINATION;
	pong_props->msg_ttl = 20.0;
	pong_props->max_threshold = UINT16_MAX;
	np_msgproperty_register(pong_props);
	//register the listener function to receive data from the sender
	np_set_listener(receive_pong, "pong");

	np_waitforjoin();

	fprintf(stdout, "Connection established.\n");

	fprintf(stdout, "Sending initial ping.\n");
	log_msg(LOG_INFO, "Sending initial ping");
	// send an initial ping
	np_send_text("ping", "ping", _ping_count++, NULL);

	//__np_example_helper_run_loop();
	uint32_t i = 0;
	double now = ev_time();
	last_ping  = now;

	while (TRUE) {
	    i +=1;
	    ev_sleep(0.01);
	    now = ev_time() ;
	    if ((now - last_ping ) > ping_props->msg_ttl) {
	    	last_ping  = now;
	    	fprintf(stdout, "Invoking ping.\n");
	    	log_msg(LOG_INFO, "Invoking ping");
	    	np_send_text("ping", "ping", _ping_count++, NULL);
	    }
	}

}
