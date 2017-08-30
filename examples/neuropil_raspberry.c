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
#include "np_http.h"
#include "np_settings.h"

#include "gpio/bcm2835.h"

#include "example_helper.c"

static uint32_t _ping_received_count = 0;
static uint32_t _ping_send_count = 0;
static uint32_t _pong_received_count = 0;
static uint32_t _pong_send_count = 0;

#define LED_GPIO_GREEN 23
#define LED_GPIO_YELLOW 18

static np_bool is_gpio_enabled = FALSE;
static np_mutex_t gpio_lock = { 0 };
static double last_response_or_invokation = 0;

const double ping_pong_intervall = 0.0001;

np_bool receive_ping(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body)
{
	char* text = np_tree_find_str(body, NP_MSG_BODY_TEXT)->val.value.s;
	uint32_t seq = np_tree_find_str(properties, _NP_MSG_INST_SEQ)->val.value.ul;

	//fprintf(stdout, "\e[1ARECEIVED: %05d -> %s\n", seq, text);
	log_msg(LOG_INFO, "RECEIVED: %d -> %s", seq, text);
	_ping_received_count++;
	log_msg(LOG_INFO, "SENDING: %d -> %s", _pong_send_count++, "pong");

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

	np_send_text("pong", "pong", _pong_send_count,NULL);

	return TRUE;
}

np_bool receive_pong(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body)
{
	char* text = np_tree_find_str(body, NP_MSG_BODY_TEXT)->val.value.s;
	uint32_t seq = np_tree_find_str(properties, _NP_MSG_INST_SEQ)->val.value.ul;
	last_response_or_invokation = ev_time();

	//fprintf(stdout, "\e[1ARECEIVED: %05d -> %s\n", seq, text);
	log_msg(LOG_INFO, "RECEIVED: %d -> %s", seq, text);
	_pong_received_count++;
	log_msg(LOG_INFO, "SENDING: %d -> %s", _ping_send_count++, "ping");

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
	np_send_text("ping", "ping", _ping_send_count,NULL);

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
	char* logpath = ".";
	char* is_gpio_enabled_opt = "1234";

	int opt;
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

	char log_file[256];
	sprintf(log_file, "%s%s_%s.log", logpath, "/neuropil_raspberry", port);
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

		// get public / local network interface id		
		char * http_domain= calloc(1, sizeof(char) * 255);
		CHECK_MALLOC(http_domain);
		if (_np_get_local_ip(http_domain) == FALSE) {
			free(http_domain);
			http_domain = NULL;
		}
		
		if(FALSE == _np_http_init(http_domain, NULL))
		{
			fprintf(stderr,   "Node could not start HTTP interface\n");
			log_msg(LOG_WARN, "Node could not start HTTP interface");
			np_sysinfo_enable_slave();
		} else {
			np_sysinfo_enable_master();
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
	ping_props->ack_mode = ACK_NONE;
	ping_props->msg_ttl = 5.0;
	ping_props->retry = 1;
	ping_props->max_threshold = UINT8_MAX;
	np_msgproperty_register(ping_props);
	//register the listener function to receive data from the sender
	np_set_listener(receive_ping, "ping");

	np_msgproperty_t* pong_props = NULL;
	np_new_obj(np_msgproperty_t, pong_props);
	pong_props->msg_subject = strndup("pong", 255);
	pong_props->ack_mode = ACK_NONE;
	pong_props->msg_ttl = 5.0;
	pong_props->retry = 1;
	pong_props->max_threshold = UINT8_MAX;
	np_msgproperty_register(pong_props);
	//register the listener function to receive data from the sender
	np_set_listener(receive_pong, "pong");

	np_waitforjoin();

	fprintf(stdout, "Connection established.\n");

	fprintf(stdout, "Sending initial ping.\n");
	log_msg(LOG_INFO, "Sending initial ping");
	// send an initial ping
	np_send_text("ping", "ping", _ping_send_count++, NULL);

	//__np_example_helper_run_loop();
	uint32_t i = 0;
	double now = ev_time();
	last_response_or_invokation  = now;

	float last_ping_send_count_per_min = 0;
	float last_ping_received_count_per_min = 0;
	float last_pong_send_count_per_min = 0;
	float last_pong_received_count_per_min = 0;
	
	float current_ping_send_count_per_min = 0;
	float current_ping_received_count_per_min = 0;
	float current_pong_send_count_per_min = 0;
	float current_pong_received_count_per_min = 0;

	float reset_ping_send_count_per_min		= 0;
	float reset_ping_received_count_per_min = 0;
	float reset_pong_send_count_per_min		= 0;
	float reset_pong_received_count_per_min = 0;
	float reset_sec_since_start_per_min = 0;

	char* statistics = NULL;
	while (TRUE) {
		i +=1;
		ev_sleep(0.01);
		now = ev_time() ;
		if ((now - last_response_or_invokation ) > ping_props->msg_ttl) {
			
			//fprintf(stdout, "Invoking ping (last one was at %f (before %f sec))\n", last_response_or_invokation, now - last_response_or_invokation);
			log_msg(LOG_INFO, "Invoking ping (last one was at %f (before %f sec))", last_response_or_invokation, now - last_response_or_invokation);
			np_send_text("ping", "ping", _ping_send_count++, NULL);
			last_response_or_invokation = now;
		}
		__np_example_helper_loop(i, 0.01);
		double sec_since_start = i * 0.01;
		double ms_since_start = sec_since_start * 1000;
		
		
		if (i != 0 && ((int)ms_since_start) % (int)(output_intervall_sec * 1000) == 0)
		{
			current_ping_received_count_per_min = (_ping_received_count	- reset_ping_received_count_per_min	) / (sec_since_start - reset_sec_since_start_per_min);
			current_ping_send_count_per_min		= (_ping_send_count		- reset_ping_send_count_per_min		) / (sec_since_start - reset_sec_since_start_per_min);
			current_pong_received_count_per_min = (_pong_received_count	- reset_pong_received_count_per_min	) / (sec_since_start - reset_sec_since_start_per_min);
			current_pong_send_count_per_min		= (_pong_send_count		- reset_pong_send_count_per_min		) / (sec_since_start - reset_sec_since_start_per_min);
			
			statistics = _np_concatAndFree(statistics, "--- Statistics PingPong START ---\n");

			statistics = _np_concatAndFree(statistics,
				"received %5d (%5.1f per min [%+5.1f]) pings\n",
				_ping_received_count,	current_ping_received_count_per_min		, current_ping_received_count_per_min	- last_ping_received_count_per_min			);
			statistics = _np_concatAndFree(statistics,
				"send     %5d (%5.1f per min [%+5.1f]) pings\n",
				_ping_send_count,		current_ping_send_count_per_min			, current_ping_send_count_per_min		- last_ping_send_count_per_min			);
			statistics = _np_concatAndFree(statistics,
				"received %5d (%5.1f per min [%+5.1f]) pongs\n",
				_pong_received_count, current_pong_received_count_per_min		, current_pong_received_count_per_min	- last_pong_received_count_per_min		);
			statistics = _np_concatAndFree(statistics, 
				"send     %5d (%5.1f per min [%+5.1f]) pongs\n",
				_pong_send_count,		current_pong_send_count_per_min			, current_pong_send_count_per_min		- last_pong_send_count_per_min			);
			statistics = _np_concatAndFree(statistics, "--- Statistics PingPong END   ---\n");
			
			last_ping_received_count_per_min = current_ping_received_count_per_min;
			last_ping_send_count_per_min = current_ping_send_count_per_min ;
			last_pong_received_count_per_min = current_pong_received_count_per_min ;
			last_pong_send_count_per_min = current_pong_send_count_per_min;
		
			if ((int)sec_since_start % 60 == 0) {
				reset_ping_received_count_per_min = _ping_received_count;
				reset_ping_send_count_per_min = _ping_send_count;
				reset_pong_received_count_per_min = _pong_received_count;
				reset_pong_send_count_per_min = _pong_send_count;
				reset_sec_since_start_per_min = sec_since_start;
			}

			fprintf(stdout, "%s", statistics);
			free(statistics);
			statistics = NULL;
		}
		
	}

}
