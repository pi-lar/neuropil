//
// neuropil is copyright 2016-2020 by pi-lar GmbH
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
#include "np_legacy.h"
#include "np_tree.h"
#include "np_message.h"
#include "np_threads.h"
#include "np_node.h"
#include "np_statistics.h"
#include "np_settings.h"


#include "../framework/sysinfo/np_sysinfo.h"
#include "../framework/http/np_http.h"

#include "gpio/bcm2835.h"

#include "example_helper.c"

#define LED_GPIO_RED 24
#define LED_GPIO_YELLOW 23
#define LED_GPIO_BUTTON 18
#define BUTTON_GPIO_BLUE_IN 27
#define BUTTON_GPIO_RED_IN 17
#define BUTTON_GPIO_GREEN_IN 22

static bool is_gpio_enabled = false;
static pthread_mutex_t gpio_lock = PTHREAD_MUTEX_INITIALIZER;
static double last_response_or_invokation = 0;

const double ping_pong_intervall = 0.01;

void handle_ping_pong_receive(np_context* context, char * response, int first_low, int first_high, struct np_message* msg)
{
	char* text = (char*)msg->data;
	
	char tmp_from[65];
	np_id_str(tmp_from, msg->from);
	np_example_print(context, stdout, "Received %d/%s from %s. Sending %s\n",msg->data_length, text, tmp_from, response);

	if (is_gpio_enabled == true)
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

	np_send(context, response, (uint8_t*)response, strlen(response));
}

bool receive_ping(np_context* context, struct np_message* message)
{
	handle_ping_pong_receive(context, "pong", LED_GPIO_YELLOW, LED_GPIO_RED, message);
	return true;
}

bool receive_pong(np_context* context, struct np_message* message)
{
	double now = np_time_now();
	last_response_or_invokation = now;
	handle_ping_pong_receive(context, "ping", LED_GPIO_RED, LED_GPIO_YELLOW, message);
	return true;
}


bool is_blue_pressed = false;
bool receive_blue_button_pressed(np_context* context, struct np_message* message) {
	is_blue_pressed = true;
	return true;
}

bool receive_blue_button_reset(np_context* context, struct np_message* message) {
	is_blue_pressed = false;
	return true;
}

void invoke_btn_blue(np_context* context, uint8_t value) {	
	is_blue_pressed = true; 
	if(value == 0) np_send(context, "blue_button_pressed", (uint8_t*)"test", 5);
	np_example_print(context, stdout, "Blue  button pressed %d ", value);	
}

void invoke_btn_green(np_context* context, uint8_t value) {
	if (is_blue_pressed && value == 0) np_send(context, "blue_button_reset", (uint8_t*)"test", 5);
	if (is_blue_pressed && value == 0) np_send(context, "green_button_pressed", (uint8_t*)"test", 5);
	np_example_print(context, stdout, "Green button pressed %d ", value);
	is_blue_pressed = false;
}

void invoke_btn_red(np_context* context, uint8_t value) {	
	if (is_blue_pressed && value == 0) np_send(context, "blue_button_reset", (uint8_t*)"test", 5);
	np_example_print(context, stdout, "Red   button pressed %d ", value);	
	is_blue_pressed = false;
}

uint8_t value_data  = 1;
uint8_t value_green = 1;
uint8_t value_red   = 1;

bool led_switch = false;
double led_switch_at = 0;
void checkGPIO(np_context * context) {
	if (is_gpio_enabled) {

		uint8_t nvalue_data = bcm2835_gpio_lev(BUTTON_GPIO_BLUE_IN);
		if (nvalue_data != value_data) { value_data = nvalue_data; invoke_btn_blue(context, value_data); }
		uint8_t nvalue_green = bcm2835_gpio_lev(BUTTON_GPIO_GREEN_IN);
		if (nvalue_green != value_green) { value_green = nvalue_green; invoke_btn_green(context, value_green); }
		uint8_t nvalue_red = bcm2835_gpio_lev(BUTTON_GPIO_RED_IN);
		if (nvalue_red != value_red) { value_red = nvalue_red; invoke_btn_red(context, nvalue_red); }

		if (is_blue_pressed) {			
			double now = np_time_now();
			if (led_switch_at + 1. < now) {
				led_switch = !led_switch;
				led_switch_at = now;
				if (led_switch) {
					bcm2835_gpio_write(LED_GPIO_BUTTON, HIGH);
				}
				else {					
					bcm2835_gpio_write(LED_GPIO_BUTTON, LOW); 
				}
			}
		}
		else {
			led_switch = false;
			bcm2835_gpio_write(LED_GPIO_BUTTON, LOW);
		}
	}
}

void initGPIO(np_context * context) {
	if (1 != bcm2835_init()) {
		np_example_print(context, stdout, "GPIO NOT initiated\n");
		is_gpio_enabled = false;
	}
	else {
		//BUTTONs
		bcm2835_gpio_set_pud(BUTTON_GPIO_BLUE_IN, BCM2835_GPIO_PUD_UP);
		bcm2835_gpio_set_pud(BUTTON_GPIO_GREEN_IN, BCM2835_GPIO_PUD_UP);
		bcm2835_gpio_set_pud(BUTTON_GPIO_RED_IN, BCM2835_GPIO_PUD_UP);
		bcm2835_gpio_fsel(BUTTON_GPIO_BLUE_IN, BCM2835_GPIO_FSEL_INPT);
		bcm2835_gpio_fsel(BUTTON_GPIO_GREEN_IN, BCM2835_GPIO_FSEL_INPT);
		bcm2835_gpio_fsel(BUTTON_GPIO_RED_IN, BCM2835_GPIO_FSEL_INPT);

		// LEDs
		bcm2835_gpio_set_pud(LED_GPIO_RED, BCM2835_GPIO_PUD_OFF);
		bcm2835_gpio_set_pud(LED_GPIO_YELLOW, BCM2835_GPIO_PUD_OFF);
		bcm2835_gpio_set_pud(LED_GPIO_BUTTON, BCM2835_GPIO_PUD_OFF);
		bcm2835_gpio_fsel(LED_GPIO_RED, BCM2835_GPIO_FSEL_OUTP);
		bcm2835_gpio_fsel(LED_GPIO_YELLOW, BCM2835_GPIO_FSEL_OUTP);
		bcm2835_gpio_fsel(LED_GPIO_BUTTON, BCM2835_GPIO_FSEL_OUTP);
		// init blinking
		int i = 20;
		while (--i > 0) {
			bcm2835_gpio_write(LED_GPIO_BUTTON, HIGH);
			bcm2835_gpio_write(LED_GPIO_RED, HIGH);
			bcm2835_gpio_write(LED_GPIO_YELLOW, HIGH);
			np_time_sleep(0.1);
			bcm2835_gpio_write(LED_GPIO_BUTTON, LOW);
			bcm2835_gpio_write(LED_GPIO_RED, LOW);
			bcm2835_gpio_write(LED_GPIO_YELLOW, LOW);
			np_time_sleep(0.1);
		}
		bcm2835_gpio_write(LED_GPIO_BUTTON, LOW);
		bcm2835_gpio_write(LED_GPIO_RED, LOW);
		bcm2835_gpio_write(LED_GPIO_YELLOW, LOW);

		np_example_print(context, stdout, "GPIO initiated\n");
	}
	np_sysinfo_enable_client(context);
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
	char* opt_instance_no = "1";

	example_user_context* user_context;
	if ((user_context = parse_program_args(
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
		"[-g 0 / 1 enables or disables GPIO support] [-k instance no]",
		"g:k:",
		&is_gpio_enabled_opt,
		&opt_instance_no
	)) == NULL) {
		exit(EXIT_FAILURE);
	}	

	is_gpio_enabled = strcmp(is_gpio_enabled_opt, "0") != 0;

	struct np_settings *settings = np_default_settings(NULL);
	settings->n_threads = no_threads;

	snprintf(settings->log_file, 255, "%s/%s_%s.log", logpath, "neuropil_raspberry", port);
	settings->log_level = level;

	np_context * context = np_new_context(settings);
	np_set_userdata(context, user_context);

	if (np_ok != np_listen(context, proto, publish_domain, atoi(port))) {
		np_example_print(context, stderr, "ERROR: Node could not listen to %s:%s:%s",proto, publish_domain, port);
		exit(EXIT_FAILURE);
	}

	log_debug_msg(LOG_DEBUG, "starting job queue");
	if (np_ok != np_run(context, 0)) {
		np_example_print(context, stderr, "ERROR: Node could not start");
		exit(EXIT_FAILURE);
	}
	if(is_gpio_enabled == true) {
		initGPIO(context);
	} else {
		// get public / local network interface id		
		char * http_domain= calloc(1, sizeof(char) * 255);
		CHECK_MALLOC(http_domain);
		if (np_get_local_ip(context, http_domain, 255) == false) {
			free(http_domain);
			http_domain = NULL;
		}
		
		if(false == _np_http_init(context, http_domain, NULL))
		{
			np_example_print(context, stderr,   "Node could not start HTTP interface\n");
			log_msg(LOG_WARN, "Node could not start HTTP interface");
			np_sysinfo_enable_client(context);
		} else {
			np_sysinfo_enable_server(context);
		}
	}


	if (NULL != j_key)
	{
		np_example_print(context, stdout, "try to join bootstrap node\n");
		np_join(context, j_key);
	}
	
	//register the listener function to receive data from the sender
	np_add_receive_cb(context, "ping", receive_ping);
	struct np_mx_properties  ping_props = np_get_mx_properties(context, "ping");
	ping_props.ackmode = NP_MX_ACK_NONE;
	ping_props.message_ttl = 5.0;
	np_set_mx_properties(context, "ping", ping_props);

 	//register the listener function to receive data from the sender
	np_add_receive_cb(context, "pong", receive_pong);
	struct np_mx_properties  pong_props = np_get_mx_properties(context, "pong");
	pong_props.ackmode = NP_MX_ACK_NONE;
	pong_props.message_ttl = 5.0;
	np_set_mx_properties(context, "pong", pong_props);


	if (strcmp(opt_instance_no, "1") == 0) {
		np_add_receive_cb(context, "blue_button_pressed", receive_blue_button_pressed);
		np_send(context, "blue_button_reset", (uint8_t*)"test", 5);
		np_send(context, "green_button_pressed", (uint8_t*)"test", 5);
		np_send(context, "red_button_pressed", (uint8_t*)"test", 5);
	}
	else if (strcmp(opt_instance_no, "2") == 0) {
		np_add_receive_cb(context, "blue_button_reset", receive_blue_button_reset);
		np_send(context, "blue_button_pressed", (uint8_t*)"test", 5);
	}
	np_statistics_add_watch(context, "blue_button_pressed");
	np_statistics_add_watch(context, "green_button_pressed");
	np_statistics_add_watch(context, "red_button_pressed");
	np_statistics_add_watch(context, "blue_button_reset");
	np_statistics_add_watch(context, "ping");
	np_statistics_add_watch(context, "pong");
	

	fprintf(stdout, "Sending initial ping.\n");
	log_msg(LOG_INFO, "Sending initial ping");
	// send an initial ping
	np_send(context, "ping", (uint8_t*)"ping", 5);

	//__np_example_helper_run_loop();
	uint32_t i = 0;
	uint32_t now = np_time_now();
	
	last_response_or_invokation  = now;

	while (true) {
		checkGPIO(context);
		now = np_time_now()*10;

		if ((now % 2)==0) {
			__np_example_helper_loop(context);
			if ((now - last_response_or_invokation) > ping_props.message_ttl) {

				np_example_print(context, stdout, "Invoking ping (last one was before %f sec)\n", now - last_response_or_invokation);
				log_msg(LOG_INFO, "Invoking ping (last one was before %f sec)", now - last_response_or_invokation);
				np_send(context, "ping", (uint8_t*)"ping", 5);
				last_response_or_invokation = now;
			}
		}
	}

}
