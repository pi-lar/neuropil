//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <inttypes.h>

#include "neuropil.h"
#include "np_types.h"
#include "np_memory.h"
#include "np_threads.h"
#include "np_log.h"
#include "np_messagepart.h"
#include "np_statistics.h"

const float output_intervall_sec = 0.5;

extern char *optarg;
extern int optind;

uint8_t enable_statistics = 1;
double started_at = 0;
double last_loop_run_at = 0;

enum np_statistic_types_e  {
	np_stat_all				= 0 ,
	np_stat_general			= 1,
	np_stat_locks			= 2,
	np_stat_msgpartcache	= 4,
	np_stat_memory			= 8,
} typedef np_statistic_types_e;
 
np_statistic_types_e statistic_types = 0;



void reltime_to_str(char*buffer,double time){
	double time_s = time;
	double time_d = (int)time / 216000;
	time_s -= time_d * 216000;
	double time_h = (int)time / 3600;
	time_s -= time_h * 3600;
	double time_m = (int)time / 60;
	time_s -= time_m * 60;
	snprintf(buffer, 49, "%2.0fd %2.0fh %2.0fmin %2.0fsec", time_d, time_h, time_m, time_s);
}


np_bool parse_program_args(
	char* program,
	int argc, 
	char **argv,
	int* no_threads ,
	char** j_key ,
	char** proto ,
	char** port ,
	char** publish_domain ,
	int*  level ,
	char** logpath,
	char* additional_fields_desc,
	char* additional_fields_optstr,
	...
) {
	np_bool ret = TRUE;
	char* usage;
	asprintf(&usage,
		"./%s [ -j key:proto:host:port ] [ -p protocol] [-b port] [-t (> 0) worker_thread_count ] [-u publish_domain] [-d loglevel] [-s statistics 0=Off 1=Console 2=Log 3=1&2] [-c statistic types 0=All 1=general 2=locks ] %s",
		program, additional_fields_desc == NULL ?"": additional_fields_desc
	);
	char* optstr; 
	asprintf(&optstr, "j:p:b:t:u:d:s:c:%s", additional_fields_optstr);

	char* additional_fields[32] = { 0 }; // max additional fields
	va_list args;
	va_start(args, additional_fields_optstr);
	char* additional_field_char;

	int additional_fields_count = 0;

	if(additional_fields_optstr != NULL){
		additional_fields_count = strlen(additional_fields_optstr) / 2;
	}
	
	int additional_field_idx = 0 ;
	int opt;
	while ((opt = getopt(argc, argv, optstr)) != EOF)
	{
		switch ((char)opt)
		{
		case 'j':
			*j_key = strdup(optarg);
			break;
		case 't':
			(*no_threads) = atoi(optarg);			
			if ((*no_threads) <= 0) {
				fprintf(stderr, "invalid option %c\n", (char)opt);
				ret = FALSE;
			}
			break;
		case 'p':
			*proto = strdup(optarg);
			break;		
		case 'u':
			*publish_domain = strdup(optarg);
			break;
		case 'd':
			(*level) = atoi(optarg);
			break;		
		case 's':
			enable_statistics = atoi(optarg);
			break;
		case 'c':
			statistic_types = atoi(optarg);
			break;
		case 'b':
			*port = strdup(optarg);
			break;
		case 'l':
			if (optarg != NULL) {
				*logpath = strdup(optarg);
			}
			else {
				fprintf(stderr, "invalid option %c\n", (char)opt);
				ret = FALSE;
			}
			break;
		default:
			// check for custom parameter
			additional_field_char = strchr(additional_fields_optstr, (char)opt);
			if (additional_field_char != NULL) {
				additional_field_idx = (additional_field_char - additional_fields_optstr) /2; // as every ident char is followed by an : symbol			
				additional_fields[additional_field_idx] = strdup(optarg);
			}
			else {		
				fprintf(stderr, "invalid option %c\n", (char)opt);
				ret = FALSE;
			}
		}
	}

	free(usage);
	free(optstr);

	if (ret) {
		for (additional_field_idx = 0; additional_field_idx < additional_fields_count; additional_field_idx++) {			
			char** arg = va_arg(args, char**);
			if(additional_fields[additional_field_idx] != NULL) {
				(*arg) = additional_fields[additional_field_idx];
			}
		}
		va_end(args);

		if ((*level) == -1) {	   // production client
			(*level) = LOG_ERROR;
		}
		else if ((*level) == -2) { // production server
			(*level) = LOG_ERROR | LOG_WARN | LOG_INFO;
		}
		else if ((*level) <= -3) { // debug
			(*level) = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG
				//| LOG_MUTEX
				//| LOG_TRACE
				//| LOG_ROUTING
				//| LOG_HTTP
				//| LOG_KEY
				| LOG_NETWORK
				| LOG_AAATOKEN
				//| LOG_MESSAGE
				//| LOG_MEMORY
				;
		}

		/**
		To create unique names and to use a seperate port for every
		node we will start the nodes in forks of this thread and use the pid as unique id.

		As the pid may be greater then the port range we will shift it if necessary.

		.. code-block:: c
		\code
		*/
		if (*port == NULL) {
			int port_pid = getpid();

			*port = calloc(1, sizeof(char) * 7);
						
			sprintf(*port, "%d", port_pid);
			if (port_pid > 65535) {
				sprintf(*port, "%d", (port_pid >> 1));
			}
			if (port_pid < 1024) {
				sprintf(*port, "%d", (port_pid + 1024));
			}
		}
		/** \endcode */
	}
	else {		
		fprintf(stderr, "usage: %s\n", usage);
	}

	return ret;
}

void __np_example_helper_loop() {
		if (started_at == 0) {
			started_at = np_time_now();
		}

		double sec_since_start = np_time_now() - started_at;
		double ms_since_start = sec_since_start * 1000;

		if ((sec_since_start - last_loop_run_at) > output_intervall_sec)
		{
			last_loop_run_at = sec_since_start;
			char* memory_str;

			if(statistic_types == np_stat_all || (statistic_types & np_stat_memory )== np_stat_memory){
				if(enable_statistics == 1 || enable_statistics > 2) {
					memory_str = np_mem_printpool(FALSE,TRUE);
					if(memory_str != NULL) printf("%f -\n%s", sec_since_start, memory_str);
					free(memory_str);
				}
				if (enable_statistics >= 2) {
					memory_str = np_mem_printpool(TRUE, TRUE);
					if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
					free(memory_str);
				}
			}

#ifdef DEBUG
			if (statistic_types == np_stat_all || (statistic_types & np_stat_msgpartcache) == np_stat_msgpartcache) {

				if (enable_statistics == 1 || enable_statistics > 2) {
					memory_str = np_messagepart_printcache(FALSE);
					if (memory_str != NULL) printf("%f -\n%s", sec_since_start, memory_str);
					free(memory_str);
				}
				if (enable_statistics >= 2) {
					memory_str = np_messagepart_printcache(TRUE);
					if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
					free(memory_str);
				}
			}
			if (statistic_types == np_stat_all || (statistic_types & np_stat_locks) == np_stat_locks) {

				if (enable_statistics == 1 || enable_statistics > 2) {
					memory_str = np_threads_printpool(FALSE);
					if (memory_str != NULL) printf("%f -\n%s", sec_since_start, memory_str);
					free(memory_str);
				}
				if (enable_statistics >= 2) {
					memory_str = np_threads_printpool(TRUE);
					if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
					free(memory_str);
				}
			}
#endif
			if (statistic_types == np_stat_all || (statistic_types & np_stat_general) == np_stat_general) {							
				
				char time[50] = { 0 };
				reltime_to_str(time, sec_since_start);

				if (enable_statistics == 1 || enable_statistics > 2) {
					memory_str = np_statistics_print(FALSE);
									
					if (memory_str != NULL) printf("%s -\n%s", time, memory_str);
					free(memory_str);
				}
				if (enable_statistics >= 2) {
					memory_str = np_statistics_print(TRUE);
					if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
					free(memory_str);
				}
			}
			
		}
		fflush(NULL);
		//if((i == (35/*sec*/ * 10))){
		//	fprintf(stdout, "Renew bootstrap token");
		//	np_key_renew_token();
		//}

}

void __np_example_helper_run_loop() {
	while (TRUE)
	{
		ev_sleep(output_intervall_sec);
	}
}
void __np_example_helper_run_info_loop() {

	while (TRUE)
	{
		__np_example_helper_loop();
		ev_sleep(output_intervall_sec);
	}
}
