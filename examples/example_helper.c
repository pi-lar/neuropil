//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>

#include "neuropil.h"
#include "np_types.h"
#include "np_memory.h"
#include "np_log.h"
#include "np_messagepart.h"

extern char *optarg;
extern int optind;

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
		"./%s [ -j key:proto:host:port ] [ -p protocol] [-b port] [-t (> 0) worker_thread_count ] [-u publish_domain] [-d loglevel] %s",
		program, additional_fields_desc
	);
	char* optstr; 
	asprintf(&optstr, "j:p:b:t:u:d:g:%s", additional_fields_optstr);

	char* additional_fields[32] = { 0 }; // max additional fields
	va_list args;
	va_start(args, additional_fields_optstr);
	char* additional_field_char;
	int additional_fields_count = strlen(additional_fields_optstr) / 2;
	
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
			(*level)= atoi(optarg);
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
				//| LOG_NETWORK
				//| LOG_AAATOKEN
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

void __np_example_helper_loop(uint32_t iteration, double sec_per_iteration) {
#ifdef DEBUG
#if DEBUG == 1
		
		double sec_since_start = iteration * sec_per_iteration ; 
		double ms_since_start = sec_since_start  * 1000;	
		if (iteration == 0 || ((int)ms_since_start) % (1/*sec*/ * 1000) == 0)
		{
			// to output
			char* memory_str = np_mem_printpool(FALSE,TRUE);
			if(memory_str != NULL) printf("%f - %s", sec_since_start, memory_str);
			free(memory_str);
			memory_str = np_mem_printpool(TRUE,TRUE);
			if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
			free(memory_str);


			memory_str = np_messagepart_printcache(FALSE);
			//if(memory_str != NULL) printf("%f - %s", sec_since_start, memory_str);
			free(memory_str);
			memory_str = np_messagepart_printcache(TRUE);
			if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
			free(memory_str);


			memory_str = np_threads_printpool(FALSE);
			if(memory_str != NULL) printf("%f - %s", sec_since_start, memory_str);
			free(memory_str);
			memory_str = np_threads_printpool(TRUE);
			if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
			free(memory_str);			
		}

		//if((i == (35/*sec*/ * 10))){
		//	fprintf(stdout, "Renew bootstrap token");
		//	np_key_renew_token();
		//}
#endif
#endif	
}

void __np_example_helper_run_loop() {
	uint32_t i = 0;
	while (TRUE) 
	{
		i += 1;
		ev_sleep(0.01);
		__np_example_helper_loop(i, 0.01);
	}
}
