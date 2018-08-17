//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>

#include "neuropil.h"
#include "np_log.h"
#include "np_types.h"
#include "np_node.h"
#include "np_keycache.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "example_helper.c"

 NP_SLL_GENERATE_PROTOTYPES(int);
NP_SLL_GENERATE_IMPLEMENTATION(int);

 #define NUM_HOST 120

 
int main(int argc, char **argv)
{
	
	char* bootstrap_hostnode = NULL;
	char* bootstrap_hostnode_default;
	uint32_t required_nodes = NUM_HOST;

	int no_threads = 8;
	char *j_key = NULL;
	char* proto = "udp4";
	char* port = NULL;
	char* publish_domain = NULL;
	int level = -2;
	char* logpath = ".";
	char* required_nodes_opt = NULL;

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
		"[-n nr_of_nodes]",
		"n:",
		&required_nodes_opt
	) == false) {
		exit(EXIT_FAILURE);
	}
	if (required_nodes_opt != NULL) required_nodes = atoi(required_nodes_opt);

	/**
	for the general initialisation of a node please look into the neuropil_node example
	*/
	int current_pid = getpid();

	np_sll_t(int, list_of_childs) = sll_init(int, list_of_childs);
	int array_of_pids[required_nodes + 1];

	int status;

	key_t key;
	int shmid = 0;
	key = ftok("./bin/neuropil_shared_hydra", 'R');
	shmid = shmget(key, 256, 0644);

	// first clean up what was left from older runtime instances
	shmctl(shmid, IPC_RMID, NULL);

	while(true)
	{
		// (re-) start child processes
		if (list_of_childs->size < required_nodes)
		{
			current_pid = fork();

			if (0 == current_pid)
			{
				// check for bootstrap node (creates shared memory)
				key = ftok("./bin/neuropil_shared_hydra", 'R');
				shmid = shmget(key, 256, 0644);

				if (shmid == -1)
				{
					fprintf(stdout, "No bootstrap host detected, creating a new one\n");
				
					struct np_settings *settings = np_new_settings(NULL);
					settings->n_threads = no_threads;

					snprintf(settings->log_file, 255, "%s%s_%s.log", logpath, "/neuropil_controller", port);
					fprintf(stdout, "logpath: %s\n", settings->log_file);
					settings->log_level = level;

					np_context * context = np_new_context(settings);

					if (np_ok != np_listen(context, proto, publish_domain, atoi(port))) {
						printf("ERROR: Node could not listen");
						exit(EXIT_FAILURE);
					}


					fprintf(stdout, "getting connection string\n");
					bootstrap_hostnode = np_get_connection_string();

					shmid = shmget(key, 256, 0644 | IPC_CREAT);
					char* data = shmat(shmid, (void *)0, 0);

					snprintf(data, 255, "%s", bootstrap_hostnode);
					fprintf(stdout, "Bootstrap host node: %s\n", bootstrap_hostnode);

					if (np_ok != np_run(context, 0)) {
						printf("ERROR: Node could not start");
						exit(EXIT_FAILURE);
					}
					fprintf(stdout, "Bootstrap host node is running\n");
					fflush(stdout);
					fflush(stderr);
				}
				else
				{
					np_time_sleep(3.1415);

					char* data = shmat(shmid, (void *)0, SHM_RDONLY);

					fprintf(stdout, "started child process %d\n", current_pid);
					current_pid = getpid();

					char port[7];
					if (current_pid > 65535)
					{
						snprintf(port, 7, "%d", (current_pid >> 1));
					}
					else
					{
						snprintf(port, 7, "%d", current_pid);
					}

					struct np_settings *settings = np_new_settings(NULL);
					settings->n_threads = no_threads;

					snprintf(settings->log_file, 255, "%s%s_%s.log", logpath, "/neuropil_controller", port);
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
					}					// send join message
					log_debug_msg(LOG_DEBUG, "creating welcome message");

					np_send_join(data);

					int timeout = 200;
					while (timeout > 0 && false == child_status->my_node_key->node->joined_network) {
						// wait for join acceptance
						np_time_sleep(0.1);
						timeout--;
					}
					if(true == child_status->my_node_key->node->joined_network ){
						fprintf(stdout, "%s joined network!\n",port);
					}else{
						fprintf(stderr, "%s could not join network!\n",port);
					}
					fflush(stdout);
					fflush(stderr);
				}

				while (1)
				{
					np_time_sleep(0.1);
				}
				// escape from the parent loop
				break;
			}
			else
			{
				// parent process keeps iterating
				fprintf(stdout, "adding (%d) : child process %d \n", sll_size(list_of_childs), current_pid);
				array_of_pids[sll_size(list_of_childs)] = current_pid;
				sll_append(int, list_of_childs, array_of_pids[sll_size(list_of_childs)]);
			}
			np_time_sleep(3.1415);

		} else {

			current_pid = waitpid(-1, &status, WNOHANG);
			// check for stopped child processes
			if ( current_pid != 0 )
			{
				fprintf(stderr, "trying to find stopped child process %d\n", current_pid);
				sll_iterator(int) iter = NULL;
				uint32_t i = 0;
				for (iter = sll_first(list_of_childs); iter != NULL; sll_next(iter))
				{
					if (current_pid == iter->val)
					{
						fprintf(stderr, "removing stopped child process\n");
						sll_delete(int, list_of_childs, iter);
						for (; i < required_nodes; i++)
						{
							array_of_pids[i] = array_of_pids[i+1];
						}
						break;
					}
					else
					{
						fprintf(stderr, "not found\n");
					}
					i++;
				}
			}
			else
			{
				// fprintf(stdout, "all (%d) child processes running\n", sll_size(list_of_childs));
			}
			np_time_sleep(3.1415);
		}
	}
	fprintf(stdout, "stopped creating child processes\n");
}
