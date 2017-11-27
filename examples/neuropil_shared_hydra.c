//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
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

NP_SLL_GENERATE_PROTOTYPES(int16_t);
NP_SLL_GENERATE_IMPLEMENTATION(int16_t);

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
	) == FALSE) {
		exit(EXIT_FAILURE);
	}
	if (required_nodes_opt != NULL) required_nodes = atoi(required_nodes_opt);

	/**
	for the general initialisation of a node please look into the neuropil_node example
	*/
	int current_pid = getpid();

	np_sll_t(int16_t, list_of_childs) = sll_init(int16_t, list_of_childs);
	int16_t array_of_pids[required_nodes + 1];

	int status;

	key_t key;
	int shmid = 0;
	key = ftok("./bin/neuropil_shared_hydra", 'R');
	shmid = shmget(key, 256, 0644);

	// first clean up what was left from older runtime instances
	shmctl(shmid, IPC_RMID, NULL);

	while(TRUE)
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
				
					char log_file_host[256];
					sprintf(log_file_host, "%s_host.log", "./neuropil_shared_hydra");

					np_log_init(log_file_host, level);
					np_init(proto, port, publish_domain);

					fprintf(stdout, "getting connection string\n");
					bootstrap_hostnode = np_get_connection_string();

					shmid = shmget(key, 256, 0644 | IPC_CREAT);
					char* data = shmat(shmid, (void *)0, 0);

					snprintf(data, 255, "%s", bootstrap_hostnode);
					fprintf(stdout, "Bootstrap host node: %s\n", bootstrap_hostnode);

					np_start_job_queue(4);
					fprintf(stdout, "Bootstrap host node is running\n");
					fflush(stdout);
					fflush(stderr);
				}
				else
				{
					ev_sleep(3.1415);

					char* data = shmat(shmid, (void *)0, SHM_RDONLY);

					fprintf(stdout, "started child process %d\n", current_pid);
					current_pid = getpid();

					char port[7];
					if (current_pid > 65535)
					{
						sprintf(port, "%d", (current_pid >> 1));
					}
					else
					{
						sprintf(port, "%d", current_pid);
					}

					char log_file[256];
					sprintf(log_file, "%s_%s.log", "./neuropil_shared_hydra", port);
					// child process
					np_log_init(log_file, level);
					// used the pid as the port
					np_state_t* child_status = np_init(proto, port, NULL);

					log_debug_msg(LOG_DEBUG, "starting job queue");
					np_start_job_queue(no_threads);
					// send join message
					log_debug_msg(LOG_DEBUG, "creating welcome message");

					np_send_join(data);

					int timeout = 200;
					while (timeout > 0 && FALSE == child_status->my_node_key->node->joined_network) {
						// wait for join acceptance
						ev_sleep(0.1);
						timeout--;
					}
					if(TRUE == child_status->my_node_key->node->joined_network ){
						fprintf(stdout, "%s joined network!\n",port);
					}else{
						fprintf(stderr, "%s could not join network!\n",port);
					}
					fflush(stdout);
					fflush(stderr);
				}

				while (1)
				{
					ev_sleep(0.1);
				}
				// escape from the parent loop
				break;
			}
			else
			{
				// parent process keeps iterating
				fprintf(stdout, "adding (%d) : child process %d \n", sll_size(list_of_childs), current_pid);
				array_of_pids[sll_size(list_of_childs)] = current_pid;
				sll_append(int16_t, list_of_childs, array_of_pids[sll_size(list_of_childs)]);
			}
			ev_sleep(3.1415);

		} else {

			current_pid = waitpid(-1, &status, WNOHANG);
			// check for stopped child processes
			if ( current_pid != 0 )
			{
				fprintf(stderr, "trying to find stopped child process %d\n", current_pid);
				sll_iterator(int16_t) iter = NULL;
				uint32_t i = 0;
				for (iter = sll_first(list_of_childs); iter != NULL; sll_next(iter))
				{
					if (current_pid == iter->val)
					{
						fprintf(stderr, "removing stopped child process\n");
						sll_delete(int16_t, list_of_childs, iter);
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
			ev_sleep(3.1415);
		}
	}
	fprintf(stdout, "stopped creating child processes\n");
}
