//
// neuropil is copyright 2016 by pi-lar GmbH
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

#define USAGE "neuropil_hydra -j key:proto:host:port [ -p protocol] [-n nr_of_nodes] [-t worker_thread_count]"
#define OPTSTR "j:p:n:t:"

NP_SLL_GENERATE_PROTOTYPES(int);
NP_SLL_GENERATE_IMPLEMENTATION(int);

#define DEBUG 0
#define NUM_HOST 120

extern char *optarg;
extern int optind;

int main(int argc, char **argv)
{
	int opt;
	int no_threads = 3;
	char* bootstrap_hostnode = NULL;
	char* proto = "udp4";
	uint32_t required_nodes = 5;
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG;

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
	{
		switch ((char) opt) {
		case 'j':
			bootstrap_hostnode = optarg;
			break;
		case 't':
			no_threads = atoi(optarg);
			if (no_threads <= 0) no_threads = 2;
			break;
		case 'p':
			proto = optarg;
			break;
		case 'n':
			required_nodes = atoi(optarg);
			break;
		default:
			fprintf(stderr, "invalid option %c\n", (char) opt);
			fprintf(stderr, "usage: %s\n", USAGE);
			exit(1);
		}
	}


	int current_pid = 0;

	np_sll_t(int, list_of_childs) = sll_init(int, list_of_childs);
	int array_of_pids[required_nodes + 1];

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
					char log_file_host[256];
					sprintf(log_file_host, "%s_host.log", "./neuropil_shared_hydra");

					np_log_init(log_file_host, level);
					np_init(proto, port, TRUE, "localhost");

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
					np_state_t* child_status = np_init(proto, port, FALSE, NULL);

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
				sll_append(int, list_of_childs, &array_of_pids[sll_size(list_of_childs)]);
			}
			ev_sleep(3.1415);

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
					if (current_pid == *iter->val)
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
			ev_sleep(3.1415);
		}
	}
	fprintf(stdout, "stopped creating child processes\n");
}
