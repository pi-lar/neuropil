//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/**
 *.. NOTE::
 *
 *   If you are not yet familiar with the neuropil initialization procedure please refer to the :ref:`tutorial`
 */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "neuropil.h"
#include "np_log.h"
#include "np_types.h"
#include "np_tree.h"
#include "np_sysinfo.h"
#include "np_node.h"
#include "np_keycache.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>



#define USAGE "neuropil_hydra [-j key:proto:host:port] [ -p protocol] [-n nr_of_nodes] [-t worker_thread_count] [-l path_to_log_folder]"
#define OPTSTR "j:p:n:t:l:"

NP_SLL_GENERATE_PROTOTYPES(int);
NP_SLL_GENERATE_IMPLEMENTATION(int);

#define DEBUG 0
#define NUM_HOST 25

extern char *optarg;
extern int optind;

/**
  The purpose of this program is to start a set of nodes
  and restart them in the case of failure.

  For this to accomplish we will do the following steps:

 *  #. :ref:`Create a bootstrap node (with http server), if none is given <np_hydra_create_bootstrap_node>`.
 *  #. :ref:`Start X nodes. Each node will be started in a different process <neuropil_hydra_step_startnodes>`.
 *  #. :ref:`Check if the created nodes are still present, if not we may start a new node <neuropil_hydra_step_check_nodes_still_present>`

  The last step will be executed in a loop.

 */
int main(int argc, char **argv)
{
	int opt;
	int no_threads = 3;
	char* bootstrap_hostnode = NULL;
	char* bootstrap_hostnode_default;
	char bootstrap_port[7];
	char* proto = "udp4";
	char* logpath = ".";

	uint32_t required_nodes = NUM_HOST;
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_SERIALIZATION;

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF) {
		switch ((char) opt) {
		case 'j':
			bootstrap_hostnode = optarg;
			break;
		case 't':
			no_threads = atoi(optarg);
			if (no_threads <= 0)
				no_threads = 2;
			break;
		case 'p':
			proto = optarg;
			break;
		case 'n':
			required_nodes = atoi(optarg);
			break;
		case 'l':
			if(optarg != NULL){
				logpath = optarg;
			}else{
				fprintf(stderr, "invalid option value\n");
				fprintf(stderr, "usage: %s\n", USAGE);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			fprintf(stderr, "invalid option %c\n", (char) opt);
			fprintf(stderr, "usage: %s\n", USAGE);
			exit(EXIT_FAILURE);
		}
	}
	// Get the current pid and shift it to be a viable port.
	// This way the application may be used for multiple instances on one system
	int current_pid = getpid();

	if (current_pid > 65535) {
		sprintf(bootstrap_port, "%d", (current_pid >> 1));
	} else {
		sprintf(bootstrap_port, "%d", current_pid);
	}
	asprintf(&bootstrap_hostnode_default, "%s:localhost:%s", proto, bootstrap_port);

	int create_bootstrap = NULL == bootstrap_hostnode;
	if (TRUE == create_bootstrap) {
		bootstrap_hostnode = bootstrap_hostnode_default;

		fprintf(stdout, "No bootstrap host specified.\n");
		current_pid = fork();

		// Running bootstrap node in a different fork
		if (0 == current_pid) {

			fprintf(stdout, "Creating new bootstrap node...\n");
			/**

			 *.. _np_hydra_create_bootstrap_node:
			 *
			 * **Step 1: Create a bootstrap node**
			 *
			   We enable the HTTP Server for this node to use our JSON interface.

 	 	 	   .. code-block:: c

			  \code
			 */
			char log_file_host[256];
			sprintf(log_file_host, "%s%s_host_%s.log", logpath, "/neuropil_hydra", bootstrap_port);
			fprintf(stdout, "logpath: %s\n", log_file_host);

			np_log_init(log_file_host, level);
			// provide localhost as hostname to support development on local machines
			np_init(proto, bootstrap_port, TRUE, "localhost");
			/**
			 \endcode
			 */
			/**
			 Enable the bootstrap node as master for our SysInfo subsystem

			   .. code-block:: c

			   \code
			 */
			np_sysinfo_enable_master();
			/**

			 \endcode
			 */
			/**
			  And wait for incomming connections

			   .. code-block:: c

			   \code
			 */
			np_start_job_queue(10);
			while (TRUE) {
			    ev_sleep(0.1);
			}
			/**

			 \endcode
			 */
		}
		fprintf(stdout, "Bootstrap host node: %s\n", bootstrap_hostnode);
		if (NULL == bootstrap_hostnode) {
			fprintf(stderr, "Bootstrap host node could not start ... exit\n");
			exit(1);
		}
	}

	/**

	   .. _neuropil_hydra_step_startnodes:

	 * **Step 2: Start nodes**

	   This step does contain 2 parts.

	 *  #. we create X nodes an join them with our bootstrap node
	 *  #. we need to remember the nodes to implement Step 3

	   Let us beginn with part 2:

	   We declare a list where we store the pid of our newly created nodes:

	 .. code-block:: c

	  \code
	 */
	np_sll_t(int, list_of_childs) = sll_init(int, list_of_childs);
	/** \endcode

	 and will later on add to this list.
	 */
	int array_of_pids[required_nodes + 1];

	current_pid = 0;
	int status;

	/**
	  Now we will create the additional nodes.
	  To prevent an ever growing list of nodes we will only create an set amount

	   .. code-block:: c

	   \code
	 */
	while (TRUE) {
		// (re-) start child processes
		if (list_of_childs->size < required_nodes) {

			/**
			 \endcode
			  To create unique names and to use a seperate port for every
			  node we will start the nodes in forks of this thread and use the pid as unique id.

			  As the pid may be greater then the port range we will shift it if necessary.

				.. code-block:: c

			   \code
			 */
			current_pid = fork();

			if (0 == current_pid) {
				fprintf(stdout, "started child process %d\n", current_pid);
				current_pid = getpid();

				char port[7];
				if (current_pid > 65535) {
					sprintf(port, "%d", (current_pid >> 1));
				} else {
					sprintf(port, "%d", current_pid);
				}
				/**
				 \endcode

				  We now start the nodes like before

				.. code-block:: c

				  \code
				 */
				char log_file[256];
				sprintf(log_file, "%s%s_%s.log", logpath, "/neuropil_hydra", port);
				np_log_init(log_file, level);
				// use the pid as port
				// provide localhost as hostname to support development on local machines
				np_state_t* child_status = np_init(proto, port, FALSE, "localhost");
				log_msg(LOG_DEBUG, "starting job queue");
				np_start_job_queue(no_threads);
				/**
				 \endcode

				  and enable the nodes as slaves in our SysInfo subsystem

				.. code-block:: c

				  \code
				 */
				np_sysinfo_enable_slave();
				/**
				 \endcode

				   and join our bootstrap node

					.. code-block:: c

				   \code
				 */
				do {
 					fprintf(stdout, "try to join bootstrap node\n");
					np_send_wildcard_join(bootstrap_hostnode);

					int timeout = 100;
					while (timeout > 0 && FALSE == child_status->my_node_key->node->joined_network) {
						// wait for join acceptance
						ev_sleep(0.1);
						timeout--;
					}

					if(FALSE == child_status->my_node_key->node->joined_network ) {
						fprintf(stderr, "%s could not join network!\n",port);
					}
				} while (FALSE == child_status->my_node_key->node->joined_network) ;

				fprintf(stdout, "%s joined network!\n",port);
				/**
				 \endcode
				 */

				while (TRUE) {
					ev_sleep(0.1);
				}

			} else {
				/**
				  While the fork process starts the new node,
				  the main process needs to add the new process id to the list we created before.

				 .. code-block:: c

				 \code
				 */
				fprintf(stdout, "adding (%d) : child process %d \n",
						sll_size(list_of_childs), current_pid);
				array_of_pids[sll_size(list_of_childs)] = current_pid;
				sll_append(int, list_of_childs,
						&array_of_pids[sll_size(list_of_childs)]);
				/**
				 \endcode
				 */
			}

			ev_sleep(3 * 3.1415);

		} else {
			/**
			  .. _neuropil_hydra_step_check_nodes_still_present:

			  * **Step 3: Check if the created nodes are still present**

			  To do this we gather informations regarding our stopped subprocesses
			  and delete them from our list of pids

			 .. code-block:: c

			 \code
			 */
			current_pid = waitpid(-1, &status, WNOHANG);
			// check for stopped child processes
			if (current_pid != 0) {
				fprintf(stderr, "trying to find stopped child process %d\n",
						current_pid);
				sll_iterator(int) iter = NULL;
				uint32_t i = 0;
				for (iter = sll_first(list_of_childs); iter != NULL;
						sll_next(iter)) {
					if (current_pid == *iter->val) {
						fprintf(stderr, "removing stopped child process\n");
						sll_delete(int, list_of_childs, iter);
						for (; i < required_nodes; i++) {
							array_of_pids[i] = array_of_pids[i + 1];
						}
						break;
					} else {
						fprintf(stderr, "not found\n");
					}
					i++;
				}
			}
			/**
			 \endcode
			 */
			ev_sleep(3.415);
		}
	}
}
