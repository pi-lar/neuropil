//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/**
.. NOTE::
   If you are not yet familiar with the neuropil initialization procedure please refer to the :ref:`tutorial`
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

#include "sodium.h"

#include "np_legacy.h"
#include "np_log.h"
#include "np_types.h"
#include "np_tree.h"
#include "np_shutdown.h"
#include "np_sysinfo.h"
#include "np_node.h"
#include "np_keycache.h"
#include "np_key.h"
#include "np_memory.h"

#include "np_util.h"
#include "np_list.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "example_helper.c"


NP_SLL_GENERATE_PROTOTYPES(int);
NP_SLL_GENERATE_IMPLEMENTATION(int);

#define NUM_HOST 4


/**
The purpose of this program is to start a set of nodes
and restart them in the case of failure.

For this to accomplish we will do the following steps:

#. :ref:`Create a bootstrap node (with http server), if none is given <np_hydra_create_bootstrap_node>`.
#. :ref:`Start X nodes. Each node will be started in a different process <neuropil_hydra_step_startnodes>`.
#. :ref:`Check if the created nodes are still present, if not we may start a new node <neuropil_hydra_step_check_nodes_still_present>`

The last step will be executed in a loop.

*/
int main(int argc, char **argv)
{
    bool create_bootstrap = true;
    bool has_a_node_started = false;
    char* bootstrap_hostnode_default;
    uint32_t required_nodes = NUM_HOST;

    double started_at = np_time_now();

    int no_threads = 8;
    char *j_key = NULL;
    char* proto = "udp4";
    char* port = NULL;
    char* publish_domain = NULL;
    int level = -2;
    char* logpath = ".";
    char* required_nodes_opt = NULL;
    char* node_creation_speed_str = NULL;
    double default_node_creation_speed = 3.415;
    char* opt_kill_node = NULL;
    uint16_t kill_node = 300;

    int opt;
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
        "[-n nr_of_nodes] [-z (double|\"default\")speed of node creation] [-k kill a node every x sec]",
        "n:z:k:",
        &required_nodes_opt,
        &node_creation_speed_str,
        &opt_kill_node

    )) == NULL) {
        exit(EXIT_FAILURE);
    }
    if (opt_kill_node != NULL) kill_node = atoi(opt_kill_node);
    if (required_nodes_opt != NULL) required_nodes = atoi(required_nodes_opt);
    if (node_creation_speed_str != NULL) {
        if (strcmp(node_creation_speed_str, "default") != 0) {
            default_node_creation_speed = atof(node_creation_speed_str);
        }
        free(node_creation_speed_str);
    }

    if (j_key != NULL) {
        create_bootstrap = false;
    }

    /**
    for the general initialisation of a node please look into the neuropil_node example
    */
    int current_pid = getpid();

    if (true == create_bootstrap) {
        // Get the current pid and shift it to be a viable port.
        // This way the application may be used for multiple instances on one system
        if(publish_domain == NULL)
            publish_domain = strdup("localhost");

        bootstrap_hostnode_default = np_build_connection_string("*", proto, publish_domain, port, true);

        j_key = bootstrap_hostnode_default;

        // np_example_print(context, stdout, "No bootstrap host specified.\n");
        has_a_node_started = true;

        current_pid = fork();

        // Running bootstrap node in a different fork
        if (0 == current_pid) {

            // np_example_print(context, stdout, "Creating new bootstrap node...\n");
            /**

            .. _np_hydra_create_bootstrap_node:

               * **Step 1: Create a bootstrap node**

               We enable the HTTP Server for this node to use our JSON interface.

            .. code-block:: c

               \code
            */
            struct np_settings *settings = np_default_settings(NULL);
            settings->n_threads = no_threads;

            snprintf(settings->log_file, 255, "%s%s_%s.log", logpath, "/neuropil_hydra_bt", port);
            // fprintf(stdout, "logpath: %s\n", settings->log_file);
            settings->log_level = level;

            np_context * context = np_new_context(settings);
            np_set_userdata(context, user_context);
            if (np_ok != np_listen(context, proto, publish_domain, atoi(port))) {
                printf("ERROR: Node could not listen");
                exit(EXIT_FAILURE);
            }

            printf("Neuropil init ok\n");
            /**
               \endcode
            */

            // start http endpoint
            // get public / local network interface id

            /**
            Enable the bootstrap node as server for our SysInfo subsystem

            .. code-block:: c

               np_sysinfo_enable_server();

            */
            printf("HttpServer init ok\n");
            __np_example_helper_loop(context);

            /**
            And wait for incoming connections

            .. code-block:: c

               \code
            */
            if (np_ok != np_run(context, 0)) {
                printf("ERROR: Node could not start");
                exit(EXIT_FAILURE);
            }
            printf("Running Neuropil\n");

            __np_example_helper_run_info_loop(context);
            /**
               \endcode
            */
        }
        // np_example_print(context, stdout, "Bootstrap host node: %s\n", j_key);
        if (NULL == j_key) {
            // np_example_print(context, stdout, "Bootstrap host node could not start ... exit\n");
            exit(EXIT_FAILURE);
        }
    }

    /**
    .. _neuropil_hydra_step_startnodes:

    * **Step 2: Start nodes**

    This step does contain 2 parts.

    #. we create X nodes an join them with our bootstrap node
    #. we need to remember the nodes to implement Step 3

    Let us begin with part 2:

    We declare a list where we store the pid of our newly created nodes:

    .. code-block:: c

       \code
    */
    np_sll_t(int, list_of_childs) = sll_init(int, list_of_childs);
    /**
       \endcode
    */

    /**
    and will later on add the pid's of started processes to this list.
    */

    current_pid = 0;
    int status;

    /**
    Now we will create the additional nodes.
    To prevent an ever growing list of nodes we will only create an set amount

    .. code-block:: c

       \code
    */
    char bootstrap_port[10];
    int bootstrap_port_i = atoi(port);
    memcpy(bootstrap_port, port, strnlen(port,10));
    double last_process_kill_at = np_time_now();
    while (true) {
        // (re-) start child processes
        if (sll_size(list_of_childs) < required_nodes) {

    /**
       \endcode
    */

            /**
            To create unique names and to use a separate port for every
            node we will start the nodes in forks of this thread and use the pid as unique id.

            .. code-block:: c

               \code
            */
            snprintf(port, 7, "%d", atoi(port) + 1);
            int port_i = atoi(port);
            current_pid = fork();

            if (0 == current_pid) {
                // disable server for clients
                if(has_a_node_started && user_context->opt_sysinfo_mode != np_sysinfo_opt_disable){
                    user_context->opt_sysinfo_mode = np_sysinfo_opt_force_client;
                }
                current_pid = getpid();
                // np_example_print(context, stdout, "Starting process %"PRIi32" on port %s\n", current_pid, port);
                /**
                   \endcode
                */

                /**
                We now start the nodes like before

                .. code-block:: c

                   \code
                */
                struct np_settings *settings = np_default_settings(NULL);
                settings->n_threads = no_threads;

                snprintf(settings->log_file, 255, "%s%s_%s.log", logpath, "/neuropil_hydra_ch", port);
                // fprintf(stdout, "logpath: %s\n", settings->log_file);
                settings->log_level = level;

                np_context * context = np_new_context(settings);
                np_set_userdata(context, user_context);

                if (np_ok != np_listen(context, proto, publish_domain, atoi(port))) {
                    printf("ERROR: Node could not listen");
                    exit(EXIT_FAILURE);
                }

                log_debug_msg(LOG_DEBUG, "starting job queue");
                /**
                   \endcode
                */

                /**
                and enable the nodes as clients in our sysinfo subsystem

                .. code-block:: c

                   \code
                */
                np_sysinfo_enable_client(context);
                /**
                   \endcode
                */

                // We enable the statistics watchers for debugging purposes
                if(has_a_node_started == false){ // <=> we are the first node started
                    np_statistics_add_watch_internals(context);
                    np_statistics_add_watch(context, _NP_SYSINFO_REQUEST);
                    np_statistics_add_watch(context, _NP_SYSINFO_REPLY);
                    __np_example_inti_ncurse(context);
                    __np_example_helper_run_loop(context);
                }
                /**
                and join our bootstrap node

                .. code-block:: c

                   \code
                */
                if (np_ok != np_run(context, 0)) {
                    printf("ERROR: Node could not start");
                    exit(EXIT_FAILURE);
                }

                bool firstConnectionTry = true;
                do {
                    if (!firstConnectionTry) {
                        // np_example_print(context, stdout, "%s (%d/%"PRIu32") tries to join bootstrap node\n", port, port_i-bootstrap_port_i, required_nodes);
                    }
                    np_send_join(context, j_key);
                    firstConnectionTry = false;
                    int timeout = 100;
                    while (timeout > 0 && np_run(context, 0.01) && false == np_has_joined(context)) {
                            // wait for join acceptance
                            timeout--;
                    }
                    if(false == np_has_joined(context) ) {
                        // np_example_print(context, stdout, "%s (%d/%"PRIu32") could not join network\n", port, port_i - bootstrap_port_i, required_nodes);
                    }
                } while (false == np_has_joined(context));
                char time[50] = { 0 };
                reltime_to_str(time, np_time_now() - started_at);
                // np_example_print(context, stdout, "%s (%d/%"PRIu32") joined network after %s!\n", port, port_i - bootstrap_port_i, required_nodes, time);
                /**
                   \endcode
                */
                np_run(context, kill_node);

                // LEAVE TEST
                np_destroy(context, true);
                // END LEAVE TEST

                exit(EXIT_SUCCESS);

                //				if (has_a_node_started == false)
                //					__np_example_helper_run_info_loop(context);
                //				else
                //					__np_example_helper_run_loop(context);

            } else {
                if (has_a_node_started == true) {
                    /**
                    While the fork process starts the new node,
                    the main process needs to add the new process id to the list we created before.

                    .. code-block:: c

                       \code
                    */
                    sll_append(int, list_of_childs, current_pid);
                    /**
                       \endcode
                    */
                }
                has_a_node_started = true;
            }
            if(default_node_creation_speed > 0)
                np_time_sleep(default_node_creation_speed);

        } else {


            /**
            .. _neuropil_hydra_step_check_nodes_still_present:

            * **Step 3: Check if the created nodes are still present**

            To do this we gather informations regarding our stopped subprocesses
            and delete them from our list of pids

            .. code-block:: c

               \code
            */

            int child_pid = waitpid(-1, &status, WNOHANG);
            // check for stopped child processesy
            if (child_pid  > 0) {

                if ( WIFEXITED(status) || WIFSIGNALED(status) )
                {
                    /*
                    if (WIFSIGNALED(status))
                        fprintf(stdout, "node (%"PRIu32") exited by signal (crash / kill)\n", child_pid);
                    else
                        fprintf(stdout, "node (%"PRIu32") exited normally  (left network)\n", child_pid);
                    */
                    sll_iterator(int) iter = NULL;
                    uint32_t i = 0;
                    for (iter = sll_first(list_of_childs);
                        iter != NULL;
                        sll_next(iter))
                    {
                        if (child_pid == iter->val)
                        {
                            // np_example_print(context, stdout, "removing stopped child process\n");
                            sll_delete(int, list_of_childs, iter);
                            break;
                        }
                        i++;
                    }
                }
            }

            /**
               \endcode
            */
            np_time_sleep(0.1);
        }

    }
}
