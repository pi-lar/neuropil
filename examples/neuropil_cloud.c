//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/**
 *.. NOTE::
 *
 *   If you are not yet familiar with the neuropil initialization procedure please refer to the :ref:`tutorial`
 */

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>

#include "neuropil.h"
#include "np_constants.h"
#include "np_log.h"

#include "example_helper.c"

void make_wildcard(char* s) {
    s[0] = '*';

    for (size_t i = 64; i <= strlen(s); i++) {
        s[i - 63] = s[i];
    }
}

int main(int argc, char **argv)
{

    int no_threads = 3;
    char *j_key = NULL;
    char* proto = "udp4";
    char* opt_port = NULL;
    char* publish_domain = NULL;
    int level = -2;
    char* opt_cloud_size = "32";
    char* logpath = ".";
    
    example_user_context* user_context_template;
    if ((user_context_template = parse_program_args(
        __FILE__,
        argc,
        argv,
        &no_threads,
        &j_key,
        &proto,
        &opt_port,
        &publish_domain,
        &level,
        &logpath,
        "[-n cloud size]",
        "n:",
        &opt_cloud_size
    )) == NULL) {
        exit(EXIT_FAILURE);
    }

    int cloud_size = atoi(opt_cloud_size);

    np_context** nodes = calloc(cloud_size, sizeof(np_context*));

    char addr[500];
    uint16_t tmp;
    int port = 4000;
    if (opt_port != NULL) {
        port = atoi(opt_port);
    }
    for (int i=0; i < cloud_size; i++) {	
        port += 1;
        struct np_settings * settings = np_default_settings(NULL);		
        settings->n_threads =  no_threads;

        snprintf(settings->log_file, 255, "neuropil_cloud_%d.log", port);
        settings->log_level = level;

        example_user_context* user_context = malloc(sizeof(example_user_context));
        memcpy(user_context, user_context_template, sizeof(example_user_context));			

        nodes[i] = np_new_context(settings); // use default settings		
        np_set_userdata(nodes[i], user_context);


        np_example_print(nodes[0], stdout, "INFO: Starting Node %"PRIsizet"\n", i);

        if (np_ok != (tmp = np_listen(nodes[i], proto, publish_domain, port))) {
            np_example_print(nodes[0], stderr, "ERROR: Node %"PRIsizet" could not listen. %s\n", i, np_error_str(tmp));
        }
        else {
            if (np_ok != (tmp = np_get_address(nodes[i], addr, SIZE(addr)))) {
                np_example_print(nodes[0], stderr, "ERROR: Could not get address of node %"PRIsizet". %s\n", i, np_error_str(tmp));
            }
            np_example_print(nodes[0], stdout, "INFO: Node %"PRIsizet" aka  (%s) listens\n", i, addr);
        }

        if (i == 0) {
            __np_example_helper_loop(nodes[i]);
        }
        else {

            char port_tmp[8]={0};
            sprintf(port_tmp,"%d", atoi(user_context_template->opt_http_port)+i);
            example_http_server_init(nodes[i], user_context_template->opt_http_domain,port_tmp);
            example_sysinfo_init(nodes[i], np_sysinfo_opt_force_client);
        }
    }
    if (j_key != NULL) {
        np_join(nodes[0], j_key);
    }
    int iteration = 0;
    bool shutdown = false;
    while (!shutdown)
    {
        iteration++;
        for (int i = 0; i < cloud_size; i++) {
            if (np_ok != (tmp = np_run(nodes[i], 0))) {
                np_example_print(nodes[0], stderr, "ERROR: Node %"PRIsizet" could not run. %s\n", i, np_error_str(tmp));
            }
            else {
                if (i == 0) {
                    __np_example_helper_loop(nodes[i]);
                    
                    if (np_get_status(nodes[i]) != np_running) {
                        shutdown = true;
                        for (int s = 1; s < cloud_size; s++) {
                            np_destroy(nodes[s], false);
                        }
                    }
                }
                if (i > 0 && iteration < cloud_size && !np_has_joined(nodes[i - 1])) {
                    // get connection str of previous node
                    if (np_ok != (tmp = np_get_address(nodes[i - 1], addr, SIZE(addr)))) {
                        np_example_print(nodes[0], stderr, "ERROR: Could not get address of node %"PRIsizet". %s\n", i, np_error_str(tmp));
                    }
                    // for fun and testing make every second join a wildcard join
                    // currently all via wildcard as of bug "hash join"
                    //if (i % 2 == 0)
                    {
                        make_wildcard(addr);
                    }
                    // join previous node
                    if (np_ok != (tmp = np_join(nodes[i], addr))) {
                        np_example_print(nodes[0], stderr, "ERROR: Node %"PRIsizet" could not join. %s\n", i, np_error_str(tmp));
                    }
                    else {
                        np_example_print(nodes[0], stdout, "INFO: Node %"PRIsizet" joins %s\n", i, addr);
                    }
                }
            }
        }
        np_time_sleep(0); // slow down
    }

    np_example_print(nodes[0], stderr, "!!! DONE WITH EVERYTHING !!!");
}
