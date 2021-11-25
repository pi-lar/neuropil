//
// neuropil is copyright 2016-2021 by pi-lar GmbH
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

#include "np_log.h"
#include "np_legacy.h"
#include "np_aaatoken.h"
#include "np_keycache.h"
#include "util/np_tree.h"
#include "np_types.h"

#include "files/file.h"
#include "search/np_search.h"

#include "example_helper.c"


bool authorize (np_context *ac, struct np_token *id);
bool authenticate (np_context *ac, struct np_token *id);

int main(int argc, char **argv)
{
	int ret = 0;

	char* realm = NULL;
	char* code = NULL;

	int no_threads = 9;
	char *j_key = NULL;
	char* proto = "udp4";
	char* port = NULL;
	char* publish_domain = NULL;
	int level = -2;
	char* logpath = ".";

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
		"[-r realmname]",
		"r:",
		&realm,
		&code
	)) == NULL) {
		exit(EXIT_FAILURE);
	}

	struct np_settings settings;
	np_default_settings(&settings);
	settings.n_threads = no_threads;

	snprintf(settings.log_file, 255, "%s%s_%s.log", logpath, "/neuropil_search_node", port);
	settings.log_level = -2;

	np_context * ac = np_new_context(&settings);
	np_set_userdata(ac, user_context);
	np_ctx_cast(ac);

	np_example_print(context, stdout, "logpath: %s\n", settings.log_file);

	np_example_save_and_load_identity(context);
	
	if (NULL != realm)
	{
		np_set_realm_name(context, realm);
		np_enable_realm_client(context);
	}

	np_set_authorize_cb(context, authorize);
	np_set_authenticate_cb(context, authenticate);

	if (np_ok != np_listen(context, proto, "localhost", atoi(port))) {
		np_example_print(context, stderr, "ERROR: Node could not listen to %s:%s:%s",proto, publish_domain, port);
	}
	else 
	{
		// __np_example_helper_loop(context); // for the fancy ncurse display
		fprintf(stdout, "INFO : node is listening on %s\n", np_get_connection_string(context));

		log_debug_msg(LOG_DEBUG, "starting http module");
		_np_http_init(context, "localhost", "3114");

		np_id file_seed;
		memset(file_seed, 0, NP_FINGERPRINT_BYTES);

		log_debug_msg(LOG_DEBUG, "starting file server");
        np_files_open(context, file_seed, "");
		
		np_sysinfo_enable_server(context);
        np_searchnode_init(context, NULL);
		
		log_debug_msg(LOG_DEBUG, "starting job queue");
		if (np_ok != np_run(context, 0.001)) {
			np_example_print(context, stderr, "ERROR: Node could not run");
		}
		else {

			if (NULL != j_key)
			{
				np_example_print(context, stdout, "try to join %s\n", j_key);
				// join previous node
				if (np_ok != np_join(context, j_key)) {
					np_example_print(context, stderr, "ERROR: Node could not join");
				}
			}

			if (np_get_status(context) == np_running)
			{
		        np_files_open(context, file_seed, "./test_data/articles");
		        // np_files_open(context, file_seed, "examples");
				np_run(context, 0.5);
				// __np_example_helper_loop(context);
			}
		}
		np_example_print(context, stderr, "Closing Node");

//////////////////////////////
		// t3821
		char search_text[] = \
			"Japan's trade surplus grew 5.3 percent from a year earlier to 11.46 billion dollars in February and well up from 2.88 billion dollars in January, the finance ministry said Tuesday."; //
			// "Lawyers for the Major League Baseball players' union and the commissioner's office are discussing ways to bring about a meeting between slugger Jason Giambi and doping investigator George Mitchell." \
			// "Many voters hope efforts to reunify Cyprus will carry on whoever wins Sunday's presidential election in the Turkish-held north, despite \"pro-settlement\" leader Mehmet Ali Talat trailing in the polls."  \
			// "President Bush's effort to limit public access to presidential records, already the subject of a federal lawsuit, came under attack from Congress Thursday when a California Republican announced he will fight it." \
			// "A severe water shortage in Beijing has prompted the city to again hike prices, possibly by up to 20 percent, a top water official said Tuesday." \
			// "John Edwards' decision this week to pull campaign resources in Nevada -- the same week that Barack Obama launched radio ads in the state -- reflects two difficulties for the Edwards candidacy: his lack of money and strong union backing." \
			// "Christl Haas, the Austrian skier who won the women's downhill at the 1964 Olympics, drowned while swimming at a Mediterranean resort, the Austrian Embassy said. She was 57." \
			// "Soccer Australia officials on Tuesday announced an Australian team to play Scotland in an international friendly match on November 15 at Glasgow, Scotland.";

            np_attributes_t attr = {0};
            np_searchquery_t sq = {0};

            if (np_create_searchquery(context, &sq, search_text, &attr))
                np_search_query(context, &sq);

			struct np_data_conf search_conf = { 0 };
			np_data_value search_val_title  = { 0 };
			search_val_title.str = "";

			np_tree_elem_t* tmp = NULL;
			RB_FOREACH(tmp, np_tree_s, np_search_get_resultset(context, &sq))
			{
				np_searchresult_t* result = tmp->val.value.v;

				struct np_data_conf conf = { 0 };
				np_data_value val_title  = { 0 };
				if (np_data_ok != np_get_data((np_datablock_t*) result->result_entry->intent.attributes, "title", &conf, &val_title ) )
				{
					val_title.str = "";
				}
				fprintf(stdout, "%5s :: %s :: %3u / %2.2f / %5s\n", 
								search_val_title.str, tmp->key.value.s, result->hit_counter, result->level, val_title.str);
			} 

//////////////////////
		np_searchnode_destroy(context);
		np_files_close(context, file_seed);
	}

	return ret;
}

bool authorize (np_context *ac, struct np_token *id)
{
	// TODO: Make sure that id->public_key is an authenticated peer!
	fprintf(stdout, "authz %s from %02X%02X%02X%02X%02X%02X%02X: %02X%02X%02X%02X%02X%02X%02X...\n",
			id->subject,
			id->issuer,
	       id->public_key[0], id->public_key[1], id->public_key[2],
	       id->public_key[3], id->public_key[4], id->public_key[5],
	       id->public_key[6]);

	if (strncmp(id->subject, "files/", 6) == 0)
	{
		np_files_send_authorized(ac, id);
	}
	// TODO: Make sure that id->public_key is the intended sender!
	return true;
}

bool authenticate (np_context *ac, struct np_token *id)
{
	// TODO: Make sure that id->public_key is an authenticated peer!
	fprintf(stdout, "authn %s from %02X%02X%02X%02X%02X%02X%02X: %02X%02X%02X%02X%02X%02X%02X...\n",
			id->subject,
			id->issuer,
	       id->public_key[0], id->public_key[1], id->public_key[2],
	       id->public_key[3], id->public_key[4], id->public_key[5],
	       id->public_key[6]);

	// TODO: Make sure that id->public_key is the intended sender!
	return true;
}
