//
// neuropil is copyright 2016-2022 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file
// for details
//
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "example_helper.c"
#include "files/file.h"

#include "search/np_search.h"
#include "util/np_tree.h"

#include "np_aaatoken.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_types.h"

bool authorize(np_context *ac, struct np_token *id);
bool authenticate(np_context *ac, struct np_token *id);

int main(int argc, char **argv) {
  int ret = 0;

  char *realm = NULL;
  char *code  = NULL;

  int   no_threads     = 9;
  char *j_key          = NULL;
  char *proto          = "udp4";
  char *port           = NULL;
  char *publish_domain = NULL;
  int   level          = -2;
  char *logpath        = ".";
  char *opt_cloud_size = "8";

  example_user_context *user_context;
  if ((user_context = parse_program_args(__FILE__,
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
                                         "[-n cloud_size]",
                                         "n:",
                                         &realm,
                                         &code)) == NULL) {
    exit(EXIT_FAILURE);
  }

  int          cloud_size = atoi(opt_cloud_size);
  np_context **context    = calloc(cloud_size, sizeof(np_context *));
  np_id       *file_seed  = calloc(cloud_size, sizeof(np_id));
  ;

  for (uint8_t i = 0; i < cloud_size; i++) {
    struct np_settings settings;
    np_default_settings(&settings);
    settings.n_threads = 5;
    snprintf(settings.log_file,
             255,
             "%s%s_%d.log",
             logpath,
             "/neuropil_search_nlnet",
             i);
    settings.log_level = LOG_INFO | LOG_WARNING | LOG_ERROR;

    context[i] = np_new_context(&settings);
    np_set_userdata(context[i], user_context);
    // np_ctx_cast(context[i]);

    np_example_print(context[i], stdout, "logpath: %s\n", settings.log_file);
    np_example_save_and_load_identity(context[i]);

    if (NULL != realm) {
      np_set_realm_name(context[i], realm);
      np_enable_realm_client(context[i]);
    }

    np_set_authorize_cb(context[i], authorize);
    np_set_authenticate_cb(context[i], authenticate);

    if (np_ok != np_listen(context[i], "pas4", "localhost", atoi(port), NULL)) {
      np_example_print(context[i],
                       stderr,
                       "ERROR: Node could not listen to %s:%s:%s\n",
                       proto,
                       publish_domain,
                       port);
    }
    // __np_example_helper_loop(context); // for the fancy ncurse display
    fprintf(stdout,
            "INFO : node is listening on %s\n",
            np_get_connection_string(context[i]));

    if (i == 0) {
      np_example_print(context[i], stdout, "starting http module\n");
      _np_http_init(context[i], "localhost", "3114");
    }

    memset(file_seed[i], 0, NP_FINGERPRINT_BYTES);

    np_example_print(context[i], stdout, "starting file server\n");
    // np_files_open(context[i], file_seed, "");

    //  np_sysinfo_enable_server(context);
    np_example_print(context[i], stdout, "starting search module\n");
    np_searchnode_init(context[i], NULL);

    np_example_print(context[i], stdout, "starting job queue\n");
    if (np_ok != np_run(context[i], 0.0)) {
      np_example_print(context[i], stderr, "ERROR: Node could not run\n");
    } else {
      if (NULL != j_key) {
        np_example_print(context[i], stdout, "try to join %s\n", j_key);
        // join previous node
        if (np_ok != np_join(context[i], j_key)) {
          np_example_print(context[i], stderr, "ERROR: Node could not join\n");
        }
      }
    }
  }

  double start = _np_time_now(context[0]);

  bool run = true;
  while (run) {
    for (uint8_t i = 0; i < cloud_size; i++) {
      enum np_return node_status = np_run(context[i], 0.0);

      if (np_ok != node_status)
        np_example_print(context[i],
                         stderr,
                         "ERROR: node run returned: %s \n",
                         np_error_str(node_status));

      if ((start + 60) < _np_time_now(context[0])) run = false;
    }
    np_time_sleep(0.003);
  }

  //////////////////////////////
  // t3821
  // char search_text[] = \
		// 	"Japan's trade surplus grew 5.3 percent from a year earlier to 11.46
  // billion dollars in February and well up from 2.88 billion dollars in
  // January, the finance ministry said Tuesday."; //
  // "Lawyers for the Major League Baseball players' union and the
  // commissioner's office are discussing ways to bring about a meeting between
  // slugger Jason Giambi and doping investigator George Mitchell." \
			// "Many voters hope efforts to reunify Cyprus will carry on whoever wins
  // Sunday's presidential election in the Turkish-held north, despite
  // \"pro-settlement\" leader Mehmet Ali Talat trailing in the polls."  \
			// "President Bush's effort to limit public access to presidential records,
  // already the subject of a federal lawsuit, came under attack from Congress
  // Thursday when a California Republican announced he will fight it." \
			// "A severe water shortage in Beijing has prompted the city to again hike
  // prices, possibly by up to 20 percent, a top water official said Tuesday." \
			// "John Edwards' decision this week to pull campaign resources in Nevada --
  // the same week that Barack Obama launched radio ads in the state -- reflects
  // two difficulties for the Edwards candidacy: his lack of money and strong
  // union backing." \
			// "Christl Haas, the Austrian skier who won the women's downhill at the 1964
  // Olympics, drowned while swimming at a Mediterranean resort, the Austrian
  // Embassy said. She was 57." \ "Soccer Australia officials on Tuesday
  // announced an Australian team to play Scotland in an international friendly
  // match on November 15 at Glasgow, Scotland.";

  // np_attributes_t attr = {0};
  // np_searchquery_t sq = {0};

  // if (np_create_searchquery(context, &sq, search_text, &attr))
  //     np_search_query(context, &sq);

  // struct np_data_conf search_conf = { 0 };
  // np_data_value search_val_title  = { 0 };
  // search_val_title.str = "";

  // np_tree_elem_t* tmp = NULL;
  // RB_FOREACH(tmp, np_tree_s, np_search_get_resultset(context, &sq))
  // {
  // 	np_searchresult_t* result = tmp->val.value.v;

  // 	struct np_data_conf conf = { 0 };
  // 	np_data_value val_title  = { 0 };
  // 	if (np_data_ok != np_get_data((np_datablock_t*)
  // result->intent->attributes, "title", &conf, &val_title ) )
  // 	{
  // 		val_title.str = "";
  // 	}
  // 	fprintf(stdout, "%5s :: %s :: %3u / %2.2f / %5s\n",
  // 					search_val_title.str, tmp->key.value.s,
  // result->hit_counter, result->level, val_title.str);
  // }

  run = true;
  fprintf(stdout, "now adding search entries from file system");
  while (run) {
    for (uint8_t i = 0; i < cloud_size; i++) {
      enum np_return node_status = np_run(context[i], 0.0);
      if (np_ok != node_status) {
        np_example_print(context[i],
                         stderr,
                         "ERROR: node run returned: %s \n",
                         np_error_str(node_status));
        run = false;
      }

      if (i == 0)
        // np_files_open(context[i], file_seed, "./test_data/articles");
        np_files_open(context[i], file_seed[i], "./neuropil_crawl");
    }
    np_time_sleep(0.003);
  }

  for (uint8_t i = 0; i < cloud_size; i++) {
    np_example_print(context[i], stderr, "closing node");
    np_files_close(context[i], "./test_data/articles");
  }
  return ret;
}

bool authorize(np_context *ac, struct np_token *id) {
  bool ret = false;
  if (strncmp(id->subject, "files/", 6) == 0) {
    // TODO: Make sure that id->public_key is an authenticated peer!
    // fprintf(stdout, "authz %s from %02X%02X%02X%02X%02X%02X :
    // %02X%02X%02X%02X%02X%02X...\n", 		id->subject,
    // id->issuer[0], id->issuer[1],     id->issuer[2],     id->issuer[3],
    // id->issuer[4],
    // id->issuer[5], 		id->public_key[0], id->public_key[1],
    // id->public_key[2], id->public_key[3], id->public_key[4],
    // id->public_key[5]);

    np_files_send_authorized(ac, id);
    ret = true;
  }
  // TODO: Make sure that id->public_key is the intended sender!
  return ret;
}

bool authenticate(np_context *ac, struct np_token *id) {
  // TODO: Make sure that id->public_key is an authenticated peer!
  fprintf(
      stdout,
      "authn %s from %02X%02X%02X%02X%02X%02X : %02X%02X%02X%02X%02X%02X ...\n",
      id->subject,
      id->issuer[0],
      id->issuer[1],
      id->issuer[2],
      id->issuer[3],
      id->issuer[4],
      id->issuer[5],
      id->public_key[0],
      id->public_key[1],
      id->public_key[2],
      id->public_key[3],
      id->public_key[4],
      id->public_key[5]);

  // TODO: Make sure that id->public_key is the intended sender!
  return true;
}
