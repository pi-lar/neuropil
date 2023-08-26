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
#include <yajl/yajl_gen.h>
#include <yajl/yajl_parse.h>

// #include "np_log.h"
#include <yajl/yajl_gen.h>
#include <yajl/yajl_parse.h>

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

uint8_t __indent = 0;

enum pubmed_entry_pos {
  pubmed_entry_none       = 0, // current position is not in object
  pubmed_entry_article_id = 1, // string
  pubmed_entry_article_text,   // list[string]
  pubmed_entry_abstract_text,  // list[string]
  pubmed_entry_labels,         // null
  pubmed_entry_section_names,  // list[string]
  pubmed_entry_sections,       // list[list[string]]
};

struct pubmed_entry_s {
  char  article_id[11];
  char *section_names[11];
  char *abstract_text[11];
};

static enum pubmed_entry_pos __current_pos        = pubmed_entry_none;
static struct pubmed_entry_s __current_entry      = {};
static uint8_t               __pubmed_array_index = 0;
static np_context           *__context;

static int test_yajl_null(void *ctx) {
  // for (uint8_t x = 0; x <= __indent; x++) printf("  ");
  // printf("null\n");
  return 1;
}

/*
static int test_yajl_boolean(void * ctx, int boolVal)
{
        for (uint8_t x = 0; x <= __indent; x++) printf("  ");
    printf("bool: %s\n", boolVal ? "true" : "false");
    return 1;
}

static int test_yajl_integer(void *ctx, long long integerVal)
{
        for (uint8_t x = 0; x <= __indent; x++) printf("  ");
    printf("integer: %lld\n", integerVal);
    return 1;
}
static int test_yajl_double(void *ctx, double doubleVal)
{
        for (uint8_t x = 0; x <= __indent; x++) printf("  ");
    printf("double: %g\n", doubleVal);
    return 1;
}
*/

static int
test_yajl_string(void *ctx, const unsigned char *stringVal, size_t stringLen) {
  switch (__current_pos) {
  case pubmed_entry_article_id: {
    uint8_t i = (stringLen < 10) ? stringLen : 10;
    strncpy(__current_entry.article_id, stringVal, i);
    __current_entry.article_id[i + 1] = '\0';
  } break;

  case pubmed_entry_abstract_text:
    __current_entry.abstract_text[__pubmed_array_index++] =
        strndup(stringVal, stringLen);
    break;

  case pubmed_entry_section_names:
    __current_entry.section_names[__pubmed_array_index++] =
        strndup(stringVal, stringLen);
    break;

  default:
    break;
  }
  return 1;

  // for (uint8_t x = 0; x <= __indent; x++) printf("  ");
  // printf("string: '");
  // fwrite(stringVal, 1, stringLen, stdout);
  // printf("'\n");
  // return 1;
}
static int
test_yajl_map_key(void *ctx, const unsigned char *stringVal, size_t stringLen) {
  if (0 == strncmp(stringVal, "article_id", 10)) {
    __current_pos = pubmed_entry_article_id;
  } else if (0 == strncmp(stringVal, "section_names", 13)) {
    __current_pos = pubmed_entry_section_names;
  } else if (0 == strncmp(stringVal, "abstract_text", 13)) {
    __current_pos = pubmed_entry_abstract_text;
  } else {
    __current_pos = pubmed_entry_none;

    // for (uint8_t x = 0; x <= __indent; x++) printf("  ");
    // char * str = (char *) malloc(stringLen + 1);
    // str[stringLen] = 0;
    // memcpy(str, stringVal, stringLen);
    // printf("key: '%s'\n", str);
    // free(str);
  }
  return 1;
}

static int test_yajl_start_map(void *ctx) {
  __current_pos = pubmed_entry_none;

  memset(&__current_entry, 0, sizeof(struct pubmed_entry_s));

  // for (uint8_t x = 0; x <= __indent; x++) printf("  ");
  __indent++;
  // printf("map open '{'\n");
  return 1;
}
static int test_yajl_end_map(void *ctx) {
  // if (strncmp("PMC3459524", __current_entry.article_id, 10) != 0) return 1;

  struct np_mx_properties mxp =
      np_get_mx_properties(__context, __current_entry.article_id);
  mxp.ackmode     = NP_MX_ACK_NONE;
  mxp.message_ttl = NP_PI * 10;
  mxp.intent_ttl  = 60 * 60 * 24; // a new token each day
  // mxp.intent_update_after = 60*60; // refresh each hour
  mxp.intent_update_after = 30; // refresh each 30 seconds

  // for(uint8_t x = 0; x < __indent_level; x++) fprintf(stdout, __indent_str);
  // fprintf(stdout, "registering   np://%s for file %s\n", subject, filename);
  np_set_mx_properties(__context, __current_entry.article_id, mxp);
  np_mx_properties_disable(__context, __current_entry.article_id);

  np_datablock_t attr[NP_EXTENSION_BYTES] = {0};
  np_init_datablock(attr, NP_EXTENSION_BYTES);

  fprintf(stdout,
          "now trying to add search entry for %-10s: ",
          __current_entry.article_id);

  struct np_data_conf data_conf_title = {
      .type      = NP_DATA_TYPE_STR,
      .data_size = strnlen(__current_entry.article_id, 11)};
  strncpy(data_conf_title.key, "title", 255);
  np_set_data(attr,
              data_conf_title,
              (np_data_value){.str = __current_entry.article_id});

  struct np_data_conf conf = {.key       = "urn",
                              .type      = NP_DATA_TYPE_STR,
                              .data_size = 10};
  np_data_value       val  = {.str = __current_entry.article_id};
  np_set_data(&attr, conf, val);

  char               *mime_type          = "application/json";
  struct np_data_conf data_conf_mimetype = {.type = NP_DATA_TYPE_STR,
                                            .data_size =
                                                strnlen(mime_type, 20)};
  strncpy(data_conf_mimetype.key, "mime_type", 255);
  np_set_data(attr, data_conf_mimetype, (np_data_value){.str = mime_type});

  uint8_t i = 0;
  // while (__current_entry.section_names[i] != NULL)
  // {
  // np_data_conf conf = { .key="urn" , .type=NP_DATA_TYPE_STR,
  // .data_size=strnlen(__current_entry.section_names[i], 255) }; np_data_value
  // val = { .str = __current_entry.section_names[i] }; np_set_data(&attr, conf,
  // val);
  // }

  i = 0;
  while (i < 11 && __current_entry.abstract_text[i] != NULL) {
    np_searchentry_t *se = calloc(1, sizeof(np_searchentry_t));
    if (np_create_searchentry(__context,
                              se,
                              __current_entry.abstract_text[i],
                              &attr)) {
      fprintf(stdout, ".");
      np_search_add_entry(__context, se);
    }
    i++;
  }
  fprintf(stdout, "\n");

  // clean up
  memset(__current_entry.article_id, 0, 11);
  i = 0;
  while (i < 11 && __current_entry.abstract_text[i] != NULL) {
    free(__current_entry.abstract_text[i]);
    i++;
  }
  i = 0;
  while (i < 11 && __current_entry.section_names[i] != NULL) {
    free(__current_entry.section_names[i]);
    i++;
  }

  __indent--;

  // printf("map close '}'\n");
  // for (uint8_t x = 0; x <= __indent; x++) printf("  ");
  return 1;
}
static int test_yajl_start_array(void *ctx) {
  // for (uint8_t x = 0; x <= __indent; x++) printf("  ");
  __indent++;
  // printf("array open '['\n");
  return 1;
}
static int test_yajl_end_array(void *ctx) {
  __pubmed_array_index = 0;

  __indent--;
  // for (uint8_t x = 0; x <= __indent; x++) printf("  ");
  // printf("array close ']'\n");
  return 1;
}

static yajl_callbacks callbacks = {test_yajl_null,
                                   NULL, // test_yajl_boolean,
                                   NULL, // test_yajl_integer,
                                   NULL, // test_yajl_double,
                                   NULL,
                                   test_yajl_string,
                                   test_yajl_start_map,
                                   test_yajl_map_key,
                                   test_yajl_end_map,
                                   test_yajl_start_array,
                                   test_yajl_end_array};

int main(int argc, char **argv) {
  int ret = 0;

  char *realm = NULL;
  char *code  = NULL;

  int   no_threads = 9;
  char *j_key      = NULL;
  char *proto      = "udp4";
  char *port       = NULL;
  char *hostname   = NULL;
  char *dns_name   = NULL;
  int   level      = -2;
  char *logpath    = ".";

  example_user_context *user_context;
  if ((user_context = parse_program_args(__FILE__,
                                         argc,
                                         argv,
                                         &no_threads,
                                         &j_key,
                                         &proto,
                                         &port,
                                         &hostname,
                                         &dns_name,
                                         &level,
                                         &logpath,
                                         "[-r realmname]",
                                         "r:",
                                         &realm,
                                         &code)) == NULL) {
    exit(EXIT_FAILURE);
  }

  struct np_settings settings;
  np_default_settings(&settings);
  settings.n_threads = 5;

  snprintf(settings.log_file,
           255,
           "%s%s_%s.log",
           logpath,
           "/neuropil_search_node_2",
           port);
  settings.log_level = 7U;

  np_context *ac = np_new_context(&settings);
  __context      = ac;

  np_set_userdata(ac, user_context);
  np_ctx_cast(ac);

  np_example_print(context, stdout, "logpath: %s\n", settings.log_file);

  np_example_save_and_load_identity(context);

  if (NULL != realm) {
    np_set_realm_name(context, realm);
    np_enable_realm_client(context);
  }

  np_set_authorize_cb(context, authorize);
  np_set_authenticate_cb(context, authenticate);

  if (np_ok != np_listen(context, proto, "localhost", atoi(port), dns_name)) {
    np_example_print(context,
                     stderr,
                     "ERROR: Node could not listen to %s:%s:%s",
                     proto,
                     hostname,
                     port);
  } else {
    // __np_example_helper_loop(context); // for the fancy ncurse display
    fprintf(stdout,
            "INFO : node is listening on %s\n",
            np_get_connection_string(context));

    log_debug_msg(LOG_DEBUG, "starting http module");
    _np_http_init(context, "localhost", "31415");

    np_id file_seed;
    memset(file_seed, 0, NP_FINGERPRINT_BYTES);

    log_debug_msg(LOG_DEBUG, "starting file server");
    // np_files_open(context, file_seed, "", false);
    np_sysinfo_enable_server(context);

    log_debug_msg(LOG_DEBUG, "starting search module");
    np_search_settings_t *search_settings = np_default_searchsettings();
    search_settings->enable_remote_peers  = false;
    search_settings->analytic_mode        = SEARCH_ANALYTICS_ON;
    np_searchnode_init(context, search_settings);
    fprintf(stdout, "initialized searchnode ...\n");

    log_debug_msg(LOG_DEBUG, "starting job queue");
    if (np_ok != np_run(context, 0.001)) {
      np_example_print(context, stderr, "ERROR: Node could not run");
      exit(1);
    }

    if (NULL != j_key) {
      np_example_print(context, stdout, "try to join %s\n", j_key);
      // join previous node
      if (np_ok != np_join(context, j_key)) {
        np_example_print(context, stderr, "ERROR: Node could not join");
      }
    }

    yajl_handle hand;
    yajl_status stat;
    hand = yajl_alloc(&callbacks, NULL, NULL);
    yajl_config(hand, yajl_allow_comments, 1);

    // FILE* file = fopen("./pubmed-dataset/test.txt", "r");
    FILE *file = fopen("./pubmed-dataset/train.txt", "r");
    if (file == NULL) {
      log_msg(LOG_ERROR, "--------- could not read pubmed dataset");
      abort();
    }
    size_t         bufSize = 10240;
    unsigned char  fileData[bufSize];
    enum np_return np_ret = np_ok;
    size_t         rd     = 0;
    log_msg(LOG_ERROR, "--------- started indexing of pubmed dataset");
    while (0 < (rd = fread((void *)fileData, 1, bufSize - 1, file))) {
      fileData[bufSize] = '\0';
      // fprintf(stdout, "read %u bytes\n", rd);
      stat = yajl_parse(hand, fileData, rd);

      if (stat != yajl_status_ok) {
        fprintf(stdout, "!!! parsing error !!!");
        exit(0);
      }
      // __np_example_helper_loop(context);
      np_run(context, 0.0);
    }
    log_msg(LOG_ERROR, "--------- stopped indexing of pubmed dataset");

    // {
    if (ferror(file)) {
      fprintf(stdout, "error %s", strerror(errno));
    };
    if (feof(file)) {
      fprintf(stdout, "eof");
    };
    // }

    stat = yajl_complete_parse(hand);
    yajl_free(hand);
    fclose(file);

    fprintf(stdout, "!!!! continue !!!!");
    fflush(stdout);

    while (np_ok == np_run(context, 0.0)) {
      // weird other stuff happeneing here?
      // for now: just sleep to prevent cpu dos
      np_time_sleep(0.0);
    }

    np_example_print(context, stderr, "Closing Node");

    // np_searchnode_destroy(context); // handled via np_add_shutdown_cb
    np_destroy(context, true);
  }

  return ret;
}

bool authorize(np_context *ac, struct np_token *id) {
  // TODO: Make sure that id->public_key is an authenticated peer!
  fprintf(stdout,
          "authz %s from %02X%02X%02X%02X%02X%02X%02X: "
          "%02X%02X%02X%02X%02X%02X%02X...\n",
          id->subject,
          id->issuer[0],
          id->issuer[1],
          id->issuer[2],
          id->issuer[3],
          id->issuer[4],
          id->issuer[5],
          id->issuer[6],
          id->public_key[0],
          id->public_key[1],
          id->public_key[2],
          id->public_key[3],
          id->public_key[4],
          id->public_key[5],
          id->public_key[6]);

  if (strncmp(id->subject, "files/", 6) == 0) {
    np_files_send_authorized(ac, id);
  }
  // TODO: Make sure that id->public_key is the intended sender!
  return true;
}

bool authenticate(np_context *ac, struct np_token *id) {
  // TODO: Make sure that id->public_key is an authenticated peer!
  fprintf(stdout,
          "authn %s from %02X%02X%02X%02X%02X%02X%02X: "
          "%02X%02X%02X%02X%02X%02X%02X...\n",
          id->subject,
          id->issuer[0],
          id->issuer[1],
          id->issuer[2],
          id->issuer[3],
          id->issuer[4],
          id->issuer[5],
          id->issuer[6],
          id->public_key[0],
          id->public_key[1],
          id->public_key[2],
          id->public_key[3],
          id->public_key[4],
          id->public_key[5],
          id->public_key[6]);

  // TODO: Make sure that id->public_key is the intended sender!
  return true;
}
