//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "np_http.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../framework/http/htparse.c"
#include "../framework/http/htparse.h"
#include "inttypes.h"
#include "parson/parson.h"
#include "sys/socket.h"

#include "neuropil.h"
#include "neuropil_log.h"

#include "../framework/sysinfo/np_sysinfo.h"
#include "util/np_event.h"
#include "util/np_list.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_dhkey.h"
#include "np_evloop.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_network.h"
#include "np_node.h"
#include "np_route.h"
#include "np_statistics.h"
#include "np_threads.h"
#include "np_util.h"

static char *HTML_NOT_IMPLEMENTED =
    "<html><head><title>neuropil</title></head><body>not "
    "implemented</body></html>";

#define MODULE_NOT_READY(MODULE)                                               \
  "<html><head><title>neuropil</title></head><body>module " TO_STRING(         \
      MODULE) " not ready. Please initiate module first</body></html>"
#define CHECK_PATH(prefix)                                                     \
  (strncmp("/" prefix, client->ht_request.ht_path, strlen(prefix)) == 0)
#define HTTP_CRLF "\r\n"

typedef enum np_http_status_e {
  UNUSED = 0,
  ACCEPTED,
  CONNECTED,
  REQUEST,
  PROCESSING,
  RESPONSE,
  SHUTDOWN
} np_http_status_e;

struct np_http_client_s {
  int          client_fd;
  struct ev_io client_watcher_in;
  struct ev_io client_watcher_out;

  // http parser and callbacks
  htparser *parser;
  // http request structure
  ht_request_t ht_request;
  // http response structure
  ht_response_t ht_response;
  // global status and last update time
  np_http_status_e status;
  np_state_t      *context;
};

typedef struct np_http_client_s np_http_client_t;
typedef np_http_client_t       *np_http_client_ptr;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
NP_SLL_GENERATE_PROTOTYPES(np_http_client_ptr);
NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_http_client_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_http_client_ptr);
#pragma clang diagnostic pop

np_module_struct(http) {
  np_context *context;
  // network io handling
  np_network_t *network;

  np_sll_t(np_http_client_ptr, clients);

  htparse_hooks *hooks;
  np_tree_t     *user_hooks;
};

typedef struct http_return_t {
  const char *text;
  int         http_code;
} http_return_t;

http_return_t http_return_codes[] = {
    {               "HTTP_NO_RESPONSE",   0},
    {             "HTTP_CODE_CONTINUE", 100},
    {                   "HTTP_CODE_OK", 200},
    {              "HTTP_CODE_CREATED", 201},
    {          "HTTP_CODE_NO_Accepted", 202},
    {           "HTTP_CODE_NO_CONTENT", 204},
    {      "HTTP_CODE_PARTIAL_CONTENT", 206},
    {         "HTTP_CODE_MULTI_STATUS", 207},
    {    "HTTP_CODE_MOVED_TEMPORARILY", 302},
    {         "HTTP_CODE_NOT_MODIFIED", 304},
    {          "HTTP_CODE_BAD_REQUEST", 400},
    {         "HTTP_CODE_UNAUTHORIZED", 401},
    {            "HTTP_CODE_FORBIDDEN", 403},
    {            "HTTP_CODE_NOT_FOUND", 404},
    {   "HTTP_CODE_METHOD_NOT_ALLOWED", 405},
    {     "HTTP_CODE_REQUEST_TIME_OUT", 408},
    {                 "HTTP_CODE_GONE", 410},
    { "HTTP_CODE_REQUEST_URI_TOO_LONG", 414},
    {               "HTTP_CODE_LOCKED", 423},
    {"HTTP_CODE_INTERNAL_SERVER_ERROR", 500},
    {      "HTTP_CODE_NOT_IMPLEMENTED", 501},
    {  "HTTP_CODE_SERVICE_UNAVAILABLE", 503}
};

typedef struct _np_http_callback_s {
  _np_http_callback_func_t callback;
  void                    *user_arg;
} _np_http_callback_t;

int _np_http_on_msg_begin(htparser *parser) {
  // pthread_mutex_lock(__http_mutex);
  np_http_client_t *client = (np_http_client_t *)parser->userdata;
  client->status           = REQUEST;

  return 0;
}

int _np_http_query_args(htparser *parser, const char *data, size_t in_len) {
  char *key = NULL;
  char *val = NULL;

  np_http_client_t *client = (np_http_client_t *)parser->userdata;

  if (NULL != client->ht_request.ht_query_args)
    np_tree_clear(client->ht_request.ht_query_args);
  if (NULL == client->ht_request.ht_query_args)
    client->ht_request.ht_query_args = np_tree_create();
  char *query_string = NULL, *to_parse = NULL;
  query_string = to_parse = strndup(data, in_len);
  char *kv_pair           = strsep(&to_parse, "&=");

  while (NULL != kv_pair) {
    if (NULL == key) {
      key = strndup(kv_pair, strlen(kv_pair));
    } else {
      val = strndup(kv_pair, strlen(kv_pair));
      np_tree_insert_str(client->ht_request.ht_query_args,
                         key,
                         np_treeval_new_s(val));
      free(key);
      free(val);
      key = NULL;
      val = NULL;
    }
    kv_pair = strsep(&to_parse, "&=");
  }
  free(query_string);
  return 0;
}

int _np_http_on_hdrs_begin(htparser *parser) {
  np_http_client_t *client = (np_http_client_t *)parser->userdata;

  if (NULL != client->ht_request.ht_header)
    np_tree_clear(client->ht_request.ht_header);
  if (NULL == client->ht_request.ht_header)
    client->ht_request.ht_header = np_tree_create();
  return 0;
}

int _np_http_hdr_key(htparser *parser, const char *data, size_t in_len) {
  np_http_client_t *client = (np_http_client_t *)parser->userdata;

  if (NULL != client->ht_request.current_key)
    free(client->ht_request.current_key);
  client->ht_request.current_key = strndup(data, in_len);
  return 0;
}

int _np_http_hdr_value(htparser        *parser,
                       const char      *data,
                       NP_UNUSED size_t in_len) {
  np_http_client_t *client = (np_http_client_t *)parser->userdata;

  np_tree_insert_str(client->ht_request.ht_header,
                     client->ht_request.current_key,
                     np_treeval_new_s((char *)data));

  free(client->ht_request.current_key);
  client->ht_request.current_key = NULL;

  return 0;
}

int _np_http_path(htparser *parser, const char *data, size_t in_len) {
  np_http_client_t *client = (np_http_client_t *)parser->userdata;
  if (NULL != client->ht_request.ht_path) free(client->ht_request.ht_path);

  client->ht_request.ht_path = strndup(data, in_len);

  return 0;
}

int _np_http_body(htparser *parser, const char *data, size_t in_len) {
  np_http_client_t *client = (np_http_client_t *)parser->userdata;

  if (NULL != client->ht_request.ht_body) free(client->ht_request.ht_body);
  client->ht_request.ht_body = strndup(data, in_len);

  return 0;
}

int _np_http_on_msg_complete(htparser *parser) {

  np_http_client_t *client     = (np_http_client_t *)parser->userdata;
  client->ht_request.ht_method = htparser_get_method(parser);
  client->ht_request.ht_length = htparser_get_content_length(parser);

  client->status = PROCESSING;

  return 0;
}

void _np_http_dispatch(np_state_t *context, np_http_client_t *client) {

  assert(PROCESSING == client->status);

  char key[128];
  snprintf(key,
           128,
           "%d:%s",
           client->ht_request.ht_method,
           client->ht_request.ht_path + 1);

  log_msg(LOG_DEBUG, NULL, "lookup   of http callback for key %s", key);

  client->ht_response.ht_header = np_tree_create();
  np_tree_insert_str(client->ht_response.ht_header,
                     "Access-Control-Allow-Origin",
                     np_treeval_new_s("*"));
  np_tree_insert_str(client->ht_response.ht_header,
                     "Access-Control-Allow-Methods",
                     np_treeval_new_s("GET"));

  np_tree_elem_t *user_callback =
      np_tree_find_str(np_module(http)->user_hooks, key);
  if (NULL != user_callback) {
    client->ht_response.cleanup_body = true;

    _np_http_callback_t *callback_data =
        (_np_http_callback_t *)user_callback->val.value.v;
    client->ht_response.ht_status =
        callback_data->callback(&client->ht_request,
                                &client->ht_response,
                                callback_data->user_arg);

    client->status = RESPONSE;
  } else {
    switch (client->ht_request.ht_method) {
    case (htp_method_GET): {
      uint32_t        buf_max = 8000;
      char            buffer[buf_max];
      uint32_t        len       = snprintf(buffer,
                              buf_max,
                              "{ \"status\":\"not_found\", \"requestd_path\": "
                                           "\"%s\", \"available_paths\": [",
                              key);
      np_tree_elem_t *iter_tree = NULL;
      RB_FOREACH (iter_tree, np_tree_s, np_module(http)->user_hooks) {
        len += snprintf(buffer + len,
                        buf_max - len,
                        "\"%s\",",
                        iter_tree->key.value.s);
      }

      snprintf(buffer + len, buf_max - len, "]}");

      client->ht_response.ht_body   = strndup(buffer, buf_max);
      client->ht_response.ht_status = HTTP_CODE_NOT_FOUND;
      np_tree_insert_str(client->ht_response.ht_header,
                         "X-Content-Type-Options",
                         np_treeval_new_s("nosniff"));
      np_tree_insert_str(client->ht_response.ht_header,
                         "Content-Type",
                         np_treeval_new_s("application/json"));

      client->ht_response.cleanup_body = true;
      client->status                   = RESPONSE;
      break;
    }
    default: {
      client->ht_response.ht_body      = strdup(HTML_NOT_IMPLEMENTED);
      client->ht_response.ht_header    = np_tree_create();
      client->ht_response.ht_status    = HTTP_CODE_NOT_IMPLEMENTED;
      client->ht_response.cleanup_body = false;
      client->status                   = RESPONSE;
    }
    }
  }
}

void _np_http_write_callback(struct ev_loop  *loop,
                             NP_UNUSED ev_io *ev,
                             int              event_type) {
  np_state_t       *context = ev_userdata(loop);
  np_http_client_t *client  = (np_http_client_t *)ev->data;

  if ((FLAG_CMP(event_type, EV_WRITE) && !FLAG_CMP(event_type, EV_ERROR)) &&
      RESPONSE == client->status) {
    log_debug(LOG_HTTP, NULL, "start writing response");
    // create http reply
    char data[2048];

    char *ht_body = client->ht_response.ht_body;
    // HTTP start
    int pos =
        snprintf(data,
                 2048,
                 "%s %d %s" HTTP_CRLF,
                 "HTTP/1.1",
                 http_return_codes[client->ht_response.ht_status].http_code,
                 http_return_codes[client->ht_response.ht_status].text);
    // add content length header
    uint32_t s_contentlength = strlen(ht_body);
    char     body_length[255];
    snprintf(body_length, 254, "%" PRIu32, s_contentlength);
    np_tree_insert_str(client->ht_response.ht_header,
                       "Content-Length",
                       np_treeval_new_s(body_length));
    np_tree_insert_str(client->ht_response.ht_header,
                       "Content-Type",
                       np_treeval_new_s("application/json"));
    // add keep alive header
    np_tree_insert_str(
        client->ht_response.ht_header,
        "Connection",
        np_treeval_new_s(htparser_should_keep_alive(client->parser)
                             ? "Keep-Alive"
                             : "close"));

    // HTTP header
    np_tree_elem_t *iter = RB_MIN(np_tree_s, client->ht_response.ht_header);
    while (NULL != iter) {
      pos += snprintf(data + pos,
                      snprintf(NULL,
                               0,
                               "%s: %s" HTTP_CRLF,
                               np_treeval_to_str(iter->key, NULL),
                               np_treeval_to_str(iter->val, NULL)) +
                          1,
                      "%s: %s" HTTP_CRLF,
                      np_treeval_to_str(iter->key, NULL),
                      np_treeval_to_str(iter->val, NULL));
      iter = RB_NEXT(np_tree_s, np_module(http)->ht_response.ht_header, iter);
    }
    pos +=
        snprintf(data + pos, snprintf(NULL, 0, "" HTTP_CRLF) + 1, "" HTTP_CRLF);
    // send header
#ifdef MSG_NOSIGNAL
    send(client->client_fd, data, pos, MSG_NOSIGNAL);
#else
    send(client->client_fd, data, pos, 0);
#endif
    np_tree_free(client->ht_response.ht_header);

    log_debug(LOG_HTTP, NULL, "send http header success");

    // HTTP body
    // memset(data, 0, 2048);

    uint32_t bytes_send = 0;
    double   t1         = np_time_now();
    int      retry      = 0;
    while (bytes_send < s_contentlength) {
      if ((np_time_now() - t1) >= 30) {
        log_debug(LOG_HTTP, NULL, "http timeout");
        break;
      } else if (retry > 3) {
        log_debug(LOG_HTTP, NULL, "http too many errors");
        break;
      }

#ifdef MSG_NOSIGNAL
      int send_return = send(client->client_fd,
                             ht_body + bytes_send,
                             fmin(2048, s_contentlength - bytes_send),
                             MSG_NOSIGNAL);
#else
      int send_return = send(client->client_fd,
                             ht_body + bytes_send,
                             fmin(2048, s_contentlength - bytes_send),
                             0);
#endif

      if (send_return >= 0) {
        bytes_send += send_return;
        log_debug(LOG_HTTP, NULL, "send http body part success");
      } else {
        // we may need to wait for the output buffer to be free
        if (EAGAIN != errno) {
          log_msg(LOG_HTTP | LOG_WARNING,
                  NULL,
                  "Sending http data error. %s",
                  strerror(errno));
          retry++;
        }
      }
    }

    if (bytes_send == s_contentlength) {
      log_debug(LOG_HTTP, NULL, "send http body success");
    } else {
      log_warn(LOG_HTTP,
               NULL,
               "send http body NO success (%" PRIu32 "/%" PRIu32 ")",
               bytes_send,
               s_contentlength);
    }

    if (client->ht_response.cleanup_body) {
      free(ht_body);
    }
    client->status = CONNECTED;
  }
}

void _np_http_read_callback(struct ev_loop  *loop,
                            NP_UNUSED ev_io *ev,
                            int              event_type) {
  np_state_t       *context = ev_userdata(loop);
  np_http_client_t *client  = (np_http_client_t *)ev->data;

  if ((event_type & EV_READ) == EV_READ &&
      (event_type & EV_ERROR) != EV_ERROR && CONNECTED <= client->status &&
      REQUEST >= client->status) {
    char data[2048];
    /* receive the new data */
    int16_t in_msg_len = recv(client->client_fd, data, 2048, 0);

    if (0 == in_msg_len) {
      // tcp disconnect
      log_debug(LOG_HTTP, NULL, "received disconnect");
      close(client->client_fd);
      ev_io_stop(EV_A_ & client->client_watcher_in);
      ev_io_stop(EV_A_ & client->client_watcher_out);
      client->status = UNUSED;
    }

    if (0 > in_msg_len) {
      log_msg(LOG_ERROR, NULL, "http receive failed: %s", strerror(errno));
      return;
    }

    log_debug(LOG_HTTP, NULL, "parsing http request");
    htparser_run(client->parser, np_module(http)->hooks, data, in_msg_len);
    if (htparser_get_error(client->parser) != htparse_error_none) {
      log_msg(LOG_ERROR, NULL, "error parsing http request");
      client->ht_response.ht_status = HTTP_CODE_BAD_REQUEST;
      client->status                = RESPONSE;
      client->ht_response.ht_header = np_tree_create();
      client->ht_response.ht_body =
          strndup("error parsing http request ...", 255);
    }

    if (PROCESSING == client->status) {
      _np_http_dispatch(context, client);
    }

  } else {
    // log_debug(LOG_MISC, NULL, "local http status now %d, but should be %d or
    // %d", np_module(http)->status, CONNECTED, REQUEST);
  }
}

void _np_http_accept(struct ev_loop  *loop,
                     NP_UNUSED ev_io *ev,
                     NP_UNUSED int    event_type) {
  np_state_t             *context = ev_userdata(loop);
  struct sockaddr_storage from;
  socklen_t               fromlen = sizeof(from);

  np_http_client_t *new_client = calloc(1, sizeof(np_http_client_t));
  CHECK_MALLOC(new_client);

  new_client->parser                   = htparser_new();
  new_client->ht_request.ht_body       = NULL;
  new_client->ht_request.ht_header     = NULL;
  new_client->ht_request.ht_query_args = NULL;
  new_client->ht_request.ht_path       = NULL;
  new_client->ht_request.current_key   = NULL;
  new_client->status                   = UNUSED;
  new_client->context                  = context;

  /*
  if (UNUSED < np_module(http)->status) {	// check if connection expired
      if (new_client->last_update < (ev_time() - __np_http_timeout)) {
          close(new_client);
          // _np_suspend_event_loop();
          ev_io_stop(EV_A_&new_client->client_watcher_in);
          ev_io_stop(EV_A_&new_client->client_watcher_out);
          // _np_resume_event_loop();
          np_module(http)->status = UNUSED;
      }
  }
   */

  if (UNUSED == new_client->status) {
    new_client->client_fd = accept(np_module(http)->network->socket,
                                   (struct sockaddr *)&from,
                                   &fromlen);

    if (new_client->client_fd < 0) {
      free(new_client);

      log_warn(LOG_HTTP,
               NULL,
               "Could not accept http connection. %s",
               strerror(errno));
    } else {
      sll_append(np_http_client_ptr, np_module(http)->clients, new_client);

      htparser_init(new_client->parser, htp_type_request);
      htparser_set_userdata(new_client->parser, new_client);

      // get calling address and port for logging
      char ipstr[255] = {0};
      char port[6]    = {0};

      if (from.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&from;
        getnameinfo((struct sockaddr *)s, sizeof s, ipstr, 255, port, 6, 0);
      } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&from;
        getnameinfo((struct sockaddr *)s, sizeof s, ipstr, 255, port, 6, 0);
      }

      log_debug(LOG_HTTP,
                NULL,
                "received http request from %s:%s (client fd: %" PRIi32 ")",
                ipstr,
                port,
                new_client->client_fd);

      new_client->status = CONNECTED;

      // set non blocking
      int current_flags = fcntl(new_client->client_fd, F_GETFL);
      current_flags |= O_NONBLOCK;
      fcntl(new_client->client_fd, F_SETFL, current_flags);

      _np_event_suspend_loop_http(context);

      ev_io_init(&new_client->client_watcher_in,
                 _np_http_read_callback,
                 new_client->client_fd,
                 EV_READ);
      ev_io_init(&new_client->client_watcher_out,
                 _np_http_write_callback,
                 new_client->client_fd,
                 EV_WRITE);

      if (new_client->client_watcher_in.data)
        free(new_client->client_watcher_in.data);
      new_client->client_watcher_in.data = new_client;
      if (new_client->client_watcher_out.data)
        free(new_client->client_watcher_out.data);
      new_client->client_watcher_out.data = new_client;

      ev_io_start(EV_A_ & new_client->client_watcher_in);
      ev_io_start(EV_A_ & new_client->client_watcher_out);

      _np_event_resume_loop_http(context);
    }

  } else {
    log_debug(LOG_HTTP, NULL, "http connection attempt not accepted");
  }
}

void _np_http_module_init(np_state_t *context) {
  if (!np_module_initiated(http)) {
    np_module_malloc(http);

    CHECK_MALLOC(_module);

    _module->user_hooks = np_tree_create();
    _module->network    = NULL;

    _module->hooks = (htparse_hooks *)malloc(sizeof(htparse_hooks));
    CHECK_MALLOC(_module->hooks);

    // define callbacks
    _module->hooks->on_msg_begin = _np_http_on_msg_begin;
    _module->hooks->method       = NULL;
    _module->hooks->scheme       = NULL; /* called if scheme is found */
    _module->hooks->hostname     = NULL;
    _module->hooks->host =
        NULL; /* called if a host was in the request scheme */
    _module->hooks->port =
        NULL; /* called if a port was in the request scheme */
    _module->hooks->path = _np_http_path; /* only the path of the uri */
    _module->hooks->args =
        _np_http_query_args;    /* only the arguments of the uri */
    _module->hooks->uri = NULL; /* the entire uri including path/args */
    _module->hooks->on_hdrs_begin    = _np_http_on_hdrs_begin;
    _module->hooks->hdr_key          = _np_http_hdr_key;
    _module->hooks->hdr_val          = _np_http_hdr_value;
    _module->hooks->on_hdrs_complete = NULL;
    _module->hooks->on_new_chunk = NULL; /* called after parsed chunk octet */
    _module->hooks->on_chunk_complete =
        NULL; /* called after single parsed chunk */
    _module->hooks->on_chunks_complete =
        NULL; /* called after all parsed chunks processed */
    _module->hooks->body            = _np_http_body;
    _module->hooks->on_msg_complete = _np_http_on_msg_complete;
  }
}

bool _np_http_init(np_state_t *context, char *in_domain, char *port) {
  char *domain = in_domain;
  if (in_domain == NULL) {
    domain = strdup("localhost");
  }

  if (port == NULL) port = TO_STRING(HTTP_PORT);
  if (!np_module_initiated(http)) {
    _np_http_module_init(context);
  }
  np_module_var(http);
  if (_module->network == NULL) {
    sll_init(np_http_client_ptr, _module->clients);

    np_new_obj(np_network_t, _module->network);
    _np_network_init(_module->network,
                     true,
                     TCP | IPv4,
                     domain,
                     port,
                     context->settings->max_msgs_per_sec,
                     -1,
                     UNKNOWN_PROTO);
    np_ref_obj(np_network_t, _module->network, ref_obj_creation);

    // _np_network_enable(_module->network);

    if (NULL == _module->network || false == _module->network->initialized)
      return false;

    _np_event_suspend_loop_http(context);
    EV_P = _np_event_get_loop_http(context);
    ev_io_stop(EV_A_ & _module->network->watcher_in);
    ev_io_init(&_module->network->watcher_in,
               _np_http_accept,
               _module->network->socket,
               EV_READ);

    if (_module->network->watcher_in.data)
      free(_module->network->watcher_in.data);
    _module->network->watcher_in.data = _module;
    ev_io_start(EV_A_ & _module->network->watcher_in);
    _np_event_resume_loop_http(context);

    np_jobqueue_submit_event_periodic(context,
                                      NP_PRIORITY_LOWEST,
                                      0.0,
                                      MISC_READ_HTTP_SEC,
                                      _np_events_read_http,
                                      "_np_events_read_http");
  }
  if (in_domain == NULL) {
    free(domain);
  }
  return true;
}

void _np_http_destroy(np_state_t *context) {
  if (np_module_initiated(http)) {
    np_module_var(http);

    EV_P = _np_event_get_loop_http(context);
    _np_event_suspend_loop_http(context);
    ev_io_stop(EV_A_ & _module->network->watcher_in);

    sll_iterator(np_http_client_ptr) iter = sll_first(_module->clients);
    while (iter != NULL) {
      np_http_client_t *client = iter->val;
      client->status           = SHUTDOWN;

      ev_io_stop(EV_A_ & client->client_watcher_in);
      ev_io_stop(EV_A_ & client->client_watcher_out);
      close(iter->val->client_fd);

      if (client->ht_request.ht_body) free(client->ht_request.ht_body);
      if (client->ht_request.ht_path) free(client->ht_request.ht_path);
      if (client->ht_request.current_key) free(client->ht_request.current_key);
      if (client->ht_request.ht_header)
        np_tree_free(client->ht_request.ht_header);
      if (client->ht_request.ht_query_args)
        np_tree_free(client->ht_request.ht_query_args);

      free(client->parser);
      free(client);
      sll_next(iter);
    }
    sll_free(np_http_client_ptr, _module->clients);

    _np_event_resume_loop_http(context);

    np_tree_free(_module->user_hooks);

    free(np_module(http)->hooks);

    // _np_network_disable(np_module(http)->network);
    np_unref_obj(np_network_t, _module->network, ref_obj_creation);
    // np_module(http)->network->watcher_in.data = NULL;

    np_module_free(http);
  }
}

void _np_add_http_callback(np_state_t              *context,
                           const char              *path,
                           htp_method               method,
                           void                    *user_args,
                           _np_http_callback_func_t func) {
  if (!np_module_initiated(http)) {
    _np_http_module_init(context);
  }
  char key[128];
  snprintf(key, 128, "%d:%s", method, path);
  log_msg(LOG_DEBUG, NULL, "register of http callback for key %s", key);

  _np_http_callback_t *callback_data = malloc(sizeof(_np_http_callback_t));
  CHECK_MALLOC(callback_data);

  callback_data->user_arg = user_args;
  callback_data->callback = func;
  np_tree_insert_str(np_module(http)->user_hooks,
                     key,
                     np_treeval_new_v(callback_data));
}
