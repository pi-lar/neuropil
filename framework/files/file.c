//
// neuropil is copyright 2016-2022 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file
// for details
//
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// neuropil core include files
#include "util/np_serialization.h"
#include "util/np_tree.h"

#include "np_dhkey.h"
#include "np_legacy.h"
#include "np_threads.h"

// neuropil framework include files
#include "files/file.h"
#include "http/urldecode.h"

#include "http/np_http.h"
#include "search/np_search.h"

// define max memory we will allocate for mmap'ed files
// TODO: only load file content up to the defined upper max (lazy loading)
#define NP_FILE_MEMORY_MAX 1024 * 1000 * 64 // 64 MB
#define SHARE_FILES        "share_file"

enum mime_types {
  application_graphql = 0,
  application_javascript,
  application_json,
  application_ld_json,
  application_pdf,
  application_xml,
  application_zip,
  audio_mpeg,
  audio_ogg,
  image_gif,
  image_jpeg,
  image_png,
  text_css,
  text_csv,
  text_html,
  text_plain,
  mime_type_MAX
};

static const char *mime_type_str[] = {"application/graphql",
                                      "application/javascript",
                                      "application/json",
                                      "application/ld+json",
                                      "application/pdf",
                                      "application/xml",
                                      "application/zip",
                                      "audio/mpeg",
                                      "audio/ogg",
                                      "image/gif",
                                      "image/jpeg",
                                      "image/png",
                                      "text/css",
                                      "text/csv",
                                      "text/html",
                                      "text/plain",
                                      NULL};

static const char *mime_type_suffix[] = {".graphql",
                                         ".js",
                                         ".json",
                                         ".ld+json",
                                         ".pdf",
                                         ".xml",
                                         ".zip",
                                         ".mpeg",
                                         ".ogg",
                                         ".gif",
                                         ".jpeg",
                                         ".png",
                                         ".css",
                                         ".csv",
                                         ".html",
                                         ".txt",
                                         NULL};

enum mime_types __find_mime_type(const char *filename) {
  const char *suffix = strrchr(filename, '.');
  for (uint8_t i = 0; i < mime_type_MAX; i++) {
    if (NULL != suffix &&
        strnlen(suffix, 5) == strnlen(mime_type_suffix[i], 5) &&
        strncmp(suffix, mime_type_suffix[i], strnlen(suffix, 3)) == 0)
      return i;
  }
  return text_plain;
}
typedef void (*send_cb)(np_state_t *ac, const char *id);

struct np_common_info {
  np_id           id;
  char            subject[76];
  char           *name;
  struct timespec last_modified;
  char            cwd[PATH_MAX];

  send_cb send_entry;
};

struct np_file_info {
  struct np_common_info ci;

  bool    loaded;
  void   *mmap_region;
  off_t   file_size;
  uint8_t mime_type;
  int     fd;
};

struct np_dir_info {
  struct np_common_info ci;

  uint16_t dir_entries_counter;
  np_id  **dir_entries;

  uint16_t file_entries_counter;
  np_id  **file_entries;
};

struct np_files {
  np_context *context;
  np_id       seed;

  np_tree_t    *_file_tree;
  np_spinlock_t _lock;

  size_t bytes_in_memory;
};
/*
urn:files:filename => HF1
urn:files:dir1 => HD1
urn:files:dir1:filename1 => HD1 + HF1
urn:files:dir1:filename2 => HD1 + HF2
urn:files:dir1:dir2 => HD1 + HD2
urn:files:dir1:dir2:filename1 => HD1 + HD2 + HF1

urn:files:<hash>

{
    hash
    path+name
    base64(name)
}
*/

static struct np_files __files        = {0};
static uint8_t         __indent_level = 0;
#define __indent_str "  "

static JSON_Value *__np_generate_error_json(const char *error,
                                            const char *details) {
  log_trace_msg(LOG_TRACE | LOG_HTTP,
                "start: JSON_Value* _np_generate_error_json(const char* "
                "error,const char* details) {");
  JSON_Value *ret = json_value_init_object();

  json_object_set_string(json_object(ret), "error", error);
  json_object_set_string(json_object(ret), "details", details);

  return ret;
}

void __load_file(struct np_file_info *info) {
  // for(uint8_t x = 0; x < __indent_level; x++) fprintf(stdout, __indent_str);
  // fprintf(stdout, "loading file %s / %s \n", info->ci.name,
  // info->ci.subject);
  np_context *context = __files.context;

  char cwd[PATH_MAX];
  getcwd(cwd, sizeof(cwd));

  chdir(info->ci.cwd);

  int fd = open(info->ci.name, O_RDONLY);
  if (-1 == fd) {
    log_msg(LOG_WARNING, "unable to open file (%s)\n", strerror(errno));
    close(fd);
    return;
  } else {
    info->fd = fd;
  }

  void *_content =
      mmap(NULL, info->file_size, PROT_READ, MAP_SHARED, info->fd, 0);
  if (_content == MAP_FAILED) {
    log_msg(LOG_WARNING, "unable to mmap file (%s)\n", strerror(errno));
    close(fd);
    return;
  }
  info->loaded      = true;
  info->mmap_region = _content;

  __files.bytes_in_memory += info->file_size;

  chdir(cwd);
}

void __close_file(struct np_file_info *info) {
  // for(uint8_t x = 0; x < __indent_level; x++) fprintf(stdout, __indent_str);
  // fprintf(stdout, "closing file %s / %s \n", info->ci.name,
  // info->ci.subject);

  if (info->mmap_region) {
    munmap(info->mmap_region, info->file_size);
  }
  if (0 < info->fd) {
    close(info->fd);
  }

  info->fd          = -1;
  info->loaded      = false;
  info->mmap_region = NULL;
  info->file_size   = 0;

  __files.bytes_in_memory -= info->file_size;
}

void __create_file_info(struct np_file_info *_info,
                        np_tree_t           *dir_tree,
                        bool                 include_content) {
  ASSERT(_info != NULL, "no dir info given");
  ASSERT(dir_tree != NULL, "no target tree given");

  char *s = NULL;
  if (((s = getenv("LC_ALL")) && *s) || ((s = getenv("LC_CTYPE")) && *s) ||
      ((s = getenv("LANG")) && *s)) {
  }

  char id_str[65];
  np_tree_insert_str(dir_tree,
                     "np_id",
                     np_treeval_new_s(np_id_str(id_str, (_info->ci.id))));
  np_tree_insert_str(dir_tree, "name", np_treeval_new_s(_info->ci.name));
  np_tree_insert_str(dir_tree, "path", np_treeval_new_s(_info->ci.cwd));
  np_tree_insert_str(dir_tree,
                     "last_modified",
                     np_treeval_new_ul(_info->ci.last_modified.tv_sec));
  np_tree_insert_str(dir_tree, "subject", np_treeval_new_s(_info->ci.subject));

  np_tree_insert_str(dir_tree,
                     "mimetype",
                     np_treeval_new_s(mime_type_str[_info->mime_type]));
  // np_tree_insert_str(dir_tree, "encoding", np_treeval_new_s(s));

  if (include_content && _info->loaded)
    np_tree_insert_str(
        dir_tree,
        "content",
        np_treeval_new_bin(_info->mmap_region, _info->file_size));
}

void __create_dir_info(struct np_dir_info *_info, np_tree_t *dir_tree) {
  ASSERT(_info != NULL, "no dir info given");
  ASSERT(dir_tree != NULL, "no target tree given");

  char id_str[65];
  np_tree_insert_str(dir_tree,
                     "np_id",
                     np_treeval_new_s(np_id_str(id_str, (_info->ci.id))));
  np_tree_insert_str(dir_tree, "name", np_treeval_new_s(_info->ci.name));
  np_tree_insert_str(dir_tree, "path", np_treeval_new_s(_info->ci.cwd));
  np_tree_insert_str(dir_tree,
                     "last_modified",
                     np_treeval_new_ul(_info->ci.last_modified.tv_sec));
  np_tree_insert_str(dir_tree, "subject", np_treeval_new_s(_info->ci.subject));

  np_tree_t *sub_dirs = np_tree_create();
  for (uint16_t j = 0; j < _info->dir_entries_counter; j++) {
    np_id_str(id_str, (*_info->dir_entries[j]));
    np_tree_insert_int(sub_dirs, j, np_treeval_new_s(id_str));
  }
  if (_info->dir_entries_counter > 0)
    np_tree_insert_str(dir_tree, "directories", np_treeval_new_tree(sub_dirs));

  np_tree_t *sub_files = np_tree_create();
  for (uint16_t j = 0; j < _info->file_entries_counter; j++) {
    np_id_str(id_str, (*_info->file_entries[j]));
    np_tree_insert_int(sub_files, j, np_treeval_new_s(id_str));
  }
  if (_info->file_entries_counter > 0)
    np_tree_insert_str(dir_tree, "files", np_treeval_new_tree(sub_files));

  np_tree_free(sub_dirs);
  np_tree_free(sub_files);
}

int __np_file_handle_http_get_file(ht_request_t  *ht_request,
                                   ht_response_t *ht_response,
                                   void          *user_arg) {
  np_context *context = __files.context;

  uint16_t    length;
  int         http_status = HTTP_CODE_INTERNAL_SERVER_ERROR; // HTTP_CODE_OK
  JSON_Value *json_obj    = NULL;

  if (NULL != ht_request->ht_path) {
    char *file_start = ht_request->ht_path + 1; // without leading '/'

    // fprintf(stdout, "http request for: %s\n", file_start);
    np_tree_elem_t *elem = np_tree_find_str(__files._file_tree, file_start);
    if (NULL != elem) {
      struct np_file_info *_info = (struct np_file_info *)elem->val.value.v;
      bool                 include_content = true;
      if (_info->file_size >= UINT16_MAX) {
        include_content = false;
        // fprintf(stdout, "too large ...");
        // json_obj = __np_generate_error_json("request invalid", "looks like
        // you are using a wrong url ..."); http_status = HTTP_CODE_BAD_REQUEST;
        // goto __json_return__;
      } else if (false == _info->loaded) {
        __load_file(_info);
      }

      // fprintf(stdout, "http request for: %s\n", file_start);
      np_tree_t *file_tree = np_tree_create();

      np_tree_insert_str(ht_response->ht_header,
                         "Content-Type",
                         np_treeval_new_s(mime_type_str[_info->mime_type]));

      __create_file_info(_info, file_tree, include_content);
      http_status = HTTP_CODE_OK;

      JSON_Value *file_in_json = np_tree2json(context, file_tree);
      ht_response->ht_body     = np_json2char(file_in_json, true);
      ht_response->ht_length = strnlen(ht_response->ht_body, UINT16_MAX + 4096);
      http_status            = HTTP_CODE_OK;

      np_tree_free(file_tree);
      json_value_free(file_in_json);

      ht_response->cleanup_body = true;

      __close_file(_info);
    } else {
      // fprintf(stdout, "not in tree");
      json_obj =
          __np_generate_error_json("request invalid",
                                   "looks like you are using a wrong url ...");
      http_status = HTTP_CODE_INTERNAL_SERVER_ERROR;
      // goto __json_return__;
    }
  }

  // by now there should be a response
  if (http_status == HTTP_CODE_INTERNAL_SERVER_ERROR) {
    log_msg(LOG_ERROR, "HTTP return is not defined for this code path");
  }

  if (json_obj != NULL) {
    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "serialise json response");

    np_tree_insert_str(ht_response->ht_header,
                       "Content-Type",
                       np_treeval_new_s(mime_type_str[application_json]));

    ht_response->ht_body   = np_json2char(json_obj, false);
    ht_response->ht_length = strnlen(ht_response->ht_body, 1024);

    json_value_free(json_obj);
  }
  ht_response->ht_status = http_status;

  // by now there should be a response
  if (http_status == HTTP_CODE_INTERNAL_SERVER_ERROR) {
    log_msg(LOG_ERROR, "HTTP return is not defined for this code path");
  }

  return http_status;
}

int __np_file_handle_http_get_dir(ht_request_t  *ht_request,
                                  ht_response_t *ht_response,
                                  void          *user_arg) {
  np_context *context = __files.context;

  int         http_status = HTTP_CODE_INTERNAL_SERVER_ERROR; // HTTP_CODE_OK
  JSON_Value *json_obj    = NULL;

  if (NULL != ht_request->ht_query_args) {
    log_msg(LOG_INFO,
            "have %d query argument(s)",
            ht_request->ht_query_args->size);
    np_tree_elem_t *new_file_or_dir =
        np_tree_find_str(ht_request->ht_query_args, SHARE_FILES);
    if (new_file_or_dir != NULL) {
      char *file_or_dir = urlDecode(new_file_or_dir->val.value.s);
      log_msg(LOG_INFO, "user requested to share file: %s", file_or_dir);
      np_id _zero = {0};
      np_files_open(context, _zero, file_or_dir, false);
      free(file_or_dir);
    }
  }

  if (NULL != ht_request->ht_path) {
    char *file_start = ht_request->ht_path + 1; // without leading '/'

    np_tree_elem_t *elem = np_tree_find_str(__files._file_tree, file_start);
    if (NULL != elem) {
      struct np_dir_info *_info = (struct np_dir_info *)elem->val.value.v;
      log_msg(LOG_INFO,
              "http request for: %s (%d directories / %d files)\n",
              _info->ci.name,
              _info->dir_entries_counter,
              _info->file_entries_counter);
      np_tree_t *dir_tree = np_tree_create();

      __create_dir_info(_info, dir_tree);

      JSON_Value *dir_in_json = np_tree2json(context, dir_tree);
      ht_response->ht_body    = np_json2char(dir_in_json, true);
      ht_response->ht_length  = strnlen(ht_response->ht_body, 4096);
      http_status             = HTTP_CODE_OK;

      np_tree_free(dir_tree);
      json_value_free(dir_in_json);
    } else {
      log_msg(LOG_DEBUG, "not in tree");

      json_obj =
          __np_generate_error_json("request invalid",
                                   "looks like you are using a wrong url ...");
      http_status = HTTP_CODE_INTERNAL_SERVER_ERROR;
      goto __json_return__;
    }
  }

__json_return__:

  if (json_obj != NULL) {
    log_debug_msg(LOG_DEBUG | LOG_SYSINFO, "serialise json response");

    np_tree_insert_str(ht_response->ht_header,
                       "Content-Type",
                       np_treeval_new_s(mime_type_str[application_json]));

    ht_response->ht_body   = np_json2char(json_obj, false);
    ht_response->ht_length = strnlen(ht_response->ht_body, 1024);

    json_value_free(json_obj);
  }
  ht_response->ht_status = http_status;

  // by now there should be a response
  if (http_status == HTTP_CODE_INTERNAL_SERVER_ERROR) {
    log_msg(LOG_ERROR, "HTTP return is not defined for this code path");
  }

  return http_status;
}

void __construct_id(const char *dir_or_filename,
                    np_subject(*subject_id),
                    char (*subject)[76]) {
  np_generate_subject(subject_id,
                      dir_or_filename,
                      strnlen(dir_or_filename, 256));

  char _name_hash[65];
  memset(*subject, 0, 76);
  np_id_str(_name_hash, *subject_id);

  strncat(*subject, "files/", 76);
  strncat(*subject, _name_hash, 76);
}

void __send_dir(np_state_t *ac, const char *id) {
  np_tree_elem_t *elem = np_tree_find_str(__files._file_tree, id);
  if (elem == NULL) return;

  struct np_dir_info *_info    = (struct np_dir_info *)elem->val.value.v;
  np_tree_t          *dir_tree = np_tree_create();

  __create_dir_info(_info, dir_tree);

  size_t buffer_size = np_tree_get_byte_size(dir_tree);
  // np_serializer_add_map_bytesize(dir_tree, &buffer_size);
  unsigned char buffer[buffer_size];
  np_tree2buffer(ac, dir_tree, buffer);

  np_send(ac, _info->ci.subject, buffer, buffer_size);
}

void __send_file(np_state_t *ac, const char *id) {
  np_tree_elem_t *elem = np_tree_find_str(__files._file_tree, id);
  if (elem == NULL) return;

  struct np_file_info *_info = (struct np_file_info *)elem->val.value.v;

  if (false == _info->loaded) __load_file(_info);

  if (true == _info->loaded) {
    // fprintf(stdout, "np request for: %s\n", _info->ci.name);

    np_tree_t *file_tree = np_tree_create();
    __create_file_info(_info, file_tree, true);

    size_t buffer_size = np_tree_get_byte_size(file_tree);
    // np_serializer_add_map_bytesize(file_tree, &buffer_size);
    char file_buffer[buffer_size];
    np_tree2buffer(ac, file_tree, file_buffer);
    np_send(ac, _info->ci.subject, file_buffer, buffer_size);

    np_tree_free(file_tree);
  }

  __close_file(_info);
}

void np_files_send_authorized(np_context *ac, struct np_token *token) {
  np_tree_elem_t *elem = np_tree_find_str(__files._file_tree, token->subject);
  if (elem != NULL) {
    struct np_common_info *_info = (struct np_common_info *)elem->val.value.v;
    _info->send_entry(ac, token->subject);
  }
}

bool __file_open(np_state_t *context,
                 np_id(**child_id),
                 const char *filename,
                 bool        searchable) {
  bool ret = false;

  char       subject[76] = {0};
  np_subject subject_id  = {0};
  // memset(subject_id, 0, NP_FINGERPRINT_BYTES);

  __construct_id(filename, &subject_id, &subject);
  // fprintf(stdout, "derived file id %s for file %s\n", subject, filename);

  struct stat _f_info;
  if (0 == stat(filename, &_f_info) &&
      NULL == np_tree_find_str(__files._file_tree, subject)) {
    struct np_file_info *_info = malloc(sizeof(struct np_file_info));

    memcpy(_info->ci.id, subject_id, NP_FINGERPRINT_BYTES);
    strncpy(_info->ci.subject, subject, 76);
    _info->ci.send_entry = &__send_file;
    _info->ci.name       = strndup(filename, 256);
#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
    _info->ci.last_modified = _f_info.st_mtimespec;
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    _info->ci.last_modified    = _f_info.st_mtime;
#else
    _info->ci.last_modified    = _f_info.st_mtim;
#endif

    getcwd(_info->ci.cwd, sizeof(_info->ci.cwd));
    _info->file_size = _f_info.st_size;
    _info->loaded    = false;
    _info->mime_type = __find_mime_type(filename);

    __load_file(_info);

    np_tree_insert_str(__files._file_tree, subject, np_treeval_new_v(_info));

    // fprintf(stdout, "-------------------- filename: %-5s (%s)
    // --------------------\n", filename, subject);

    struct np_mx_properties mxp = np_get_mx_properties(context, subject_id);
    mxp.role                    = NP_MX_PROVIDER;
    mxp.ackmode                 = NP_MX_ACK_NONE;
    mxp.message_ttl             = _info->file_size / NP_PI * 100;
    mxp.intent_ttl              = 60 * 60 * 24; // a new token each day
    // mxp.intent_update_after = 60*60; // refresh each hour
    mxp.intent_update_after = 60; // refresh each minute

    // for(uint8_t x = 0; x < __indent_level; x++) fprintf(stdout,
    // __indent_str); fprintf(stdout, "registering   np://%s for file %s\n",
    // subject, filename);
    np_set_mx_properties(context, subject_id, mxp);
    np_mx_properties_disable(context, subject_id);

    if (np_module_initiated(http)) {
      // for(uint8_t x = 0; x < __indent_level; x++) fprintf(stdout,
      // __indent_str); fprintf(stdout, "registering http://%s\n", subject);
      _np_add_http_callback(context,
                            subject,
                            htp_method_GET,
                            &__files,
                            __np_file_handle_http_get_file);
    }

    if (np_module_initiated(search) && searchable) {
      np_datablock_t attr[NP_EXTENSION_BYTES] = {0};
      np_init_datablock(attr, NP_EXTENSION_BYTES);

      // add filename/title attribute
      struct np_data_conf data_conf_title = {.type = NP_DATA_TYPE_STR,
                                             .data_size =
                                                 strnlen(filename, 255)};
      strncpy(data_conf_title.key, "title", 255);
      np_set_data(attr, data_conf_title, (np_data_value){.str = filename});

      struct np_data_conf data_conf_urn = {.type      = NP_DATA_TYPE_STR,
                                           .data_size = strnlen(subject, 255)};
      strncpy(data_conf_urn.key, "urn", 255);
      np_set_data(attr, data_conf_urn, (np_data_value){.str = subject});

      // add mime type attribute
      // struct np_data_conf data_conf_type = { .type=NP_DATA_TYPE_STR,
      // .data_size=strnlen(mime_type, 20) }; strncpy(data_conf_type.key,
      // "@type" , 255); np_set_data(&attr, data_conf_type, (np_data_value)
      // {.str=mime_type_str[_info->mime_type]} );

      // add mime type attribute
      char               *mime_type          = mime_type_str[_info->mime_type];
      struct np_data_conf data_conf_mimetype = {.type = NP_DATA_TYPE_STR,
                                                .data_size =
                                                    strnlen(mime_type, 20)};
      strncpy(data_conf_mimetype.key, "mime_type", 255);
      np_set_data(attr,
                  data_conf_mimetype,
                  (np_data_value){.str = mime_type_str[_info->mime_type]});
      // if (
      //     (0 == strncmp(filename, "t3821", 5) || 0 == strncmp(filename,
      //     "t3809", 5))
      //     ||
      //     (0 == strncmp(filename, "t7907", 5) || 0 == strncmp(filename,
      //     "t4530", 5))
      //     ||
      //     (0 == strncmp(filename, "t1088", 5) || 0 == strncmp(filename,
      //     "t5015", 5))
      //     ||
      //     (0 == strncmp(filename, "t4211", 5) || 0 == strncmp(filename,
      //     "t9248", 5))
      // )

      {
        // fprintf(stdout, "--- filename: %-50s --- (%-50s) ---\n", filename,
        // subject);

        // np_searchquery_t sq = {0};
        // if (np_create_searchquery(context, &sq, _info->mmap_region, &attr))
        // {
        //     np_search_query(context, &sq);
        //     np_index_destroy(&sq.query_entry.search_index);
        // }
        // char rotator[] = { '/', '-', '\\', '|' };
        // uint16_t i = 1;
        size_t left_file_size = _info->file_size;
        char  *text_start     = _info->mmap_region;
        while (text_start != NULL && left_file_size > 0) {
          // fprintf(stdout, "--- adding search indices: %5u %c \r", i,
          // rotator[i%4]); fflush(stdout);

          char *text_end    = memchr(text_start, '\n', left_file_size);
          char *search_text = strndup(text_start, text_end - text_start);

          np_searchentry_t *se = calloc(1, sizeof(np_searchentry_t));
          if (/*0 == strncmp(search_text, "theme funds", strlen("theme funds"))
                 &&*/
              np_create_searchentry(context, se, search_text, &attr)) {
            // fprintf(stdout, "--- adding search indices: %5u %c \r", i,
            // rotator[i%4]); fflush(stdout);
            np_search_add_entry(context, se);
            // fprintf(stdout, "--- adding search indices: %5u %c \r", i,
            // rotator[i%4]); fflush(stdout);
          }

          // fprintf(stdout, "\t%s\n", search_text);
          free(search_text);

          left_file_size -= text_end - text_start + 1;
          text_start = text_end;
          if (text_start != NULL) text_start++;
          // i++;
          // fprintf(stdout, "--- adding search indices: %5u %c \r", i,
          // rotator[i%4]); fflush(stdout); throttle to prevent overload of
          // other systems
          np_time_sleep(NP_PI / 157);
        }
        // fprintf(stdout, "\n");
      }
    }

    // only return the address of the calculated np_id
    *child_id = &_info->ci.id;

    __close_file(_info);

    ret = true;
  }
  return ret;
}

bool __dir_open(np_state_t *context,
                np_id(**child_id),
                const char *dirname,
                bool        searchable) {
  bool ret = false;

  // open the directory and read basic values
  struct np_dir_info *dir_info = NULL;
  struct stat         _d_info  = {0};

  bool insert = false;
  // construct a subject hash name, the sum of the childs
  char  subject[76];
  np_id subject_id;
  memset(subject_id, 0, NP_FINGERPRINT_BYTES);

  __construct_id(dirname, &subject_id, &subject);

  // for(uint8_t x = 0; x < __indent_level; x++) fprintf(stdout, __indent_str);
  // fprintf(stdout, "derived directory id %s for directory %s\n", subject,
  // dirname);

  if (0 == stat(dirname, &_d_info) &&
      NULL == np_tree_find_str(__files._file_tree, subject)) {
    dir_info = calloc(1, sizeof(struct np_dir_info));
    memcpy(dir_info->ci.id, subject_id, NP_FINGERPRINT_BYTES);
    strncpy(dir_info->ci.subject, subject, 76);
    dir_info->ci.name = strndup(dirname, 256);
#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
    dir_info->ci.last_modified = _d_info.st_mtimespec;
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    dir_info->ci.last_modified = _d_info.st_mtime;
#else
    dir_info->ci.last_modified = _d_info.st_mtim;
#endif
    dir_info->ci.send_entry = &__send_dir;

    dir_info->dir_entries         = NULL;
    dir_info->dir_entries_counter = 0;
    dir_info->file_entries        = NULL;
    dir_info->dir_entries_counter = 0;

    *child_id = &dir_info->ci.id;
    insert    = true;
  } else if (NULL != np_tree_find_str(__files._file_tree, subject)) {
    dir_info = np_tree_find_str(__files._file_tree, subject)->val.value.v;
  } else {
    return ret;
  }

  char cwd[PATH_MAX];
  getcwd(cwd, sizeof(cwd));

  chdir(dirname);
  __indent_level++;

  getcwd(dir_info->ci.cwd, sizeof(dir_info->ci.cwd));

  DIR           *dir        = opendir(".");
  struct dirent *_dir_entry = NULL;
  while ((_dir_entry = readdir(dir)) != NULL) {
    if (_dir_entry->d_name[0] == '.') {
      continue;
    }

    struct stat _f_info;
    if (0 == stat(_dir_entry->d_name, &_f_info)) {
      np_id *_id = NULL;
      if (S_ISDIR(_f_info.st_mode)) {
        if (__dir_open(context, &_id, _dir_entry->d_name, searchable)) {
          dir_info->dir_entries =
              realloc(dir_info->dir_entries,
                      sizeof(np_id *) * (dir_info->dir_entries_counter + 1));
          dir_info->dir_entries[dir_info->dir_entries_counter] = _id;
          dir_info->dir_entries_counter++;
        }
      }

      if (S_ISREG(_f_info.st_mode)) {
        if (__file_open(context, &_id, _dir_entry->d_name, searchable)) {
          dir_info->file_entries =
              realloc(dir_info->file_entries,
                      sizeof(np_id *) * (dir_info->file_entries_counter + 1));
          dir_info->file_entries[dir_info->file_entries_counter] = _id;
          dir_info->file_entries_counter++;
        }
      }
    }
  }
  __indent_level--;
  closedir(dir);

  if (true == insert) {
    np_tree_insert_str(__files._file_tree, subject, np_treeval_new_v(dir_info));

    struct np_mx_properties mxp = np_get_mx_properties(context, subject);
    mxp.ackmode                 = NP_MX_ACK_NONE;
    mxp.message_ttl             = NP_PI * 10;
    mxp.intent_ttl              = 60 * 60 * 24; // a new token each day
    mxp.intent_update_after     = 60 * 60;      // refresh each hour

    // for(uint8_t x = 0; x < __indent_level; x++) fprintf(stdout,
    // __indent_str); fprintf(stdout, "registering   np://%s for directory
    // %s\n", subject, dirname);
    np_set_mx_properties(context, subject, mxp);

    if (np_module_initiated(http)) {
      // for(uint8_t x = 0; x < __indent_level; x++) fprintf(stdout,
      // __indent_str); fprintf(stdout, "registering http://%s\n", subject);
      _np_add_http_callback(context,
                            subject,
                            htp_method_GET,
                            &__files,
                            __np_file_handle_http_get_dir);
    }
    ret = true;
  }

  chdir(cwd);
  return ret;
}

void np_files_open(np_context *ac,
                   np_id       identifier_seed,
                   const char *dir_or_filename,
                   bool        searchable) {
  const char *subject    = "files";
  np_subject  subject_id = {0};
  np_generate_subject(subject_id, subject, strnlen(subject, 6));

  char cwd[PATH_MAX];
  getcwd(cwd, sizeof(cwd));

  np_state_t         *context  = (np_state_t *)ac;
  struct np_dir_info *dir_info = NULL;
  if (NULL == __files._file_tree) {
    char id_seed_str[65];
    __files.context    = ac;
    __files._file_tree = np_tree_create();

    np_spinlock_init(&__files._lock, PTHREAD_PROCESS_PRIVATE);
    memcpy(__files.seed, identifier_seed, NP_FINGERPRINT_BYTES);
    log_msg(LOG_INFO,
            "initialized file server, seed is %s\n",
            np_id_str(id_seed_str, identifier_seed));

    dir_info = calloc(1, sizeof(struct np_dir_info));
    memcpy(dir_info->ci.id, identifier_seed, NP_FINGERPRINT_BYTES);
    strncpy(dir_info->ci.subject, subject, 9);
    dir_info->ci.name = strndup("/", 1);

    double now                        = np_time_now();
    dir_info->ci.last_modified.tv_sec = (long)now;
    dir_info->ci.last_modified.tv_nsec =
        (now - dir_info->ci.last_modified.tv_sec) * 1000000000L;

    dir_info->ci.send_entry = &__send_dir;

    dir_info->dir_entries         = NULL;
    dir_info->dir_entries_counter = 0;
    dir_info->file_entries        = NULL;
    dir_info->dir_entries_counter = 0;

    np_tree_insert_str(__files._file_tree,
                       dir_info->ci.subject,
                       np_treeval_new_v(dir_info));

    struct np_mx_properties mxp = np_get_mx_properties(context, subject_id);
    mxp.ackmode                 = NP_MX_ACK_NONE;
    mxp.message_ttl             = NP_PI * 10;
    mxp.intent_ttl              = 60 * 60 * 24; // a new token each day
    mxp.intent_update_after     = 60 * 60;      // refresh each hour

    // for(uint8_t x = 0; x < __indent_level; x++) fprintf(stdout,
    // __indent_str); fprintf(stdout, "registering   np://%s for file %s\n",
    // subject, "/");
    np_set_mx_properties(context, subject_id, mxp);

    if (np_module_initiated(http)) {
      // for(uint8_t x = 0; x < __indent_level; x++) fprintf(stdout,
      // __indent_str); fprintf(stdout, "registering http://%s\n", subject);
      _np_add_http_callback(context,
                            subject,
                            htp_method_GET,
                            &__files,
                            __np_file_handle_http_get_dir);
    }
  } else {
    dir_info = np_tree_find_str(__files._file_tree, subject)->val.value.v;
  }

  struct stat _f_info;
  if (0 == stat(dir_or_filename, &_f_info)) {
    np_id *_id = NULL;
    if (S_ISDIR(_f_info.st_mode)) {
      if (__dir_open(context, &_id, dir_or_filename, searchable)) {
        dir_info->dir_entries =
            realloc(dir_info->dir_entries,
                    sizeof(np_id *) * (dir_info->dir_entries_counter + 1));
        dir_info->dir_entries[dir_info->dir_entries_counter] = _id;
        dir_info->dir_entries_counter++;
      }
    }
    if (S_ISREG(_f_info.st_mode)) {
      if (__file_open(context, &_id, dir_or_filename, searchable)) {
        dir_info->file_entries =
            realloc(dir_info->file_entries,
                    sizeof(np_id *) * (dir_info->file_entries_counter + 1));
        dir_info->file_entries[dir_info->file_entries_counter] = _id;
        dir_info->file_entries_counter++;
      }
    }
  } else {
    log_msg(LOG_WARNING,
            "np_file: could not stat given filename # %s # (%d) : %s \n",
            dir_or_filename,
            errno,
            strerror(errno));
  }

  chdir(cwd);
}

void np_files_close(np_context *ac, const char *alias) {}

void np_files_list(np_context *ac, const char *alias) {}

// a callback function that can be passed to the neuropil library
bool np_files_store_cb(np_context *context, struct np_message *msg) {
  np_tree_t *file_info = np_tree_create();
  np_buffer2tree(context, msg->data, msg->data_length, file_info);

  // char id_str[65];
  np_tree_elem_t *_np_id   = np_tree_find_str(file_info, "np_id");
  np_tree_elem_t *_content = np_tree_find_str(file_info, "content");
  np_tree_elem_t *_name    = np_tree_find_str(file_info, "name");

  // open the hash filename
  int fd = open(_np_id->val.value.s,
                O_CREAT | O_WRONLY | O_TRUNC,
                S_IRUSR | S_IWUSR);
  if (fd == -1) {
    log_msg(LOG_WARNING,
            "error: %s for filename %s",
            strerror(errno),
            _np_id->val.value.s);
    return true;
  }
  // and write the file contents
  uint32_t bytes_written =
      write(fd, _content->val.value.bin, _content->val.size);

  // TODO: hardlink the real filename to the hashed one
  // link(_np_id->val.value.s, _name->val.value.s);

  // TODO: add attributes
  // e.g.: store the encrpyted file and use the uuid of the token as an
  // attribute to identify the decryption e.g.: add the data owner as an
  // attribute

  log_msg(LOG_INFO,
          "received file %s -> %s",
          _name->val.value.s,
          _np_id->val.value.s);

  return true;
}
