//
// neuropil is copyright 2016-2020 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include "ncurses.h"

#include "np_threads.h"

#include "../framework/http/np_http.h"
#include "../framework/sysinfo/np_sysinfo.h"

#ifndef _NP_EXAMPLE_HELPER_H_
#define _NP_EXAMPLE_HELPER_H_

#define __NP_INTERACTIVE_CACHE 500
#define LOG_BUFFER_SIZE (30000)
#define ESC '\033'

enum np_statistic_types_e {
    np_stat_all = 0x000,
    np_stat_general         = 0x001,
    np_stat_locks           = 0x002,
    np_stat_msgpartcache    = 0x004,
    np_stat_memory          = 0x008,
    np_stat_performance     = 0x010,
    np_stat_jobs            = 0x020,
    np_stat_threads         = 0x040,
} typedef np_statistic_types_e;


struct __np_switchwindow_scrollable {
    np_mutex_t access;
    WINDOW * win;
    char * buffer;
    int cursor;
};

enum np_user_interface {
    np_user_interface_off = 0,
    np_user_interface_ncurse = 1,
    np_user_interface_log = 2,
    np_user_interface_console = 4
};

enum np_example_load_identity_status {
    np_example_load_identity_status_success = 1,
    np_example_load_identity_status_not_found = 0,
    np_example_load_identity_status_found_but_failed = -1,
};

typedef void(*np_interactive_fn)(np_context* context, char* input);


typedef struct example_user_context {
    np_http_t* local_http;
    bool _printed_startup;
    enum np_user_interface user_interface;
    np_statistic_types_e statistic_types;

    int term_width_top_rigth ;
    int term_height_bottom ;

    struct __np_switchwindow_scrollable * _current ;

    bool __np_ncurse_initiated;

    float input_intervall_sec;
    float output_intervall_sec;
    WINDOW * __np_top_left_win;
    WINDOW * __np_top_right_win;
    WINDOW * __np_top_logo_win;
    WINDOW * __np_bottom_win_help;

    struct __np_switchwindow_scrollable * __np_switch_msgpartcache;
    struct __np_switchwindow_scrollable * __np_switch_memory_ext;
    struct __np_switchwindow_scrollable * __np_switch_log;
    struct __np_switchwindow_scrollable * __np_switch_performance;
    struct __np_switchwindow_scrollable * __np_switch_jobs;
    struct __np_switchwindow_scrollable * __np_switch_threads;
    struct __np_switchwindow_scrollable * __np_switch_interactive;

    bool is_in_interactive;
    np_interactive_fn __np_interactive_event_on_enter ;
    char* __np_interactive_text;
    char __np_interactive_cache[__NP_INTERACTIVE_CACHE];

    bool _np_httpserver_active;


    char * __log_buffer;
    char * __log_buffer_cursor;
    np_mutex_t* __log_mutex;

    double started_at;
    double last_loop_run_at;
    double ncurse_init_at;

    bool identity_opt_is_set;
    char identity_filename[255] ;
    char identity_passphrase[255] ;

    char node_description[255];

    unsigned char salt[crypto_pwhash_SALTBYTES] ;
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    bool key_is_gen;


    char* opt_http_domain;
    char* opt_http_port;
    enum np_sysinfo_opt_e opt_sysinfo_mode;

    bool __shutdown;

}example_user_context;

#endif //_NP_EXAMPLE_HELPER_H_


