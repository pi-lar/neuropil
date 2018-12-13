//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <float.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <getopt.h>
#include <assert.h>
#include <math.h>

#include <curses.h>
#include <ncurses.h>
#include "sodium.h"

#include "../examples/example_helper.h"


#include "np_legacy.h"
#include "np_types.h"
#include "np_statistics.h"
#include "np_memory.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_key.h"
#include "np_list.h"
#include "np_sysinfo.h"
#include "np_threads.h"
#include "np_log.h"
#include "np_messagepart.h"
#include "np_jobqueue.h"
#include "np_performance.h"
#include "web/np_http.h"
#include "np_statistics.h"

#include "np_conversion.c"

const char* logo =
"MMWKkxxdoollcdKMMMMMMMMMMMMWOollolloOWMM\n"
"MMNxccccccccccdKWMMMMMMMMMMWkccccccckWMM\n"
"MMNxcccccccccccoKWMMMMMMMMMWkccccccckWMM\n"
"MMNxccccloxxolcco0WMMMMMMMMWkccccccckWMM\n"
"MMNxcccd0NWWN0occo0WMMMMMMMWkccccccckWMM\n"
"MMNxcccOWMMMMWkccclONWMMMMMWkccccccckWMM\n"
"MMNxcccdKNWMW0occccldONMMMMWkccccccckWMM\n"
"MMNxcccclokXKdccccccclkNMMMWOccccccckWMM\n"
"MMNxccccccl0W0occccccclkNMMWOlcccccckWMM\n"
"MMNxcccccclOWWKdccccccccxNMM0lcccccckWMM\n"
"MMNxcccccccOWMMKdccccccccxXM0lcccccckWMM\n"
"MMNxcccccccOWMMMXxccccccccxXKocccccckWMM\n"
"MMNxcccccccOWMMMMXxccccccco0NKOxlccckWMM\n"
"MMNxcccccccOWMMMMMNkllccco0WMMMW0lcckWMM\n"
"MMNxcccccccOWMMMMMMNKklccoKMMMMMKo:ckWMM\n"
"MMNxcccccccOWMMMMMMMMNOlccdOKXKOoccckWMM\n"
"MMNxcccccccOWMMMMMMMMMWOlcccclcccccckWMM\n"
"MMNxcccccccOWMMMMMMMMMMW0occc:cccccckWMM\n"
"MMNxcccccccOWMMMMMMMMMMMW0occccccccckWMM\n"
"MMNxcccccclOWMMMMMMMMMMMMWOlcccccccckWMM";

bool __np_terminal_resize_flag = false;

example_user_context* example_new_usercontext() {

    example_user_context* user_context = calloc(1, sizeof(example_user_context));
    user_context->local_http = NULL;

    user_context->_printed_startup = false;
    user_context->user_interface = np_user_interface_ncurse;
    user_context->statistic_types = 0;

    user_context->term_width_top_rigth = 41;
    user_context->term_height_bottom = 15;

    user_context->_current = NULL;

    user_context->__np_ncurse_initiated = false;

    user_context->input_intervall_sec = 0.10;
    user_context->output_intervall_sec = 0.50;
    user_context->__np_top_left_win = NULL;
    user_context->__np_top_right_win= NULL;
    user_context->__np_top_logo_win= NULL;
    user_context->__np_bottom_win_help= NULL;

    user_context->__np_switch_msgpartcache= NULL;
    user_context->__np_switch_memory_ext= NULL;
    user_context->__np_switch_log= NULL;
    user_context->__np_switch_performance= NULL;
    user_context->__np_switch_jobs= NULL;
    user_context->__np_switch_interactive= NULL;

    user_context->is_in_interactive = false; 
    user_context->__np_interactive_event_on_enter = NULL;
    user_context->__np_interactive_text = NULL;
    memset(&user_context->__np_interactive_cache, 0, __NP_INTERACTIVE_CACHE);

    user_context->_np_httpserver_active = false;


    user_context->__log_buffer = NULL;
    user_context->__log_buffer_cursor = 0;
    user_context->__log_mutex = NULL;

    user_context->started_at = 0;
    user_context->last_loop_run_at = 0;
    user_context->ncurse_init_at = 0;

    user_context->identity_opt_is_set = false;
    memset(&user_context->identity_filename, 0 , 255);
    memset(&user_context->identity_passphrase, 0, 255);

    memset(&user_context->salt, 123, crypto_pwhash_SALTBYTES);
    memset(&user_context->nonce, 123 , crypto_secretbox_NONCEBYTES);
    memset(&user_context->key,0, crypto_secretstream_xchacha20poly1305_KEYBYTES);
    user_context->key_is_gen = false;


    user_context->opt_http_domain = NULL;
    user_context->opt_sysinfo_mode = np_sysinfo_opt_auto;

    return user_context;
}

int getInput() {
    int ret = getch();
    if (ret == ESC) {
        if (getch() == '[') {
            switch (getch()) {
            case 'A':
                ret = KEY_UP;
                break;
            case 'B':
                ret = KEY_DOWN;
                break;
            case 'C':
                ret = KEY_RIGHT;
                break;
            case 'D':
                ret = KEY_LEFT;
                break;
            }
        }
    }

    return ret;
}

void reltime_to_str(char*buffer, double time) {
    // totaltime format: seconds.milliseconds
    // Now we need to format the seconds part to days:hours:seconds

    uint32_t time_d = (time / 86400); // 60*60*24 = 86400
    uint32_t time_d_r = (uint32_t)time % 86400;
    uint32_t time_h = time_d_r / 3600; // 60*60 = 3600
    uint32_t time_h_r = time_d_r % 3600;
    uint32_t time_m = (time_h_r / 60);
    uint32_t time_m_r = time_h_r % 60;
    uint32_t time_s = time_m_r;

    snprintf(buffer, 49, "%02"PRIu32"d %02"PRIu32"h %02"PRIu32"min %02"PRIu32"sec", time_d, time_h, time_m, time_s);
}

void __np_switchwindow_draw(np_context* context) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));
    struct __np_switchwindow_scrollable * _current = ud->_current;

    if (ud->__np_ncurse_initiated == true && _current != NULL) {
        _LOCK_ACCESS(&_current->access) {
            werase(_current->win);
            int displayedRows = 0;

            char * buffer = strdup(_current->buffer);
            char* line = strtok(buffer, "\n");
            int y = 0;
            if (line != NULL) {
                do {
                    // clean line from escapes
                    for (size_t c = 0; c < strlen(line); c++)
                        if (line[c] < 32 || line[c] > 126) line[c] = ' ';

                    if (y >= _current->cursor) {
                        mvwprintw(_current->win, displayedRows, 0, line);
                        displayedRows++;
                    }
                    y++;
                } while ((line = strtok(NULL, "\n")) != NULL && displayedRows <= ud->term_height_bottom);
            }

            wrefresh(_current->win);
            free(buffer);
        }
    }
}

void __np_switchwindow_show(np_context* context, struct __np_switchwindow_scrollable *target) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));
    
    if (ud->_current == NULL)
    {
        ud->_current = target;
    }
    else {
        _LOCK_ACCESS(&ud->_current->access) {
            ud->_current = target;
            wclear(ud->_current->win);
        }
    }
}
void __np_switchwindow_scroll_check_bounds(np_context* context, struct __np_switchwindow_scrollable *target) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));	

    int lines = 0;
    for (uint32_t c = 0; c < strlen(target->buffer); c++) {
        if (target->buffer[c] == '\n') lines++;
    }
    int max_scroll = lines - ud->term_height_bottom;

    if (max_scroll <= 0)
    {
        target->cursor = 0;
    }
    else {
        if (target->cursor > max_scroll)
            target->cursor = max_scroll;
        else
            target->cursor = fmax(0, target->cursor);
    }
}

void __np_switchwindow_scroll(np_context* context, struct __np_switchwindow_scrollable *target, int relative, bool draw) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));
    struct __np_switchwindow_scrollable * _current = ud->_current;

    _LOCK_ACCESS(&target->access) {
        target->cursor += relative;
        __np_switchwindow_scroll_check_bounds(context, target);
    }
    if (draw && _current == target)__np_switchwindow_draw(context);
}

void __np_switchwindow_update_buffer(np_context* context, struct __np_switchwindow_scrollable * target, char* buffer, int scroll_relative) {

    _LOCK_ACCESS(&target->access) {
        free(target->buffer);
        target->buffer = strdup(buffer);
        __np_switchwindow_scroll(context, target, scroll_relative, false);
    }

}

void __np_switchwindow_interactive_incomming(np_context* context, int key) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));

    // ENTER
    if (key == KEY_ENTER || key == 10) {
        if (ud->__np_interactive_event_on_enter != NULL) {
            ud->__np_interactive_event_on_enter(context, ud->__np_interactive_cache);
        }
        memset(ud->__np_interactive_cache, 0, __NP_INTERACTIVE_CACHE);
        ud->is_in_interactive = false;
        __np_switchwindow_show(context, ud->__np_switch_log);
    }
    // ESC
    else if (key == ESC) {
        memset(ud->__np_interactive_cache, 0, __NP_INTERACTIVE_CACHE);
        ud->is_in_interactive = false;
        __np_switchwindow_show(context, ud->__np_switch_log);
    }
    else {
        // BACKSPACE
        char tmp[__NP_INTERACTIVE_CACHE + 500];
        if (key == KEY_BACKSPACE) {
            int l = strlen(ud->__np_interactive_cache);
            if (l > 0) {
                memset(ud->__np_interactive_cache+l-1, 0,1);
            }
            snprintf(tmp, __NP_INTERACTIVE_CACHE + 500, "%s\nInput:\n%s", ud->__np_interactive_text, ud->__np_interactive_cache);
        }
        else {
            if (key >= 32 && key <= 126) {
                ud->__np_interactive_cache[strlen(ud->__np_interactive_cache) % __NP_INTERACTIVE_CACHE] = (char)key;
                snprintf(tmp, __NP_INTERACTIVE_CACHE + 500, "%s\nInput:\n%s", ud->__np_interactive_text, ud->__np_interactive_cache);
            }
            else {
                snprintf(tmp, __NP_INTERACTIVE_CACHE + 500, "%s\nInput: (invalid key %d)\n%s", ud->__np_interactive_text, key, ud->__np_interactive_cache);
            }
        }
        __np_switchwindow_update_buffer(context, ud->__np_switch_interactive, tmp, 0);

    }
}

void __np_switchwindow_configure_interactive(np_context* context, char* text, np_interactive_fn on_enter) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));
    ud->__np_interactive_event_on_enter = on_enter;
    ud->__np_interactive_text = text;
    __np_switchwindow_update_buffer(context, ud->__np_switch_interactive, ud->__np_interactive_text, 0);
    __np_switchwindow_show(context, ud->__np_switch_interactive);
    ud->is_in_interactive = true;
}

struct __np_switchwindow_scrollable * __np_switchwindow_new(np_context* context, chtype color_pair, int width, int y) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));
    struct __np_switchwindow_scrollable * ret = calloc(1, sizeof(struct __np_switchwindow_scrollable));

    _np_threads_mutex_init(context, &ret->access, "__np_switchwindow_scrollable->access");

    int h = ud->term_height_bottom, w = width/*140*/, x = 0/*, y = 39*/;
    ret->win = newwin(h, w, y, x);
    wbkgd(ret->win, color_pair);
    scrollok(ret->win, true);

    __np_switchwindow_update_buffer(context, ret, "initiated", 0);

    return ret;
}

void __np_switchwindow_del(np_context* context, struct __np_switchwindow_scrollable * self) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));
    _LOCK_ACCESS(&self->access) {
        if (ud->_current == self) ud->_current = NULL;
        delwin(self->win);
    }
    _np_threads_mutex_destroy(context, &self->access);
    free(self);
}

void np_print_startup(np_context*context);

void np_example_print(np_context * context, FILE * stream, const char * format_in, ...) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));
    np_print_startup(context);
    va_list args;
    va_start(args, format_in);

    char tmp_time[200];
    char format[LOG_BUFFER_SIZE - 201] = { 0 };
    char buffer[LOG_BUFFER_SIZE - 1] = { 0 };
    reltime_to_str(tmp_time, np_time_now() - ud->started_at);

    // render msg
    vsnprintf(format, LOG_BUFFER_SIZE - 201, format_in, args);
    // add time string
    int to_add_size =
        snprintf(buffer, LOG_BUFFER_SIZE - 1, "%s -%s%s", tmp_time,(strlen(format) > 200? "\n":" "), format);

    va_end(args);

    if (to_add_size > 0) {
        if (ud->__log_mutex == NULL) {
            ud->__log_mutex = malloc(sizeof(np_mutex_t));
            _np_threads_mutex_init(context, ud->__log_mutex, "Example logger mutex");
        }
        _LOCK_ACCESS(ud->__log_mutex)
        {
            if (ud->__log_buffer == NULL) ud->__log_buffer = calloc(1, LOG_BUFFER_SIZE); // TODO: move to an init

            // count lines to scroll accordingly
            int line_count = 0;
            for (int c = 0; c < to_add_size; c++) {
                if (buffer[c] == '\n') line_count++;
            }

            int total_to_add_size = to_add_size + 1; // '\n' append
            int rescued_buffer_size = LOG_BUFFER_SIZE - total_to_add_size - 1/*NULL Term*/;

            // move existing memory
            memmove(&ud->__log_buffer[total_to_add_size], ud->__log_buffer, rescued_buffer_size);
            // copy new
            memcpy(ud->__log_buffer, buffer, to_add_size);
            // append \n
            memset(&ud->__log_buffer[to_add_size], '\n', 1);
            // always terminate string
            memset(&ud->__log_buffer[LOG_BUFFER_SIZE - 1], '\0', 1);

            if (ud->__np_ncurse_initiated) {
                __np_switchwindow_update_buffer(context, ud->__np_switch_log, ud->__log_buffer, -1 * line_count);
            } else {
                fputs(buffer, stream);
                fflush(stream);
            }
        }
    }
}

char* np_get_startup_str(np_state_t* context) {
    char* ret = NULL;
    char* new_line = "\n";

    ret = np_str_concatAndFree(ret, new_line);
    ret = np_str_concatAndFree(ret, "%s initializiation successful%s", NEUROPIL_RELEASE, new_line);
    ret = np_str_concatAndFree(ret, "%s event loop with %d worker threads started%s", NEUROPIL_RELEASE, context->thread_count, new_line);
    ret = np_str_concatAndFree(ret, "your neuropil node will be addressable as:%s", new_line);
    ret = np_str_concatAndFree(ret, new_line);
    char* connection_str = np_get_connection_string(context);
    ret = np_str_concatAndFree(ret, "\t%s%s", connection_str, new_line);
    free(connection_str);
    ret = np_str_concatAndFree(ret, new_line);
    if (_np_key_cmp(context->my_node_key, context->my_identity) != 0) {
        ret = np_str_concatAndFree(ret, "your neuropil id is addressable via:%s", new_line);
        ret = np_str_concatAndFree(ret, "\t%s%s", _np_key_as_str(context->my_identity), new_line);
        ret = np_str_concatAndFree(ret, new_line);
    }

    ret = np_str_concatAndFree(ret, "%s%s", NEUROPIL_COPYRIGHT, new_line);
    ret = np_str_concatAndFree(ret, "%s%s", NEUROPIL_TRADEMARK, new_line);
    ret = np_str_concatAndFree(ret, new_line);

    return ret;
}

void np_print_startup(np_context * context) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));

    if (ud->_printed_startup == false && np_get_status(context) == np_running) {
        ud->_printed_startup = true;
        char* ret = np_get_startup_str(context);
        np_example_print(context, stdout, ret);
        //log_msg(LOG_INFO, ret);
        free(ret);
    }
}


bool np_example_save_identity(np_context* context, char* passphrase, char* filename) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));
    bool  ret = false;
    
    struct np_token new_token = np_new_identity(context, np_time_now() + 60 * 60 * 24 * 7, NULL);
    size_t token_size = sizeof(new_token);

    int tmp = 0;
    if (!ud->key_is_gen &&
        (tmp = crypto_pwhash(
            ud->key,
            sizeof ud->key,
            passphrase,
            strlen(passphrase),
            ud->salt,
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE,
            crypto_pwhash_ALG_ARGON2ID13
        )) != 0
        ) {
        log_debug_msg(LOG_DEBUG, "Error creating key! (%"PRIi32")", tmp);
    }
    else {
        ud->key_is_gen = true;
    }

    if (ud->key_is_gen) {
        unsigned char crypted_data[token_size + crypto_secretbox_MACBYTES];
        memset(crypted_data, 0, sizeof crypted_data);

        if (0 != crypto_secretbox_easy(
            crypted_data,
            (unsigned char*)&new_token,
            token_size,
            ud->nonce,
            ud->key)) {
            log_debug_msg(LOG_DEBUG, "Error encrypting file!");
        }
        else {
            FILE *f = fopen(filename, "wb");
            if (f != NULL) {
                if (fwrite(crypted_data, sizeof crypted_data, 1, f) == 1) {
                    ret = true;
                }
            }
            fclose(f);

            np_example_print(context, stdout, "Saved ident %s into file %s\n",
                new_token.uuid,
                filename
            );

        }

    }
    return ret;
}
enum np_example_load_identity_status  np_example_load_identity(np_context *context, char* passphrase, char* filename) {
    enum np_example_load_identity_status ret = np_example_load_identity_status_not_found;
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));

    FILE *f = fopen(filename, "rb");
    if (f != NULL)
    {
        ret = np_example_load_identity_status_found_but_failed;
        if (!ud->key_is_gen &&
            crypto_pwhash(
                ud->key,
                sizeof ud->key,
                passphrase,
                strlen(passphrase),
                ud->salt,
                crypto_pwhash_OPSLIMIT_INTERACTIVE,
                crypto_pwhash_MEMLIMIT_INTERACTIVE,
                crypto_pwhash_ALG_ARGON2ID13
            ) != 0) {
            log_debug_msg(LOG_DEBUG, "Error creating key!");
        }
        else {
            ud->key_is_gen = true;
        }
        if (ud->key_is_gen) {

            struct stat info;
            stat(filename, &info);
            unsigned char* crypted_data = (unsigned char *)malloc(info.st_size);
            fread(crypted_data, info.st_size, 1, f);

            assert(sizeof(struct np_token) == info.st_size - crypto_secretbox_MACBYTES);
            struct np_token buffer;

            if (0 == crypto_secretbox_open_easy(
                (unsigned char*)&buffer,
                crypted_data,
                info.st_size,
                ud->nonce,
                ud->key)
                ) {								
                np_use_identity(context, buffer);				
                ret = np_example_load_identity_status_success;
            }
            free(crypted_data);
        }
        fclose(f);
    }
    return ret;
}

void np_example_save_and_load_identity(np_state_t* context) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));

    if (ud->identity_opt_is_set) {
        np_example_print(context, stdout, "Try to load ident file.\n");
        enum np_example_load_identity_status load_status;
        if ((load_status = np_example_load_identity(context, ud->identity_passphrase, ud->identity_filename)) == np_example_load_identity_status_not_found) {

            np_example_print(context, stdout, "Load detected no available token file. Try to save ident to file.\n");
            if (!np_example_save_identity(context, ud->identity_passphrase, ud->identity_filename)) {
                np_example_print(context, stdout, "Cannot load or save identity file. error(%"PRIi32"): %s. file: \"%s\"\n", errno, strerror(errno), ud->identity_filename);
                exit(EXIT_FAILURE);
            }
            else {
                np_example_print(context, stdout, "Saved ident to file.\n");
                load_status = np_example_load_identity(context, ud->identity_passphrase, ud->identity_filename);
            }
        }

        if (load_status == np_example_load_identity_status_success) {
            np_example_print(context, stdout, "Loaded ident(%s) from file.\n", _np_key_as_str(context->my_identity));
        }
        else if (load_status == np_example_load_identity_status_found_but_failed) {
            np_example_print(context, stdout, "Could not load from file.\n");
        }
        else {
            np_example_print(context, stdout, "Unknown np_example_load_identity_status\n");
        }
    }
}

example_user_context* parse_program_args(
    char* program,
    int argc,
    char **argv,
    int* no_threads,
    char** j_key,
    char** proto,
    char** port,
    char** publish_domain,
    int*  level,
    char** logpath,
    char* additional_fields_desc,
    char* additional_fields_optstr,
    ...
) {
    example_user_context* user_context = example_new_usercontext();

    bool ret = true;
    char* usage;
    asprintf(&usage,
        "./%s [ -j key:proto:host:port ] [ -p protocol] [-b port] [-t (> 0) worker_thread_count ] [-u publish_domain] [-d loglevel] [-l logpath] [-s statistics 0=Off 1=Console 2=Log 4=Ncurse] [-y statistic types 0=All 1=general 2=locks ] [-i identity filename] [-a passphrase for identity file]  [-w http domain] [-o sysinfo 0=none,1=auto,2=server,3=client] %s",
        program, additional_fields_desc == NULL ? "" : additional_fields_desc
    );
    char* optstr;
    asprintf(&optstr, "j:p:b:t:u:l:d:s:y:i:a:w:o:%s", additional_fields_optstr);

    char* additional_fields[32] = { 0 }; // max additional fields
    va_list args;
    va_start(args, additional_fields_optstr);
    char* additional_field_char;

    int additional_fields_count = 0;

    if (additional_fields_optstr != NULL) {
        additional_fields_count = strlen(additional_fields_optstr) / 2;
    }

    int additional_field_idx = 0;
    int opt;

    while ((opt = getopt(argc, argv, optstr)) != EOF)
    {
        switch ((char)opt)
        {
        case 'j':
            *j_key = strdup(optarg);
            break;
        case 't':
            (*no_threads) = atoi(optarg);
            if ((*no_threads) < 0) {
                fprintf(stderr, "invalid option %c\n", (char)opt);
                ret = false;
            }
            break;
        case 'p':
            *proto = strdup(optarg);
            break;
        case 'u':
            *publish_domain = strdup(optarg);
            break;
        case 'w':
            user_context->opt_http_domain = strdup(optarg);
            break;
        case 'o':
            user_context->opt_sysinfo_mode = atoi(optarg);
            break;
        case 'd':
            (*level) = atoi(optarg);
            break;
        case 's':
            user_context->user_interface = atoi(optarg);
            break;
        case 'y':
            user_context->statistic_types = atoi(optarg);
            break;
        case 'b':
            *port = strdup(optarg);
            break;
        case 'i':
            user_context->identity_opt_is_set = true;
            strncpy(user_context->identity_filename, optarg, strnlen(optarg, 254));
            break;
        case 'a':
            strncpy(user_context->identity_passphrase, optarg, strnlen(optarg, 254));
            break;
        case 'l':
            if (optarg != NULL) {
                *logpath = strdup(optarg);
            }
            else {
                fprintf(stderr, "invalid option %c\n", (char)opt);
                ret = false;
            }
            break;
        default:
            // check for custom parameter
            additional_field_char = strchr(additional_fields_optstr, (char)opt);
            if (additional_field_char != NULL) {
                additional_field_idx = (additional_field_char - additional_fields_optstr) / 2; // as every ident char is followed by an : symbol
                additional_fields[additional_field_idx] = strdup(optarg);
            }
            else {
                fprintf(stderr, "invalid option %c\n", (char)opt);
                ret = false;
            }
        }
    }

    free(optstr);

    if (ret) {
        for (additional_field_idx = 0; additional_field_idx < additional_fields_count; additional_field_idx++) {
            char** arg = va_arg(args, char**);
            if (additional_fields[additional_field_idx] != NULL) {
                (*arg) = additional_fields[additional_field_idx];
            }
        }
        va_end(args);

        uint32_t log_categories = 0
            | LOG_VERBOSE
            | LOG_TRACE
            //| LOG_MUTEX
            | LOG_ROUTING
            //| LOG_HTTP
            //| LOG_KEY
            | LOG_NETWORK
            | LOG_HANDSHAKE
            //| LOG_AAATOKEN
            //| LOG_SYSINFO
            | LOG_MESSAGE
            //| LOG_SERIALIZATION
            //| LOG_SERIALIZATION
            //| LOG_MEMORY
            //| LOG_MISC
            //| LOG_EVENT
            //| LOG_THREADS
            //| LOG_JOBS
            //| LOG_GLOBAL
            ;

        if ((*level) == -1) {	   // production client
            (*level) = LOG_ERROR | log_categories;
        }
        else if ((*level) == -2) { // production server
            (*level) = LOG_ERROR | LOG_WARN | LOG_INFO | log_categories;
        }
        else if ((*level) <= -3) { // debug
            (*level) = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | log_categories;
        }

        /**
        To create unique names and to use a seperate port for every
        node we will start the nodes in forks of this thread and use the pid as unique id.

        As the pid may be greater then the port range we will shift it if necessary.

        .. code-block:: c
        \code
        */
        if (*port == NULL) {
            int port_pid = getpid();			
            
            if (port_pid > 65535) {
                port_pid  = port_pid >> 1;
            }
            if (port_pid < 1024) {
                port_pid += 1024;
            }
            asprintf(port, "%d", port_pid);
        }
        /** \endcode */
    }
    else {
        fprintf(stderr, "usage: %s\n", usage);
    }
    free(usage);
    
    if (!ret) {
        free(user_context);
        user_context = NULL;
    }

    return user_context;
}

void __np_example_deinti_ncurse(np_context * context) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));

    if (ud->__np_ncurse_initiated == true) {
        delwin(ud->__np_top_left_win);
        delwin(ud->__np_top_right_win);
        delwin(ud->__np_top_logo_win);
        delwin(ud->__np_bottom_win_help);

        __np_switchwindow_del(context, ud->__np_switch_memory_ext);
        __np_switchwindow_del(context, ud->__np_switch_log);
        __np_switchwindow_del(context, ud->__np_switch_msgpartcache);
        __np_switchwindow_del(context, ud->__np_switch_performance);

        endwin();
        ud->__np_ncurse_initiated = false;
    }
}

void __np_example_print_help(example_user_context* ud) {
    werase(ud->__np_top_left_win);
    werase(ud->__np_top_right_win);
    if (ud->_current != NULL) werase(ud->_current->win);

    mvwprintw(ud->__np_bottom_win_help, 0, 0,
        "(P)erformance / Message(c)ache / Extended (M)emory / (L)og / J(o)bs "
        "| R(e)paint "
        "| Log: (F)ollow / (U)p / dow(N) "
        "| (Q)uit | (H)TTP | (S)ysInfo | (J)oin"
    );
    int pos = -1;
    if (ud->_current == ud->__np_switch_performance) pos = 1;
    else if (ud->_current == ud->__np_switch_msgpartcache) pos = 24;
    else if (ud->_current == ud->__np_switch_memory_ext) pos = 43;
    else if (ud->_current == ud->__np_switch_log) pos = 54;
    else if (ud->_current == ud->__np_switch_jobs) pos = 64;
    mvwchgat(ud->__np_bottom_win_help, 0, pos, 1, A_UNDERLINE, 4, NULL);
    wrefresh(ud->__np_bottom_win_help);

}
void __np_example_inti_ncurse(np_context* context) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));
    if (false == ud->__np_ncurse_initiated) {
        if (FLAG_CMP(ud->user_interface, np_user_interface_ncurse)) {
            ud->__np_ncurse_initiated = true;
            ud->ncurse_init_at = np_time_now();


            /* Start curses mode          */
            initscr(); // Init ncurses mode
            // other:
            /*
            newterm(NULL, stderr, stdin);
            FILE *f = fopen("/dev/tty", "r+");
            SCREEN *screen = newterm(NULL, f, f);
            set_term(screen);
            */

            int term_current_height, term_current_width;
            getmaxyx(stdscr, term_current_height, term_current_width);  /* get the screen size */

            int term_width_top_left;
            int term_height_top_left;
            // term_height_bottom = 15
            int term_height_help = 1;

            int term_height_logo = 20;

            term_width_top_left = fmin(term_current_width, fmax(100, term_current_width - ud->term_width_top_rigth));
            ud->term_width_top_rigth = term_current_width - term_width_top_left;

            term_height_top_left = term_current_height - ud->term_height_bottom - term_height_help;
            int term_height__top_right = term_height_top_left - term_height_logo;

            // setup ncurse config
            curs_set(0); // Hide cursor
            raw();				/* Line buffering disabled	*/
            keypad(stdscr, true);
            noecho();
            timeout(0);
            start_color();

            init_pair(1, COLOR_YELLOW, COLOR_BLUE);
            init_pair(2, COLOR_BLUE, COLOR_YELLOW);
            init_pair(3, COLOR_WHITE, COLOR_MAGENTA);
            init_pair(4, COLOR_WHITE, COLOR_BLACK);

            init_pair(5, COLOR_CYAN, COLOR_BLACK);
            init_pair(6, COLOR_GREEN, COLOR_BLACK);
            init_pair(7, COLOR_RED, COLOR_BLACK);

            if (ud->statistic_types == np_stat_all || (ud->statistic_types & np_stat_general) == np_stat_general) {
                ud->__np_top_left_win = newwin(term_height_top_left, term_width_top_left, 0, 0);
                wbkgd(ud->__np_top_left_win, COLOR_PAIR(1));
            }


            ud->__np_top_logo_win = newwin(term_height_logo, ud->term_width_top_rigth, 0, term_width_top_left);
            wbkgd(ud->__np_top_logo_win, COLOR_PAIR(4));

#ifdef NP_THREADS_CHECK_THREADING
            if (ud->statistic_types == np_stat_all || (ud->statistic_types & np_stat_locks) == np_stat_locks) {
                ud->__np_top_right_win = newwin(term_height__top_right, ud->term_width_top_rigth, term_height_logo, term_width_top_left);
                wbkgd(ud->__np_top_right_win, COLOR_PAIR(2));
            }
#else
            if (ud->statistic_types == np_stat_all || (ud->statistic_types & np_stat_memory) == np_stat_memory) {
                ud->__np_top_right_win = newwin(term_height__top_right, ud->term_width_top_rigth, term_height_logo, term_width_top_left);
                wbkgd(ud->__np_top_right_win, COLOR_PAIR(2));
            }
#endif
            // switchable windows
            {

                if (ud->statistic_types == np_stat_all || (ud->statistic_types & np_stat_msgpartcache) == np_stat_msgpartcache) {

                    ud->__np_switch_msgpartcache = __np_switchwindow_new(context, COLOR_PAIR(5), term_current_width, term_height_top_left);

                }
                if (ud->statistic_types == np_stat_all || (ud->statistic_types & np_stat_memory) == np_stat_memory) {
                    ud->__np_switch_memory_ext = __np_switchwindow_new(context, COLOR_PAIR(6), term_current_width, term_height_top_left);
                }
                if (ud->statistic_types == np_stat_all || (ud->statistic_types & np_stat_performance) == np_stat_performance) {
                    ud->__np_switch_performance = __np_switchwindow_new(context, COLOR_PAIR(6), term_current_width, term_height_top_left);
                }
                if (ud->statistic_types == np_stat_all || (ud->statistic_types & np_stat_jobs) == np_stat_jobs) {
                    ud->__np_switch_jobs = __np_switchwindow_new(context, COLOR_PAIR(6), term_current_width, term_height_top_left);
                }
                ud->__np_switch_interactive = __np_switchwindow_new(context, COLOR_PAIR(6), term_current_width, term_height_top_left);;
                ud->__np_switch_log = __np_switchwindow_new(context, COLOR_PAIR(6), term_current_width, term_height_top_left);
                __np_switchwindow_show(context, ud->__np_switch_log);
                if (ud->__log_buffer != NULL)
                    __np_switchwindow_update_buffer(context, ud->__np_switch_log, ud->__log_buffer, -999999);
            }

            ud->__np_bottom_win_help = newwin(term_height_help, term_current_width, term_current_height - term_height_help, 0);
            wbkgd(ud->__np_bottom_win_help, COLOR_PAIR(4));
        }
    }
    else {
        __np_example_print_help(ud);
    }
}

void __np_example_reset_ncurse(np_context*context) {
    __np_example_deinti_ncurse(context);
    __np_example_inti_ncurse(context);
}
void resizeHandler(NP_UNUSED int sig)
{
    __np_terminal_resize_flag = true;
}

void _np_interactive_http_mode(np_context* context, char* buffer) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));

    if (strncmp(buffer, "0", 2) == 0 || strncmp(buffer, "Off", 4) == 0) {
        if (ud->_np_httpserver_active) {
            example_http_server_deinit(context);
            ud->_np_httpserver_active = false;
        }
    }
    else if (strncmp(buffer, "1", 2) == 0 || strncmp(buffer, "On", 3) == 0) {
        if (ud->_np_httpserver_active) {
            example_http_server_deinit(context);
        }
        ud->_np_httpserver_active = example_http_server_init(context, ud->opt_http_domain, ud->opt_sysinfo_mode);
    }
    else {
        np_example_print(context, stdout, "Setting http domain to \"%s\" and (re)starting HTTP server.", buffer);
        free(ud->opt_http_domain);
        ud->opt_http_domain = strdup(buffer);
        if (ud->_np_httpserver_active) {
            example_http_server_deinit(context);
        }
        ud->_np_httpserver_active = example_http_server_init(context, ud->opt_http_domain, ud->opt_sysinfo_mode);

    }
}
void _np_interactive_quit(np_context* context, char* buffer) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));

    if (strncmp(buffer, "1", 2) == 0 ||
        strncmp(buffer, "y", 1) == 0 ){
        if (ud->_np_httpserver_active) {
            example_http_server_deinit(context);
            ud->_np_httpserver_active = false;
        }
        __np_example_deinti_ncurse(context);
        np_destroy(context, true);
        exit(EXIT_SUCCESS);
    }
}

void _np_interactive_join(np_context* context, char* buffer) {

    np_example_print(context, stdout, "Try to join network at \"%s\".", buffer);
    np_join(context, buffer);
}
void _np_interactive_sysinfo_mode(np_context* context, char* buffer) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));
    /*
    "Sysinfo mode:\n"
        "0/Off\n"
        "1/Auto\n"
        "2/Master\n"
        "3/Client\n"
        */
    if (strncmp(buffer, "0", 2) == 0 || strncmp(buffer, "1", 2) == 0 || strncmp(buffer, "2", 2) == 0 || strncmp(buffer, "3", 2) == 0) {
        ud->opt_sysinfo_mode = atoi(buffer);
        if (ud->_np_httpserver_active) {
            np_example_print(context, stdout, "Restarting HTTP server.");
            example_http_server_deinit(context);
            ud->_np_httpserver_active = example_http_server_init(context, ud->opt_http_domain, ud->opt_sysinfo_mode);
        }
    }
    else {
        np_example_print(context, stderr, "Sysinfo mode \"%s\" not supported.", buffer);
    }
}

void __np_example_helper_loop(np_state_t* context) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));
    if (ud->__np_ncurse_initiated == true && __np_terminal_resize_flag == true) {
        __np_example_reset_ncurse(context);
        __np_terminal_resize_flag = false;
    }

    // Runs only once
    if (ud->started_at == 0) {
        ud->started_at = np_time_now();

        if (FLAG_CMP(ud->user_interface, np_user_interface_ncurse)) {
            signal(SIGWINCH, resizeHandler);
            __np_example_inti_ncurse(context);
        }

        np_print_startup(context);
        // starting the example http server to support the http://view.neuropil.io application
        ud->_np_httpserver_active = example_http_server_init(context, ud->opt_http_domain, ud->opt_sysinfo_mode);
    }

    double sec_since_start = np_time_now() - ud->started_at;

    if ((sec_since_start - ud->last_loop_run_at) > ud->output_intervall_sec)
    {
        ud->last_loop_run_at = sec_since_start;

        if (FLAG_CMP(ud->user_interface, np_user_interface_ncurse)) {
            mvwprintw(ud->__np_top_logo_win, 0, 0, "%s", logo);
        }

        char* memory_str;

        if (ud->statistic_types == np_stat_all || (ud->statistic_types & np_stat_memory) == np_stat_memory) {
            if (FLAG_CMP(ud->user_interface, np_user_interface_ncurse) || FLAG_CMP(ud->user_interface, np_user_interface_console)) {
                memory_str = np_mem_printpool(context, false, false);
                if (memory_str != NULL) {
                    if (FLAG_CMP(ud->user_interface, np_user_interface_ncurse)){
                        mvwprintw(ud->__np_top_right_win, 0, 0, "%s", memory_str);
                    }
                    if (FLAG_CMP(ud->user_interface, np_user_interface_console)){
                        np_example_print(context, stdout, memory_str);
                    }
                }
                free(memory_str);

                if (FLAG_CMP(ud->user_interface, np_user_interface_ncurse) && ud->_current == ud->__np_switch_memory_ext) {
                    memory_str = np_mem_printpool(context, false, true);
                    if (memory_str != NULL) {
                        __np_switchwindow_update_buffer(context, ud->__np_switch_memory_ext, memory_str, 0);
                    }
                    free(memory_str);
                }

                if (FLAG_CMP(ud->user_interface, np_user_interface_console)) {
                    memory_str = np_mem_printpool(context, false, true);
                    np_example_print(context, stdout, memory_str);
                    free(memory_str);
                }
            }
            if (FLAG_CMP(ud->user_interface, np_user_interface_log)) {
                memory_str = np_mem_printpool(context, true, true);
                if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
                free(memory_str);
            }
        }

        if (ud->statistic_types == np_stat_all || (ud->statistic_types & np_stat_performance) == np_stat_performance) {
            if (FLAG_CMP(ud->user_interface, np_user_interface_ncurse) && ud->_current == ud->__np_switch_performance) {
                NP_PERFORMANCE_GET_POINTS_STR(memory);

                if (memory != NULL) {
                    __np_switchwindow_update_buffer(context, ud->__np_switch_performance, memory, 0);
                }
                free(memory);

            }
            if (FLAG_CMP(ud->user_interface, np_user_interface_console)) {
                NP_PERFORMANCE_GET_POINTS_STR(memory);

                if (memory != NULL) {
                    np_example_print(context, stdout, memory);
                    free(memory);
                }
            }

            if (FLAG_CMP(ud->user_interface, np_user_interface_log)) {
                NP_PERFORMANCE_GET_POINTS_STR(memory);
                if (memory != NULL) log_msg(LOG_INFO, "%s", memory);
                free(memory);
            }
        }

        if (ud->statistic_types == np_stat_all || (ud->statistic_types & np_stat_jobs) == np_stat_jobs) {
            if (FLAG_CMP(ud->user_interface, np_user_interface_ncurse)) {
                if (ud->_current == ud->__np_switch_jobs) {
                    memory_str = np_jobqueue_print(context, false);
                    if (memory_str != NULL) {
                        __np_switchwindow_update_buffer(context, ud->__np_switch_jobs, memory_str, 0);
                    }
                    free(memory_str);
                }
            }
            if (FLAG_CMP(ud->user_interface, np_user_interface_console)) {
                memory_str = np_jobqueue_print(context, false);
                if (memory_str != NULL) np_example_print(context, stdout, memory_str);
                free(memory_str);
            }

            if (FLAG_CMP(ud->user_interface, np_user_interface_log)) {
                memory_str = np_jobqueue_print(context, true);
                if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
                free(memory_str);
            }
        }

        if (ud->statistic_types == np_stat_all || (ud->statistic_types & np_stat_msgpartcache) == np_stat_msgpartcache) {
            if (FLAG_CMP(ud->user_interface, np_user_interface_ncurse) || FLAG_CMP(ud->user_interface, np_user_interface_console)) {

                memory_str = np_messagepart_printcache(context, false);
                if (memory_str != NULL) {
                    if (FLAG_CMP(ud->user_interface, np_user_interface_ncurse) && ud->_current == ud->__np_switch_msgpartcache) {

                        __np_switchwindow_update_buffer(context, ud->__np_switch_msgpartcache, memory_str, 0);
                    }
                    if (FLAG_CMP(ud->user_interface, np_user_interface_console)) {
                        np_example_print(context, stdout, memory_str);
                    }
                }
                free(memory_str);
            }

            if (FLAG_CMP(ud->user_interface, np_user_interface_log)) {
                memory_str = np_messagepart_printcache(context, true);
                if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
                free(memory_str);
            }
        }
#ifdef DEBUG
        if (ud->statistic_types == np_stat_all || (ud->statistic_types & np_stat_locks) == np_stat_locks) {
            if (FLAG_CMP(ud->user_interface, np_user_interface_ncurse) || FLAG_CMP(ud->user_interface, np_user_interface_console)) {
                memory_str = np_threads_printpool(context, false);
                if (memory_str != NULL) {
                    if (FLAG_CMP(ud->user_interface, np_user_interface_ncurse)){
                        mvwprintw(ud->__np_top_right_win, 0, 0, "%s", memory_str);
                    }
                    if (FLAG_CMP(ud->user_interface, np_user_interface_console)){
                        np_example_print(context, stdout, memory_str);
                    }
                }
                free(memory_str);
            }
            if (FLAG_CMP(ud->user_interface, np_user_interface_log)) {
                memory_str = np_threads_printpool(context, true);
                if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
                free(memory_str);
            }
        }
#endif
        if (ud->statistic_types == np_stat_all || (ud->statistic_types & np_stat_general) == np_stat_general) {
            char time[50] = { 0 };
            reltime_to_str(time, sec_since_start);

            if (FLAG_CMP(ud->user_interface, np_user_interface_ncurse) || FLAG_CMP(ud->user_interface, np_user_interface_console)) {
                memory_str = np_statistics_print(context, false);

                if (memory_str != NULL) {
                    if (FLAG_CMP(ud->user_interface, np_user_interface_ncurse)) {
                        mvwprintw(ud->__np_top_left_win, 0, 0, "%s - BUILD IN "
#if defined(DEBUG)
                            "DEBUG"
#elif defined(RELEASE)
                            "RELEASE"
#else
                            "NON DEBUG and NON RELEASE"
#endif
                            " (%s)\n%s ", time, NEUROPIL_RELEASE, memory_str);
                    }
                    if (FLAG_CMP(ud->user_interface, np_user_interface_console)) {
                        np_example_print(context, stdout, memory_str);
                    }
                }
                free(memory_str);
            }
            if (FLAG_CMP(ud->user_interface, np_user_interface_log)) {
                memory_str = np_statistics_print(context, true);
                if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
                free(memory_str);
            }
        }

        if (ud->__np_ncurse_initiated == true) {
            wrefresh(ud->__np_bottom_win_help);
            wrefresh(ud->__np_top_left_win);
            wrefresh(ud->__np_top_right_win);
            wrefresh(ud->__np_top_logo_win);
            __np_switchwindow_draw(context);
            __np_example_print_help(ud);
        }
    }

    if (ud->__np_ncurse_initiated == true) {
        int key = getch();
        if (key != ERR) {
            if (ud->is_in_interactive) {
                __np_switchwindow_interactive_incomming(context, key);
            }
            else {
                switch (key) {
                case KEY_RESIZE:
                case 101:	// e
                case 69:	// E
                    __np_example_reset_ncurse(context);
                    break;
                case 99:	// c
                case 67:	// C
                    __np_switchwindow_show(context, ud->__np_switch_msgpartcache);
                    break;
                case 112:	// p
                case 80:	// P
                    __np_switchwindow_show(context, ud->__np_switch_performance);
                    break;
                case 109:	// m
                case 77:	// M
                    __np_switchwindow_show(context, ud->__np_switch_memory_ext);
                    break;
                case 108:	// l
                case 76:	// L
                    __np_switchwindow_show(context, ud->__np_switch_log);
                    break;
                case 111:	// o
                case 79:	// O
                    __np_switchwindow_show(context, ud->__np_switch_jobs);
                    break;
                case 102:	// f
                case 70:	// F
                    __np_switchwindow_scroll(context, ud->_current, -999999, true);
                    break;
                case 117:	// u
                case 85:	// U
                case KEY_UP:
                    __np_switchwindow_scroll(context, ud->_current, -1, true);
                    break;
                case 110:	// n
                case 78:	// N
                case KEY_DOWN:
                    __np_switchwindow_scroll(context, ud->_current, 1, true);
                    break;
                case 104:	// h
                case 72:	// H
                    __np_switchwindow_configure_interactive(context,
                        "Sysinfo mode:\n"
                        "0/Off\n"
                        "1/On\n"
                        "any other input reconfigures the listening domain\n"
                        , _np_interactive_http_mode
                    );
                    break;
                case 115:	// s
                case 83:	// S
                    __np_switchwindow_configure_interactive(context,
                        "Sysinfo mode:\n"
                        "0/Off\n"
                        "1/Auto\n"
                        "2/Master\n"
                        "3/Client\n"
                        , _np_interactive_sysinfo_mode
                    );
                    break;
                case 106:	// j
                case 74:	// J
                    __np_switchwindow_configure_interactive(context,
                        "Connection string:\n"
                        , _np_interactive_join
                    );
                    break;
                case 113: // q
                    __np_switchwindow_configure_interactive(context,
                        "Quit:\n"
                        "0/n/no/cancel\n"
                        "1/y/yes\n"
                        , _np_interactive_quit
                    );
                    break;
                }
            }
        }
    }
}

void __np_example_helper_run_loop(np_context*context) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));
    double sleep = ud->input_intervall_sec;
    while (true)
    {
        if(((np_state_t*)context)->settings->n_threads == 0)
            sleep = fmin(ud->input_intervall_sec, np_run(context,0));
        np_time_sleep(sleep);
    }
}

void __np_example_helper_run_info_loop(np_context*context) {
    example_user_context* ud = ((example_user_context*)np_get_userdata(context));
    double sleep = ud->input_intervall_sec;
    while (true)
    {
        __np_example_helper_loop(context);
        if (((np_state_t*)context)->settings->n_threads == 0)
            sleep = fmin(ud->input_intervall_sec, np_run(context,0));
        np_time_sleep(sleep);
    }
}

#include "web/np_http.c"
