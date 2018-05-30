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

#include <curses.h>
#include <ncurses.h>
#include "sodium.h"

#include "neuropil.h"
#include "np_types.h"
#include "np_memory.h"
#include "np_threads.h"
#include "np_http.h"
#include "np_util.h"
#include "np_key.h"
#include "np_list.h"
#include "np_identity.h"
#include "np_sysinfo.h"
#include "np_log.h"
#include "np_messagepart.h"
#include "np_jobqueue.h"
#include "np_statistics.h"

np_bool __np_ncurse_initiated = FALSE; 
const float output_intervall_sec = 0.5;

extern char *optarg;
extern int optind;

uint8_t enable_statistics = 1;
double started_at = 0;
double last_loop_run_at = 0;

enum np_sysinfo_opt_e {
	np_sysinfo_opt_disable = 0,
	np_sysinfo_opt_auto = 1,
	np_sysinfo_opt_force_master = 2,
	np_sysinfo_opt_force_slave = 3
} typedef np_sysinfo_opt_e;

enum np_statistic_types_e {
	np_stat_all = 0x000,
	np_stat_general = 0x001,
	np_stat_locks = 0x002,
	np_stat_msgpartcache = 0x004,
	np_stat_memory = 0x008,
	np_stat_performance = 0x010,
	np_stat_jobs = 0x020,
} typedef np_statistic_types_e;

np_statistic_types_e statistic_types = 0;


struct __np_switchwindow_scrollable {
	np_mutex_t access;
	WINDOW * win;
	char * buffer;
	int cursor;
};
const int rows_in_switchable = 15;


struct __np_switchwindow_scrollable * _current = NULL;

void __np_switchwindow_draw() {

	
	if (__np_ncurse_initiated == TRUE && _current != NULL) {
		_LOCK_ACCESS(&_current->access) {
			int displayedRows = 0;

			char * buffer = strdup(_current->buffer);
			char* line = strtok(buffer, "\n");
			int y = 0;
			werase(_current->win);
			if (line != NULL) {
				do {
					// clean line from escapes
					for (int c = 0; c < strlen(line); c++)
						if (line[c] < 32 || line[c] > 126) line[c] = ' ';

					if (y >= _current->cursor) {						
						mvwprintw(_current->win, displayedRows, 0, line);
						displayedRows++;						
					}
					y++;
				} while ((line = strtok(NULL, "\n")) != NULL && displayedRows <= rows_in_switchable);
			}
			 
			wrefresh(_current->win);
			free(buffer);
		}
	}
}

void __np_switchwindow_show(struct __np_switchwindow_scrollable *target) {	
	if (_current == NULL)
	{
		_current = target;
	}
	else {
		_LOCK_ACCESS(&_current->access) {
			_current = target;
		}
	}
}
void __np_switchwindow_scroll_check_bounds(struct __np_switchwindow_scrollable *target) {	
	int lines = 0;
	for (int c = 0; c < strlen(target->buffer); c++) {
		if (target->buffer[c] == '\n') lines++;
	}
	int max_scroll =  lines - rows_in_switchable;
	
	if (max_scroll <= 0)
	{
		target->cursor = 0;
	}else{
		if (target->cursor > max_scroll) 
			target->cursor = max_scroll;
		else 
			target->cursor = max(0, target->cursor);
	}
}

void __np_switchwindow_scroll(struct __np_switchwindow_scrollable *target, int relative) {

	_LOCK_ACCESS(&target->access) {
		target->cursor += relative;
		__np_switchwindow_scroll_check_bounds(target);
	}
	if (_current == target)__np_switchwindow_draw();
} 

void __np_switchwindow_update_buffer(struct __np_switchwindow_scrollable * target, char* buffer, int scroll_relative) {
	
	_LOCK_ACCESS(&target->access) {
		free(target->buffer);
 		target->buffer = strdup(buffer);
		__np_switchwindow_scroll(target, scroll_relative);
	}

}

struct __np_switchwindow_scrollable * __np_switchwindow_new(chtype color_pair) {
	struct __np_switchwindow_scrollable * ret = calloc(1, sizeof(struct __np_switchwindow_scrollable));

	_np_threads_mutex_init(&ret->access, "__np_switchwindow_scrollable->access");

	int h = rows_in_switchable, w = 140, x = 0, y = 39;
	ret->win = newwin(h, w, y, x);
	wbkgd(ret->win, color_pair);
	scrollok(ret->win, TRUE);

	__np_switchwindow_update_buffer(ret, "initiated", 0);

	return ret;
}

void __np_switchwindow_del(struct __np_switchwindow_scrollable * self) {	
	_LOCK_ACCESS(&self->access) {
		if (_current == self) _current = NULL;
		delwin(self->win);
	}
	_np_threads_mutex_destroy(&self->access);
	free(self);
}
WINDOW * __np_stat_general_win;
WINDOW * __np_stat_locks_win;
WINDOW * __np_stat_memory_win;
WINDOW * __np_help_win;


struct __np_switchwindow_scrollable * __np_switch_log;
struct __np_switchwindow_scrollable * __np_switch_msgpartcache;
struct __np_switchwindow_scrollable * __np_switch_memory_ext;
struct __np_switchwindow_scrollable * __np_switch_log;
struct __np_switchwindow_scrollable * __np_switch_performance;
struct __np_switchwindow_scrollable * __np_switch_jobs;


#define LOG_BUFFER_SIZE (3000)
char * __log_buffer = NULL;
char * __log_buffer_cursor = 0;

void np_print_startup();

void np_example_print(FILE * stream, const char * format, ...) {
	np_print_startup();
	va_list args, args2;
	va_start(args, format);
	va_start(args2, format);

	char* buffer = calloc(1, 500);
	int to_add_size = vsnprintf(buffer, 500, format, args);

	if (to_add_size > 0) {
		to_add_size = min(500 - 1, to_add_size);
		if (__log_buffer == NULL) __log_buffer = calloc(1, LOG_BUFFER_SIZE); // TODO: move to an init

		int total_to_add_size = to_add_size + 1; // '\n' append
		int rescued_buffer_size = LOG_BUFFER_SIZE - total_to_add_size - 1/*NULL Term*/;

		// move existing memory		
		memmove(&__log_buffer[total_to_add_size], __log_buffer, rescued_buffer_size);
		// copy new 
		memcpy(__log_buffer, buffer, to_add_size);
		// append \n
		memset(&__log_buffer[to_add_size], '\n', 1);
		// always terminate string
		memset(&__log_buffer[LOG_BUFFER_SIZE - 1], '\0', 1);

		// count lines to scroll accordingly
		int lines = 0;
		for (int c = 0; c < to_add_size; c++) {
			if (buffer[c] == '\n') lines++;
		}
		if (__np_ncurse_initiated) {
			__np_switchwindow_update_buffer(__np_switch_log, __log_buffer, -1 * lines);
		}
		else {
			vfprintf(stream, format, args2);
			fflush(stream);
		}
	}
	free(buffer);

	va_end(args);
	va_end(args2);
}


void example_http_server_init(char* http_domain, np_sysinfo_opt_e opt_sysinfo_mode) {	
	np_bool http_init = FALSE;
	if (http_domain == NULL || (strncmp("none", http_domain, 5) != 0 && strncmp("false", http_domain, 5) != 0 && strncmp("FALSE", http_domain, 5) != 0 && strncmp("0", http_domain, 2) != 0)) {
		if (http_domain == NULL) {
			http_domain = calloc(1, sizeof(char) * 255);
			CHECK_MALLOC(http_domain);
			if (np_get_local_ip(http_domain, 255) == FALSE) {
				free(http_domain);
				http_domain = NULL;
			}
		}
		http_init = np_http_init(http_domain);
		if (http_init == FALSE) {
			log_msg(LOG_WARN, "Node could not start HTTP interface");
		}
	}
	if (opt_sysinfo_mode != np_sysinfo_opt_disable) {
		if ((http_init && opt_sysinfo_mode == np_sysinfo_opt_auto) || opt_sysinfo_mode == np_sysinfo_opt_force_master)
		{
			np_example_print(stdout, "HTTP interface set to %s\n", http_domain);
			log_msg(LOG_INFO, "HTTP interface set to %s", http_domain);
			np_example_print(stdout, "Enable sysinfo master option\n");
			np_sysinfo_enable_master();
		}
		else {
			fprintf(stdout, "Node could not start HTTP interface\n");
			np_example_print(stdout, "Enable sysinfo slave option\n");
			np_sysinfo_enable_slave();
		}
		np_statistics_add_watch_internals();

		// If you want to you can enable the statistics modulte to view the nodes statistics
		np_statistics_add_watch(_NP_SYSINFO_REQUEST);
		np_statistics_add_watch(_NP_SYSINFO_REPLY);

	}
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

char* np_get_startup_str() {
	char* ret = NULL;
	char* new_line = "\n";

	ret = np_str_concatAndFree(ret, new_line);
	ret = np_str_concatAndFree(ret, "%s initializiation successful%s", NEUROPIL_RELEASE, new_line);
	ret = np_str_concatAndFree(ret, "%s event loop with %d worker threads started%s", NEUROPIL_RELEASE, np_state()->thread_count, new_line);
	ret = np_str_concatAndFree(ret, "your neuropil node will be addressable as:%s", new_line);	
	ret = np_str_concatAndFree(ret, new_line);
	char* connection_str = np_get_connection_string();
	ret = np_str_concatAndFree(ret, "\t%s%s", connection_str, new_line);
	free(connection_str);
	ret = np_str_concatAndFree(ret, new_line);
	if(_np_key_cmp(np_state()->my_node_key, np_state()->my_identity) != 0){	
		ret = np_str_concatAndFree(ret, "your neuropil id is addressable via:%s", new_line);
		ret = np_str_concatAndFree(ret, "\t%s%s", _np_key_as_str(np_state()->my_identity), new_line);	
		ret = np_str_concatAndFree(ret, new_line);
	}
	
	ret = np_str_concatAndFree(ret, "%s%s", NEUROPIL_COPYRIGHT, new_line);
	ret = np_str_concatAndFree(ret, "%s%s", NEUROPIL_TRADEMARK, new_line);
	ret = np_str_concatAndFree(ret, new_line);

	return ret;
}
bool _printed_startup = false;
void np_print_startup() {
	if (_printed_startup == false) {
		_printed_startup = true;
		char* ret = np_get_startup_str();
		np_example_print(stdout, ret);
		//log_msg(LOG_INFO, ret);
		free(ret);
	}
}

enum np_example_load_identity_status {
	np_example_load_identity_status_success = 1,
	np_example_load_identity_status_not_found = 0,
	np_example_load_identity_status_found_but_failed = -1,
};
np_bool identity_opt_is_set = FALSE;
char identity_filename[255] = { 0 };
char identity_passphrase[255] = { 0 };

unsigned char salt[crypto_pwhash_SALTBYTES] = { 123 };
unsigned char nonce[crypto_secretbox_NONCEBYTES] = { 123 };
unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
np_bool key_is_gen = FALSE;


np_bool np_example_save_identity(char* passphrase, char* filename) {
	np_bool  ret = FALSE;

	unsigned char buffer[5000] = { 0 };
	size_t token_size = np_identity_export_current(&buffer);

	int tmp = 0;
	if (!key_is_gen &&
		(tmp = crypto_pwhash(
			key,
			sizeof key,
			passphrase,
			strlen(passphrase),
			salt,
			crypto_pwhash_OPSLIMIT_INTERACTIVE,
			crypto_pwhash_MEMLIMIT_INTERACTIVE	,
			crypto_pwhash_ALG_ARGON2ID13
		)) != 0
	) {			
		log_debug_msg(LOG_DEBUG, "Error creating key! (%"PRIi32")",tmp);
	} else {
		key_is_gen = TRUE;
	}

	if(key_is_gen) {
		unsigned char crypted_data[token_size + crypto_secretbox_MACBYTES];
		memset(crypted_data, 0, sizeof crypted_data);

		if (0 != crypto_secretbox_easy(
			crypted_data,
			buffer,
			token_size,
			nonce,
			key)) {			
			log_debug_msg(LOG_DEBUG, "Error encrypting file!");
		}
		else {
			FILE *f = fopen(filename, "wb");
			if (f != NULL) {
				if (fwrite(crypted_data, sizeof crypted_data, 1, f) == 1) {
					ret = TRUE;
				}
			}
			fclose(f);
		}
		
	}
	return ret;
}
enum np_example_load_identity_status  np_example_load_identity(char* passphrase, char* filename) {
	enum np_example_load_identity_status ret = np_example_load_identity_status_not_found;
	FILE *f = fopen(filename, "rb");
	if (f != NULL)
	{
		ret = np_example_load_identity_status_found_but_failed;
		if (!key_is_gen &&
			crypto_pwhash(
				key,
				sizeof key,
				passphrase,
				strlen(passphrase),
				salt,
				crypto_pwhash_OPSLIMIT_INTERACTIVE,
				crypto_pwhash_MEMLIMIT_INTERACTIVE,
				crypto_pwhash_ALG_ARGON2ID13
			) != 0) {
			log_debug_msg(LOG_DEBUG, "Error creating key!");
		}
		else {
			key_is_gen = TRUE;
		}
		if(key_is_gen){
			
			struct stat info;
			stat(filename, &info);
			char* crypted_data = (char *)malloc(info.st_size);
			fread(crypted_data, info.st_size, 1, f);

			unsigned char buffer[info.st_size- crypto_secretbox_MACBYTES];

			if (0 == crypto_secretbox_open_easy(
				buffer,
				crypted_data,
				info.st_size,
				nonce,
				key)
			) {				
				np_aaatoken_t* token =  np_identity_import(&buffer, sizeof buffer);				
				if (token == NULL) {
					log_debug_msg(LOG_DEBUG, "Error deserializing aaatoken!");
				}
				else {
					np_set_identity(token);
				}

				ret = np_example_load_identity_status_success;
			}
			free(crypted_data);
		}
		fclose(f);
	}
	return ret;
}

void np_example_save_or_load_identity() {

	if (identity_opt_is_set) {
		np_example_print(stdout, "Try to load ident file.\n");
		enum np_example_load_identity_status load_status;
		if ((load_status = np_example_load_identity(identity_passphrase, identity_filename)) == np_example_load_identity_status_not_found) {
			
			np_example_print(stdout, "Load detected no available token file. Try to save current ident to file.\n");
			if (!np_example_save_identity(identity_passphrase, identity_filename)) {				
				np_example_print(stdout, "Cannot load or save identity file. error(%"PRIi32"): %s. file: \"%s\"\n", errno, strerror(errno), identity_filename);
				exit(EXIT_FAILURE);
			}
			else {
				np_example_print(stdout, "Saved current ident (%s) to file.\n", _np_key_as_str(np_state()->my_identity));
				/*
				if (!np_example_load_identity(identity_passphrase, identity_filename)) {
					np_example_print(stdout, "Cannot load after save of identity file. error(%"PRIi32"): %s. file: \"%s\"\n", errno, strerror(errno), identity_filename);
					exit(EXIT_FAILURE);
				}
				*/				
			}			
		}
		else {
			if (load_status == np_example_load_identity_status_success) {
				np_example_print(stdout, "Loaded ident(%s) from file.\n", _np_key_as_str(np_state()->my_identity));
			}else if (load_status == np_example_load_identity_status_found_but_failed) {
				np_example_print(stdout, "Could not load from file.\n");
			}
			else {
				np_example_print(stdout, "Unknown np_example_load_identity_status\n");
			}
		}
	}
}

char* opt_http_domain = NULL;
int opt_sysinfo_mode = 1;

np_bool parse_program_args(
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
	np_bool ret = TRUE;
	char* usage;
	asprintf(&usage,
		"./%s [ p-j key:proto:host:port ] [ -p protocol] [-b port] [-t (> 0) worker_thread_count ] [-u publish_domain] [-d loglevel] [-l logpath] [-s statistics 0=Off 1=Console 2=Log 3=1&2] [-y statistic types 0=All 1=general 2=locks ] [-i identity filename] [-a passphrase for identity file]  [-w http domain] [-o sysinfo 0=none,1=auto,2=master,3=slave]%s",
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
				ret = FALSE;
			}
			break;
		case 'p':
			*proto = strdup(optarg);
			break;
		case 'u':
			*publish_domain = strdup(optarg);
			break;
		case 'w':
			opt_http_domain = strdup(optarg);
			break;
		case 'o':
			opt_sysinfo_mode = atoi(optarg);
			break;
		case 'd':
			(*level) = atoi(optarg);
			break;
		case 's':
			enable_statistics = atoi(optarg);
			break;
		case 'y':
			statistic_types = atoi(optarg);
			break;
		case 'b':
			*port = strdup(optarg);
			break;
		case 'i':
			identity_opt_is_set = TRUE;
			strncpy(identity_filename, optarg, strnlen(optarg,254));
			break;
		case 'a':
			strncpy(identity_passphrase, optarg, strnlen(optarg, 254));
			break;
		case 'l':
			if (optarg != NULL) {
				*logpath = strdup(optarg);
			}
			else {
				fprintf(stderr, "invalid option %c\n", (char)opt);
				ret = FALSE;
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
				ret = FALSE;
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
			//| LOG_TRACE
			//| LOG_MUTEX
			| LOG_ROUTING
			//| LOG_HTTP
			//| LOG_KEY
			| LOG_NETWORK
			//| LOG_AAATOKEN
			//| LOG_SYSINFO
			//| LOG_MESSAGE
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

			*port = calloc(1, sizeof(char) * 7);

			sprintf(*port, "%d", port_pid);
			if (port_pid > 65535) {
				sprintf(*port, "%d", (port_pid >> 1));
			}
			if (port_pid < 1024) {
				sprintf(*port, "%d", (port_pid + 1024));
			}
		}
		/** \endcode */
	}
	else {
		fprintf(stderr, "usage: %s\n", usage);
	}
	free(usage);

	return ret;
}

void __np_example_deinti_ncurse() {
	if (__np_ncurse_initiated == TRUE) {
		__np_ncurse_initiated = FALSE;

		delwin(__np_stat_general_win);
		delwin(__np_stat_memory_win);
		delwin(__np_stat_locks_win);
		delwin(__np_help_win);

		__np_switchwindow_del(__np_switch_memory_ext);
		__np_switchwindow_del(__np_switch_log);
		__np_switchwindow_del(__np_switch_msgpartcache);
		__np_switchwindow_del(__np_switch_performance);		

		endwin();
	}
}

void __np_example_inti_ncurse() {
	if (FALSE == __np_ncurse_initiated) {
		if (enable_statistics == 1 || enable_statistics % 2 != 0) {

			__np_ncurse_initiated = TRUE;
			
			/* Start curses mode          */
			//initscr(); // Init ncurses mode
			// other:
			newterm(NULL, stderr, stdin);    
			FILE *f = fopen("/dev/tty", "r+");
			SCREEN *screen = newterm(NULL, f, f);
			set_term(screen);

			// setup ncurse config
			curs_set(0); // Hide cursor
			noecho();
			nocbreak();
			timeout(0);
			start_color();
			init_pair(1, COLOR_YELLOW, COLOR_BLUE);
			init_pair(2, COLOR_BLUE, COLOR_YELLOW);
			init_pair(3, COLOR_WHITE, COLOR_MAGENTA);
			init_pair(4, COLOR_WHITE, COLOR_BLACK);

			init_pair(5, COLOR_CYAN, COLOR_BLACK);
			init_pair(6, COLOR_GREEN, COLOR_BLACK);
			init_pair(7, COLOR_RED, COLOR_BLACK);

			if (statistic_types == np_stat_all || (statistic_types & np_stat_general) == np_stat_general) {
				__np_stat_general_win = newwin(39, 104, 0, 0);
				wbkgd(__np_stat_general_win, COLOR_PAIR(1));
			}

#ifdef NP_THREADS_CHECK_THREADING
			if (statistic_types == np_stat_all || (statistic_types & np_stat_locks) == np_stat_locks) {
				__np_stat_locks_win = newwin(39, 43, 0, 104);
				wbkgd(__np_stat_locks_win, COLOR_PAIR(2));
			}
#else
			if (statistic_types == np_stat_all || (statistic_types & np_stat_memory) == np_stat_memory) {
				__np_stat_memory_win = newwin(39, 43, 0, 104);
				wbkgd(__np_stat_memory_win, COLOR_PAIR(2));
			}
#endif
			// switchable windows
			{
				
				if (statistic_types == np_stat_all || (statistic_types & np_stat_msgpartcache) == np_stat_msgpartcache) {
				
					__np_switch_msgpartcache = __np_switchwindow_new(COLOR_PAIR(5));

				}
				if (statistic_types == np_stat_all || (statistic_types & np_stat_memory) == np_stat_memory) {
					__np_switch_memory_ext= __np_switchwindow_new(COLOR_PAIR(6));
				}
				if (statistic_types == np_stat_all || (statistic_types & np_stat_performance) == np_stat_performance) {
					__np_switch_performance = __np_switchwindow_new(COLOR_PAIR(6));
				}
				if (statistic_types == np_stat_all || (statistic_types & np_stat_jobs) == np_stat_jobs) {
					__np_switch_jobs = __np_switchwindow_new(COLOR_PAIR(6));
				}
				__np_switch_log = __np_switchwindow_new(COLOR_PAIR(6));
				__np_switchwindow_show(__np_switch_log);
				if(__log_buffer != NULL)
					__np_switchwindow_update_buffer(__np_switch_log, __log_buffer, -999999);
			}

			__np_help_win = newwin(10, 104 + 43, 39 + 15, 0);
			wbkgd(__np_help_win, COLOR_PAIR(4));
			


		}	
	}
	else {
		werase(__np_stat_general_win);
		werase(__np_stat_locks_win);
		werase(__np_stat_memory_win);
		if(_current != NULL) werase(_current->win);

	}
	if (__np_ncurse_initiated) {
		mvwprintw(__np_help_win, 0, 0,
			"(P)erformance/ Message(c)ache / Extended (M)emory / (L)og / (J)obs "
			"| R(e)paint "
			"| Log: (F)ollow / (U)p / dow(N) %"PRId32
		);
		int pos = -1;
		if (_current == __np_switch_performance) pos = 1;
		else if (_current == __np_switch_msgpartcache) pos = 23;
		else if (_current == __np_switch_memory_ext) pos = 42;
		else if (_current == __np_switch_log) pos = 53;
		else if (_current == __np_switch_jobs) pos = 61;
		mvwchgat(__np_help_win, 0, pos, 1, A_UNDERLINE, 4, NULL);

	}
}

void __np_example_reset_ncurse() {
	__np_example_deinti_ncurse();
	__np_example_inti_ncurse();
}

int iteri = -1;

void __np_example_helper_loop() {
	__np_example_inti_ncurse();

	// Runs only once
	if (started_at == 0) {		
		started_at = np_time_now();
		np_print_startup();

		// starting the example http server to support the http://view.neuropil.io application	
		example_http_server_init(opt_http_domain, opt_sysinfo_mode);

		np_example_save_or_load_identity();
	}

	double sec_since_start = np_time_now() - started_at;

	if ((sec_since_start - last_loop_run_at) > output_intervall_sec)
	{
		last_loop_run_at = sec_since_start;
		char* memory_str;

		if (statistic_types == np_stat_all || (statistic_types & np_stat_memory) == np_stat_memory) {
			if (enable_statistics == 1 || enable_statistics > 2) {

				memory_str = np_mem_printpool(FALSE, FALSE);
				if (memory_str != NULL) {
					if (__np_ncurse_initiated == TRUE) {
						mvwprintw(__np_stat_memory_win, 0, 0, "%s", memory_str);
					}
					else {
						np_example_print(stdout, memory_str);
					}
				}
				free(memory_str);

				if (_current == __np_switch_memory_ext) {
					memory_str = np_mem_printpool(FALSE, TRUE);
					if (memory_str != NULL) {
						if (__np_ncurse_initiated == TRUE) {
							__np_switchwindow_update_buffer(__np_switch_memory_ext, memory_str, 0);
						}
						else {
							np_example_print(stdout, memory_str);
						}
					}
					free(memory_str);
				}
			}
			if (enable_statistics >= 2) {
				memory_str = np_mem_printpool(TRUE, TRUE);
				if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
				free(memory_str);
			}
		}
		if (statistic_types == np_stat_all || (statistic_types & np_stat_performance) == np_stat_performance) {
			if (enable_statistics == 1 || enable_statistics > 2) {
				if (_current == __np_switch_performance) {
					NP_PERFORMANCE_GET_POINTS_STR(memory);

					if (memory != NULL) {
						if (__np_ncurse_initiated == TRUE) {
							__np_switchwindow_update_buffer(__np_switch_performance, memory, 0);
						}
						else {
							np_example_print(stdout, memory);
						}
					}
					free(memory);
				}
			}
			if (enable_statistics >= 2) {
				NP_PERFORMANCE_GET_POINTS_STR(memory);
				if (memory != NULL) log_msg(LOG_INFO, "%s", memory);
				free(memory);
			}
		}
		if (statistic_types == np_stat_all || (statistic_types & np_stat_jobs) == np_stat_jobs) {
			if (enable_statistics == 1 || enable_statistics > 2) {
				if (_current == __np_switch_jobs) {
					memory_str = np_jobqueue_print(FALSE);
					if (memory_str != NULL) {
						if (__np_ncurse_initiated == TRUE) {
							__np_switchwindow_update_buffer(__np_switch_jobs, memory_str, 0);
						}
						else {
							np_example_print(stdout, memory_str);
						}
					}
					free(memory_str);
				}
			}
			if (enable_statistics >= 2) {
				memory_str = np_jobqueue_print(TRUE);
				if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
				free(memory_str);
			}
		}

		if (statistic_types == np_stat_all || (statistic_types & np_stat_msgpartcache) == np_stat_msgpartcache) {
			if (enable_statistics == 1 || enable_statistics > 2) {
				if (_current == __np_switch_msgpartcache) {
					memory_str = np_messagepart_printcache(FALSE);
					if (memory_str != NULL) {
						if (__np_ncurse_initiated == TRUE) {
							__np_switchwindow_update_buffer(__np_switch_msgpartcache, memory_str, 0);
						}
						else {
							np_example_print(stdout, memory_str);
						}
					}
					free(memory_str);
				}
				if (enable_statistics >= 2) {
					memory_str = np_messagepart_printcache(TRUE);
					if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
					free(memory_str);
				}
			}
		}
#ifdef DEBUG
		if (statistic_types == np_stat_all || (statistic_types & np_stat_locks) == np_stat_locks) {
			if (enable_statistics == 1 || enable_statistics > 2) {
				memory_str = np_threads_printpool(FALSE);
				if (memory_str != NULL) {
					if (__np_ncurse_initiated == TRUE) {
						mvwprintw(__np_stat_locks_win, 0, 0, "%s", memory_str);
					}
					else {
						np_example_print(stdout, memory_str);
					}
				}
				free(memory_str);
			}
			if (enable_statistics >= 2) {
				memory_str = np_threads_printpool(TRUE);
				if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
				free(memory_str);
			}
		}
#endif
		if (statistic_types == np_stat_all || (statistic_types & np_stat_general) == np_stat_general) {
			char time[50] = { 0 };
			reltime_to_str(time, sec_since_start);

			if (enable_statistics == 1 || enable_statistics > 2) {
				memory_str = np_statistics_print(FALSE);

				if (memory_str != NULL && __np_ncurse_initiated == TRUE) {
					mvwprintw(__np_stat_general_win, 0, 0, "%s - BUILD IN "
#if defined(DEBUG)
						"DEBUG"
#elif defined(RELEASE)
						"RELEASE"
#else
						"NON DEBUG and NON RELEASE"
#endif
						" (%s.%05d)\n%s ", time, NEUROPIL_RELEASE, NEUROPIL_RELEASE_BUILD, memory_str);
				}
				else {
					np_example_print(stdout, memory_str);
				}
				free(memory_str);
			}
			if (enable_statistics >= 2) {
				memory_str = np_statistics_print(TRUE);
				if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
				free(memory_str);
			}	
		}		

		if (__np_ncurse_initiated == TRUE) {
			refresh();
			wrefresh(__np_help_win);
			wrefresh(__np_stat_locks_win);
			wrefresh(__np_stat_general_win);
			__np_switchwindow_draw();

			wrefresh(__np_stat_memory_win);
		}		
	}

	if (__np_ncurse_initiated == TRUE) {
		int key = getch();
		switch (key) {
		case KEY_RESIZE:
		case 101:	// e
		case 69:	// E			
			__np_example_reset_ncurse();
			break;
		case 99:	// c
		case 67:	// C
			__np_switchwindow_show(__np_switch_msgpartcache);
			break;
		case 112:	// p
		case 80:	// P
			__np_switchwindow_show(__np_switch_performance); 
			break;			
		case 109:	// m
		case 77:	// M
			__np_switchwindow_show(__np_switch_memory_ext); 
			break;
		case 108:	// l
		case 76:	// L
			__np_switchwindow_show(__np_switch_log);
			break;
		case 106:	// j
		case 74:	// J
			__np_switchwindow_show(__np_switch_jobs);
			break;
		case 102:	// f
		case 70:	// F
			__np_switchwindow_scroll(_current, -999999);
			break;			
		case 117:	// u
		case 85:	// U
		case KEY_UP:
			__np_switchwindow_scroll(_current,-1);
			break;
		case 110:	// n
		case 78:	// N
		case KEY_DOWN:
			__np_switchwindow_scroll(_current, 1);
			break;
		case 113: // q
			np_destroy();
			exit(EXIT_SUCCESS);
			break;
		}
	}
}

void __np_example_helper_run_loop() {
	double sleep;
	while (TRUE)
	{
		sleep = min(output_intervall_sec, __np_jobqueue_run_jobs_once());
		np_time_sleep(sleep);
	}
}

void __np_example_helper_run_info_loop() {
	double sleep;
	while (TRUE)
	{
		__np_example_helper_loop();
		sleep = min(output_intervall_sec, __np_jobqueue_run_jobs_once());
		np_time_sleep(sleep);
	}
}