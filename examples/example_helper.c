//
// neuropil is copyright 2016-2017 by pi-lar GmbH
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
#include "np_statistics.h"

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
} typedef np_statistic_types_e;

np_statistic_types_e statistic_types = 0;

WINDOW * __np_stat_general_win;
WINDOW * __np_stat_locks_win;
WINDOW * __np_stat_memory_win;
WINDOW * __np_help_win;

WINDOW * __np_stat_msgpartcache_win;
WINDOW * __np_stat_memory_ext;
WINDOW * __np_stat_log;
WINDOW * __np_stat_switchable_window;
np_bool __np_ncurse_initiated = FALSE;
np_bool __np_refresh_windows = TRUE;

#define LOG_BUFFER_SIZE (3000)
np_sll_t(char_ptr, log_buffer);
int log_user_cursor = -1;


void example_http_server_init(char* http_domain, np_sysinfo_opt_e opt_sysinfo_mode) {
	np_bool http_init = FALSE;
	if (http_domain == NULL || (strncmp("none", http_domain, 5) != 0 && strncmp("false", http_domain, 5) != 0 && strncmp("FALSE", http_domain, 5) != 0 && strncmp("0", http_domain, 2) != 0)) {
		if (http_domain == NULL) {
			http_domain = calloc(1, sizeof(char) * 255);
			CHECK_MALLOC(http_domain);
			if (_np_get_local_ip(http_domain, 255) == FALSE) {
				free(http_domain);
				http_domain = NULL;
			}
		}
		http_init = _np_http_init(http_domain);
		if (http_init == FALSE) {
			log_msg(LOG_WARN, "Node could not start HTTP interface");
		}
	}
	if (opt_sysinfo_mode != np_sysinfo_opt_disable) {
		if ((http_init && opt_sysinfo_mode == np_sysinfo_opt_auto) || opt_sysinfo_mode == np_sysinfo_opt_force_master)
		{
			fprintf(stdout, "HTTP interface set to %s\n", http_domain);
			log_msg(LOG_INFO, "HTTP interface set to %s", http_domain);
			np_sysinfo_enable_master();

			// If you want to you can enable the statistics modulte to view the nodes statistics
			np_statistics_add_watch_internals();
			np_statistics_add_watch(_NP_SYSINFO_REQUEST);
			np_statistics_add_watch(_NP_SYSINFO_REPLY);
		}
		else {
			fprintf(stderr, "Node could not start HTTP interface\n");
			np_sysinfo_enable_slave();
		}
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

	ret = _np_concatAndFree(ret, new_line);
	ret = _np_concatAndFree(ret, "%s initializiation successful%s", NEUROPIL_RELEASE, new_line);
	ret = _np_concatAndFree(ret, "%s event loop with %d worker threads started%s", NEUROPIL_RELEASE, _np_state()->thread_count, new_line);
	ret = _np_concatAndFree(ret, "your neuropil node will be addressable as:%s", new_line);
	ret = _np_concatAndFree(ret, new_line);

	char* connection_str = np_get_connection_string();
	ret = _np_concatAndFree(ret, "\t%s%s", connection_str, new_line);
	free(connection_str);

	ret = _np_concatAndFree(ret, new_line);
	ret = _np_concatAndFree(ret, "%s%s", NEUROPIL_COPYRIGHT, new_line);
	ret = _np_concatAndFree(ret, "%s%s", NEUROPIL_TRADEMARK, new_line);
	ret = _np_concatAndFree(ret, new_line);

	return ret;
}

void np_example_print(FILE * stream, const char * format, ...) {
	va_list args;
	va_start(args, format);
	if (__np_ncurse_initiated == FALSE) {
		vfprintf(stream, format, args);
		fflush(stream);
	}
	else {
		char* buffer = calloc(1, 500);
		vsnprintf(buffer, 500, format, args);

		if (buffer[0] != 0) {
			sll_prepend(char_ptr, log_buffer, buffer);

			if (sll_size(log_buffer) > LOG_BUFFER_SIZE) {
				sll_iterator(char_ptr) last = sll_last(log_buffer);
				char* tmp = last->val;
				sll_delete(char_ptr, log_buffer, last);
				free(tmp);
			}
			if (log_user_cursor == 0) {
				wscrl(__np_stat_log, 1);
			}
		}
		else {
			free(buffer);
		}
	}
	va_end(args);
}

void np_print_startup() {
	char* ret = np_get_startup_str();
	np_example_print(stdout, ret);
	free(ret);
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
				np_example_print(stderr, "Cannot load or save identity file. error(%"PRIi32"): %s. file: \"%s\"\n", errno, strerror(errno), identity_filename);
				exit(EXIT_FAILURE);
			}
			else {
				np_example_print(stdout, "Saved current ident (%s) to file.\n", _np_key_as_str(_np_state()->my_identity));
				/*
				if (!np_example_load_identity(identity_passphrase, identity_filename)) {
					np_example_print(stderr, "Cannot load after save of identity file. error(%"PRIi32"): %s. file: \"%s\"\n", errno, strerror(errno), identity_filename);
					exit(EXIT_FAILURE);
				}
				*/				
			}			
		}
		else {
			if (load_status == np_example_load_identity_status_success) {
				np_example_print(stdout, "Loaded ident(%s) from file.\n", _np_key_as_str(_np_state()->my_identity));
			}else if (load_status == np_example_load_identity_status_found_but_failed) {
				np_example_print(stderr, "Could not load from file.\n");
			}
			else {
				np_example_print(stderr, "Unknown np_example_load_identity_status\n");
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
		"./%s [ -j key:proto:host:port ] [ -p protocol] [-b port] [-t (> 0) worker_thread_count ] [-u publish_domain] [-d loglevel] [-l logpath] [-s statistics 0=Off 1=Console 2=Log 3=1&2] [-y statistic types 0=All 1=general 2=locks ] [-i identity filename] [-a passphrase for identity file]  [-w http domain] [-o sysinfo 0=none,1=auto,2=master,3=slave]%s",
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
			if ((*no_threads) <= 0) {
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
			//| LOG_NETWORK
			| LOG_AAATOKEN
			//| LOG_SYSINFO
			//| LOG_MESSAGE
			//| LOG_SERIALIZATION
			//| LOG_MEMORY
			//| LOG_MISC
			//| LOG_EVENT
			| LOG_THREADS
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
		delwin(__np_stat_memory_ext);
		delwin(__np_stat_log);
		delwin(__np_stat_msgpartcache_win);
		delwin(__np_stat_memory_win);
		delwin(__np_stat_locks_win);
		delwin(__np_help_win);
		endwin();
	}
}

void __np_example_inti_ncurse() {
	if (FALSE == __np_ncurse_initiated) {
		if (enable_statistics == 1 || enable_statistics % 2 != 0) {
			if (log_buffer != NULL) {
				sll_iterator(char_ptr) iter_buffer = sll_first(log_buffer);
				while (iter_buffer != NULL)
				{
					free(iter_buffer->val);
					sll_next(iter_buffer);
				}
				sll_free(char_ptr, log_buffer);
			}
			sll_init(char_ptr, log_buffer);
			__np_ncurse_initiated = TRUE;
			initscr(); // Init ncurses mode
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

			if (statistic_types == np_stat_all || (statistic_types & np_stat_locks) == np_stat_locks) {
				__np_stat_locks_win = newwin(39, 43, 0, 104);
				wbkgd(__np_stat_locks_win, COLOR_PAIR(2));
			}

			if (statistic_types == np_stat_all || (statistic_types & np_stat_memory) == np_stat_memory) {
				__np_stat_memory_win = newwin(15, 43, 39, 0);
				wbkgd(__np_stat_memory_win, COLOR_PAIR(3));
			}

			// switchable windows
			{
				int h = 15, w = 103, x = 39, y = 45;
				if (statistic_types == np_stat_all || (statistic_types & np_stat_msgpartcache) == np_stat_msgpartcache) {
					__np_stat_msgpartcache_win = newwin(h, w, x, y);
					wbkgd(__np_stat_msgpartcache_win, COLOR_PAIR(5));
					scrollok(__np_stat_msgpartcache_win, TRUE);

				}
				if (statistic_types == np_stat_all || (statistic_types & np_stat_memory) == np_stat_memory) {
					__np_stat_memory_ext = newwin(h, w, x, y);
					wbkgd(__np_stat_memory_ext, COLOR_PAIR(6));
					scrollok(__np_stat_memory_ext, TRUE);
				}

				__np_stat_log = newwin(h, w, x, y);
				wbkgd(__np_stat_log, COLOR_PAIR(7));
				scrollok(__np_stat_log, TRUE);

				__np_stat_switchable_window = __np_stat_log;
			}

			__np_help_win = newwin(10, 104 + 43, 39 + 15, 0);
			wbkgd(__np_help_win, COLOR_PAIR(4));
			mvwprintw(__np_help_win, 0, 0,
				"Windows: Message(p)arts / Extended (M)emory / (L)og; "
				"General: (S)top output / (R)esume output / R(e)paint "
				"Log: (F)ollow; (U)p; dow(N); "
			);

			wclear(__np_stat_general_win);
			wclear(__np_stat_locks_win);
			wclear(__np_stat_memory_ext);
			wclear(__np_stat_log);
			wclear(__np_stat_msgpartcache_win);
			wclear(__np_stat_memory_win);
		}
	}
	else {
		werase(__np_stat_general_win);
		werase(__np_stat_locks_win);
		werase(__np_stat_switchable_window);
		werase(__np_stat_memory_win);
		werase(__np_stat_msgpartcache_win);
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
				memory_str = np_mem_printpool(FALSE, TRUE);
				if (memory_str != NULL) {
					if (__np_ncurse_initiated == TRUE) {
						mvwprintw(__np_stat_memory_ext, 0, 0, "%s", memory_str);
					}
					else {
						np_example_print(stdout, memory_str);
					}
				}
				free(memory_str);
			}
			if (enable_statistics >= 2) {
				memory_str = np_mem_printpool(TRUE, TRUE);
				if (memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str);
				free(memory_str);
			}
		}

#ifdef DEBUG
		if (statistic_types == np_stat_all || (statistic_types & np_stat_msgpartcache) == np_stat_msgpartcache) {
			if (enable_statistics == 1 || enable_statistics > 2) {
				memory_str = np_messagepart_printcache(FALSE);
				if (memory_str != NULL) {
					if (__np_ncurse_initiated == TRUE) {
						mvwprintw(__np_stat_msgpartcache_win, 0, 0, "%s", memory_str);
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
						"\n%s", time, memory_str);
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

			if (__np_ncurse_initiated == TRUE && __np_stat_switchable_window == __np_stat_log) {
				static int old_log_user_cursor;

				if(old_log_user_cursor != log_user_cursor){
					char* b = _sll_char_make_flat(log_buffer);
					mvwprintw(__np_stat_log, 0, 0, "%s", b);
					free(b);
					old_log_user_cursor = log_user_cursor;
				}

				/*
				int y = 0;
				int displayedRows = 0;
				sll_iterator(char_ptr) iter_log = sll_first(log_buffer);

				while (iter_log != NULL)
				{
					if (y >= log_user_cursor) {
						mvwprintw(__np_stat_log, displayedRows, 0, "%s", iter_log->val);

						// count newlines in string
						int i, count;
						for (i = 0, count = 0; iter_log->val[i]; i++)
							count += (iter_log->val[i] == '\n');

						displayedRows += count + 1;

						if (displayedRows > 15) {
							break;
						}
					}

					sll_next(iter_log);
					y++;
				}
				*/
				mvwprintw(__np_stat_log, 16, 0, "%"PRIu32"items in log", sll_size(log_buffer));
			}
		}

		if (__np_ncurse_initiated == TRUE && __np_refresh_windows == TRUE) {
			wrefresh(__np_help_win);
			wrefresh(__np_stat_locks_win);
			wrefresh(__np_stat_general_win);
			wrefresh(__np_stat_switchable_window);
			wrefresh(__np_stat_memory_win);
		}
	}

	if (__np_ncurse_initiated == TRUE) {
		int key = getch();
		switch (key) {
		case KEY_RESIZE:
		case 101:	// e
			__np_example_reset_ncurse();
			break;
		case 112:	// p
		case 80:	// P
			__np_stat_switchable_window = __np_stat_msgpartcache_win;
			log_user_cursor = 0;
			break;
		case 109:	// m
		case 77:	// M
			__np_stat_switchable_window = __np_stat_memory_ext;
			log_user_cursor = 0;
			break;
		case 108:	// l
		case 76:	// L
			__np_stat_switchable_window = __np_stat_log;
			log_user_cursor = 0;
			break;
		case 115:	// s
		case 83:	// S
			__np_refresh_windows = FALSE;
			break;

		case 114:	// r
		case 82:	// R
			__np_refresh_windows = TRUE;
			break;
		case 102:	// f
		case 70:	// F
			wscrl(__np_stat_switchable_window, log_user_cursor);
			log_user_cursor = 0;
			break;
		case 117:	// u
		case 85:	// U
		case KEY_UP:
			log_user_cursor = max(0, log_user_cursor - 1);
			wscrl(__np_stat_switchable_window, 1);
			break;
		case 110:	// n
		case 78:	// N
		case KEY_DOWN:
			log_user_cursor = min(log_user_cursor + 1, sll_size(log_buffer));
			wscrl(__np_stat_switchable_window, -1);
			break;
		case 113: // q
			np_destroy();
			exit(EXIT_SUCCESS);
			break;
		}
	}
}

void __np_example_helper_run_loop() {
	while (TRUE)
	{
		np_time_sleep(output_intervall_sec);
	}
}

void __np_example_helper_run_info_loop() {
	while (TRUE)
	{
		__np_example_helper_loop();
		np_time_sleep(output_intervall_sec);
	}
}