#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "np_log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_keycache.h"
#include "np_node.h"
#include "np_types.h"
#include "np_util.h"
#include "np_val.h"


/**
.. highlight:: c
*/

#define USAGE "neuropil [ -j bootstrap:port ] [ -p protocol] [-b port] [-t worker_thread_count]"
#define OPTSTR "j:p:b:t:"

extern char *optarg;
/**
.. code-block:: c
*/

np_state_t* state = NULL;
np_tree_t* authorized_tokens = NULL;
np_tree_t* authenticated_tokens = NULL;

pthread_mutex_t _aaa_mutex = PTHREAD_MUTEX_INITIALIZER;

int seq = -1;
int joinComplete = 0;

np_bool check_authorize_token(NP_UNUSED np_aaatoken_t* token)
{
	pthread_mutex_lock(&_aaa_mutex);
	if (NULL == authorized_tokens) authorized_tokens = make_jtree();

	// if a token reaches this point, is has already been check for technical validity
	np_bool ret_val = FALSE;

	char pub_key[2*crypto_sign_PUBLICKEYBYTES+1];
	sodium_bin2hex(pub_key, 2*crypto_sign_PUBLICKEYBYTES+1, token->public_key, crypto_sign_PUBLICKEYBYTES);

	if (NULL != tree_find_str(authorized_tokens, token->issuer))
	{
		pthread_mutex_unlock(&_aaa_mutex);
		return (TRUE);
	}

	fprintf(stdout, "----------------------------------------------\n");
	fprintf(stdout, "authorization request for : \n");
	fprintf(stdout, "\tuuid              : %s\n", token->uuid);
	fprintf(stdout, "\trealm             : %s\n", token->realm);
	fprintf(stdout, "\tissuer            : %s\n", token->issuer);
	fprintf(stdout, "\tsubject           : %s\n", token->subject);
	fprintf(stdout, "\taudience          : %s\n", token->audience);

	struct timeval token_time;
	struct tm token_ts;
	char time_entry[27];
	token_time.tv_sec = (long) token->issued_at;
	token_time.tv_usec = (long) ((token->issued_at - (double) token_time.tv_sec) * 1000000.0);
	localtime_r(&token_time.tv_sec, &token_ts);
	strftime(time_entry, 19, "%Y-%m-%d %H:%M:%S", &token_ts);
	snprintf(time_entry+19, 6, ".%6d", token_time.tv_usec);
	fprintf(stdout, "\tissued date       : %s\n", time_entry);

	token_time.tv_sec = (long) token->expiration;
	token_time.tv_usec = (long) ((token->expiration - (double) token_time.tv_sec) * 1000000.0);
	localtime_r(&token_time.tv_sec, &token_ts);
	strftime(time_entry, 19, "%Y-%m-%d %H:%M:%S", &token_ts);
	snprintf(time_entry+19, 6, ".%6d", token_time.tv_usec);
	fprintf(stdout, "\texpiration        : %s\n", time_entry);

	fprintf(stdout, "\tpublic_key        : %s\n", pub_key);
//	if (tree_find_str(token->extensions, "passcode"))
//	{
//		fprintf(stdout, "----------------------------------------------\n");
//		fprintf(stdout, "\tpasscode          : %s\n",
//				tree_find_str(token->extensions, "passcode")->val.value.s);
//	}
	fprintf(stdout, "----------------------------------------------\n");
	fflush(stdout);
	// fprintf(stdout, "authorize ? [ (a)lways / (o)nce / (n)ever ]: ");

/*
 * char result = fgetc(stdin);
	switch (result)
	{
	case 'a':
		ret_val = TRUE;
		*/
	np_ref_obj(np_aaatoken_t, token);
	tree_insert_str(authorized_tokens, token->issuer, new_val_v(token));
/*
	  	break;
	case 'o':
		ret_val = TRUE;
		break;
	case 'n':
	default:
		break;
	}
*/
//	fprintf(stdout, "----------------------------------------------\n");
//	fflush(stdout);

	pthread_mutex_unlock(&_aaa_mutex);
	return (TRUE); // ret_val;
}

np_bool check_authenticate_token(np_aaatoken_t* token)
{
	pthread_mutex_lock(&_aaa_mutex);

	if (NULL == authenticated_tokens) authenticated_tokens = make_jtree();
	// if a token reaches this point, is has already been check for technical validity
	np_bool ret_val = FALSE;

	char pub_key[2*crypto_sign_PUBLICKEYBYTES+1];
	sodium_bin2hex(pub_key, 2*crypto_sign_PUBLICKEYBYTES+1, token->public_key, crypto_sign_PUBLICKEYBYTES);

	if (NULL != tree_find_str(authenticated_tokens, token->issuer))
	{
		pthread_mutex_unlock(&_aaa_mutex);
		return (TRUE);
	}

	fprintf(stdout, "----------------------------------------------\n");
	fprintf(stdout, "authentication request for:\n");
	fprintf(stdout, "\trealm             : %s\n", token->realm);
	fprintf(stdout, "\tissuer            : %s\n", token->issuer);
	fprintf(stdout, "\tsubject           : %s\n", token->subject);
	fprintf(stdout, "\taudience          : %s\n", token->audience);
	struct timeval token_time;
	struct tm token_ts;
	char time_entry[27];
	token_time.tv_sec = (long) token->issued_at;
	token_time.tv_usec = (long) ((token->issued_at - (double) token_time.tv_sec) * 1000000.0);
	localtime_r(&token_time.tv_sec, &token_ts);
	strftime(time_entry,    19, "%Y-%m-%d %H:%M:%S", &token_ts);
	snprintf(time_entry+19,  6, ".%6d", token_time.tv_usec);
	fprintf(stdout, "\tissued date       : %s\n", time_entry);

	token_time.tv_sec = (long) token->expiration;
	token_time.tv_usec = (long) ((token->expiration - (double) token_time.tv_sec) * 1000000.0);
	localtime_r(&token_time.tv_sec, &token_ts);
	strftime(time_entry, 19, "%Y-%m-%d %H:%M:%S", &token_ts);
	snprintf(time_entry+19, 6, ".%6d", token_time.tv_usec);
	fprintf(stdout, "\texpiration        : %s\n", time_entry);

	fprintf(stdout, "\tpublic_key        : %s\n", pub_key);
//	fprintf(stdout, "----------------------------------------------\n");
//	if (tree_find_str(token->extensions, "passcode"))
//	{
//		fprintf(stdout, "\tpasscode          : %s\n",
//				tree_find_str(token->extensions, "passcode")->val.value.s);
//	}
	fprintf(stdout, "----------------------------------------------\n");
	fflush(stdout);
/*	fprintf(stdout, "authenticate ? (a)lways / (o)nce / (n)ever: ");

	char result = fgetc(stdin);
	switch (result)
	{
	case 'y':
		ret_val = TRUE;
		*/
	np_ref_obj(np_aaatoken_t, token);
	tree_insert_str(authenticated_tokens, token->issuer, new_val_v(token));
/*		break;
	case 'N':
	default:
		break;
	}
	fprintf(stdout, "----------------------------------------------\n");
	fflush(stdout);
	*/
	pthread_mutex_unlock(&_aaa_mutex);
	return (TRUE); // ret_val;
}

np_bool check_account_token(NP_UNUSED np_aaatoken_t* token)
{
	return (TRUE);
}

np_aaatoken_t* create_realm_identity()
{
	np_aaatoken_t* realm_identity = NULL;
	np_new_obj(np_aaatoken_t, realm_identity);

	strncpy(realm_identity->realm,   "pi-lar test realm",  255);
	strncpy(realm_identity->subject, "pi-lar realmmaster", 255);
	strncpy(realm_identity->issuer,  "pi-lar realmmaster", 255);

	realm_identity->not_before = ev_time();
	realm_identity->expiration = realm_identity->not_before + 7200.0;
	realm_identity->state = AAA_VALID | AAA_AUTHENTICATED | AAA_AUTHORIZED;

	realm_identity->uuid = np_create_uuid("pi-lar realmmaster", 0);

	// add some unique identification parameters
	// a far better approach is to follow the "zero-knowledge" paradigm (use the source, luke)
	// also check libsodium password hahsing functionality
	tree_insert_str(realm_identity->extensions, "passcode", new_val_hash("test"));

	return (realm_identity);
}

int main(int argc, char **argv)
{
	int opt;
	int no_threads = 4;
	char* j_key = NULL;
	char* proto = NULL;
	char* port = NULL;

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
	{
		switch ((char) opt)
		{
		case 'j':
			j_key = optarg;
			break;
		case 't':
			no_threads = atoi(optarg);
			if (no_threads <= 0) no_threads = 4;
			break;
		case 'p':
			proto = optarg;
			break;
		case 'b':
			port = optarg;
			break;
		default:
			fprintf(stderr, "invalid option %c\n", (char) opt);
			fprintf(stderr, "usage: %s\n", USAGE);
			exit(1);
		}
	}

	/**
	in your main program, initialize the logging of neuopil

	.. code-block:: c

	   char log_file[256];
	   sprintf(log_file, "%s_%d.log", "./neuropil_controller", getpid());
	   int level = LOG_ERROR | LOG_WARN | LOG_INFO;
	   log_init(log_file, level);
	*/
	char log_file[256];
	sprintf(log_file, "%s_%s.log", "./neuropil_realmmaster", "0");
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_ROUTING | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_NETWORK | LOG_AAATOKEN;
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO;
	np_log_init(log_file, level);

	/**
	initialize the global variable with the np_init function

	.. code-block:: c

	   state = np_init(proto, port);
	*/
	state = np_init(proto, port, TRUE);

	np_aaatoken_t* realm_identity = create_realm_identity();
	np_set_identity(realm_identity);
	np_set_realm_name("pi-lar test realm");
	np_enable_realm_master();

	np_setauthenticate_cb(check_authenticate_token);
	np_setauthorizing_cb(check_authorize_token);
	np_setaccounting_cb(check_account_token);

	// state->my_node_key->node->joined_network = 1;

	/**
	check stdout and the log file because it will contain the hashvalue / connect string for your node, e.g.

	.. code-block:: c

       2f96848a8c490e0f0f71c74caa900423bcf2d32882a9a0b3510c50085f7ec0e5:udp6:localhost:3333
	*/

	/**
	start up the job queue with 8 concurrent threads competing for job execution.

	.. code-block:: c

	   np_start_job_queue(8);
	*/


	// dsleep(50);
	log_msg(LOG_DEBUG, "starting job queue");
	np_start_job_queue(no_threads);

	if (NULL != j_key)
	{
		np_send_join(j_key);
	}

	/**
	and finally loop (almost) forever

	.. code-block:: c

	   while (1) {
	       dsleep(1.0);
	   }
	*/

	/**
	your're done ...

	if you plan to connect your nodes to this controller as a bootstrap node.
	The created process can be contacted by other nodes and will forward messages as required.
	By default the authentication / authorization / accounting handler accept nodes/message request
	from everybody.

    .. note::
	   Make sure that you implement and register the appropiate aaa callback functions
	   to control with which nodes you exchange messages. By default everybody is allowed to interact
	   with your node
	*/

	while (1)
	{
		ev_sleep(1.0);
	}
}
