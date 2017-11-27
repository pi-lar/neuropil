//
// neuropil is copyright 2016 by pi-lar GmbH
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
#include <assert.h>

#include "np_log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_keycache.h"
#include "np_node.h"
#include "np_types.h"
#include "np_util.h"
#include "np_treeval.h"

#include "example_helper.c"
 

np_state_t* state = NULL;
np_tree_t* authorized_tokens = NULL;
np_tree_t* authenticated_tokens = NULL;

pthread_mutex_t _aaa_mutex = PTHREAD_MUTEX_INITIALIZER;

int seq = -1;
int joinComplete = 0;

np_bool check_authorize_token(NP_UNUSED np_aaatoken_t* token)
{
	pthread_mutex_lock(&_aaa_mutex);
	if (NULL == authorized_tokens) authorized_tokens = np_tree_create();

	// if a token reaches this point, is has already been check for technical validity
	np_bool ret_val = FALSE;

	char pub_key[2*crypto_sign_PUBLICKEYBYTES+1];
	sodium_bin2hex(pub_key, 2*crypto_sign_PUBLICKEYBYTES+1, token->public_key, crypto_sign_PUBLICKEYBYTES);

	if (NULL != np_tree_find_str(authorized_tokens, token->issuer))
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

	token_time.tv_sec = (long) token->expires_at;
	token_time.tv_usec = (long) ((token->expires_at - (double) token_time.tv_sec) * 1000000.0);
	localtime_r(&token_time.tv_sec, &token_ts);
	strftime(time_entry, 19, "%Y-%m-%d %H:%M:%S", &token_ts);
	snprintf(time_entry+19, 6, ".%6d", token_time.tv_usec);
	fprintf(stdout, "\texpiration        : %s\n", time_entry);

	fprintf(stdout, "\tpublic_key        : %s\n", pub_key);
//	if (np_tree_find_str(token->extensions, "passcode"))
//	{
//		fprintf(stdout, "----------------------------------------------\n");
//		fprintf(stdout, "\tpasscode          : %s\n",
//				np_tree_find_str(token->extensions, "passcode")->val.value.s);
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
	np_tree_insert_str(authorized_tokens, token->issuer, np_treeval_new_v(token));
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

	if (NULL == authenticated_tokens) authenticated_tokens = np_tree_create();
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

	token_time.tv_sec = (long) token->expires_at;
	token_time.tv_usec = (long) ((token->expires_at - (double) token_time.tv_sec) * 1000000.0);
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
	tree_insert_str(authenticated_tokens, token->issuer, np_treeval_new_v(token));
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
	strncpy(realm_identity->issuer,  "pi-lar realmmaster", 64);

	realm_identity->not_before = np_time_now();
	realm_identity->expires_at = realm_identity->not_before + 7200.0;
	realm_identity->state = AAA_VALID | AAA_AUTHENTICATED | AAA_AUTHORIZED;

	free(realm_identity->uuid);
	realm_identity->uuid = np_uuid_create("pi-lar realmmaster", 0);

	// add some unique identification parameters
	// a far better approach is to follow the "zero-knowledge" paradigm (use the source, luke)
	// also check libsodium password hahsing functionality
	tree_insert_str(realm_identity->extensions, "passcode", np_treeval_new_hash("test"));

	return (realm_identity);
}

int main(int argc, char **argv)
{

	int no_threads = 8;
	char *j_key = NULL;
	char* proto = "udp4";
	char* port = NULL;
	char* publish_domain = NULL;
	int level = -2;
	char* logpath = ".";
 
	int opt;
	if (parse_program_args(
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
		NULL,
		NULL,		
	) == FALSE) {
		exit(EXIT_FAILURE);
	}
 
	/**
	for the general initialisation of a node please look into the neuropil_node example
	*/
	
	/**
	in your main program, initialize the logging of neuopil

	.. code-block:: c

	   char log_file[256];
	   sprintf(log_file, "%s_%d.log", "./neuropil_controller", getpid());
	   int level = LOG_ERROR | LOG_WARN | LOG_INFO;
	   log_init(log_file, level);
	*/
	char log_file[256];
	sprintf(log_file, "%s%s_%s.log", logpath, "/neuropil_realmmaster", port);
	np_log_init(log_file, level);

	/**
	initialize the global variable with the np_init function

	.. code-block:: c

	   state = np_init(proto, port);
	*/
	state = np_init(proto, port, publish_domain);

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
	log_debug_msg(LOG_DEBUG, "starting job queue");
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
