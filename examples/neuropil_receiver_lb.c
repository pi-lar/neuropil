//
// neuropil is copyright 2016-2018 by pi-lar GmbH
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

/**
.. highlight:: c
*/

#include "neuropil.h"

#include "example_helper.c"


#define NP_CHECK_ERROR(status) \
    if (np_ok != status) \
    { \
    		fprintf(stdout, "ERROR: %s", np_error_str[status]); \
    		exit(EXIT_FAILURE); \
    }; \


bool authorize (np_context *ac, struct np_token *id)
{
//	// TODO: Make sure that id->public_key is the intended recipient!
//	char pubkey[65];
//	pubkey[64] = '\0';
//    char* ctx = (char*) np_get_userdata(ac);
//	sodium_bin2hex(pubkey, 65, id->public_key, 32U);
//	fprintf(stdout, "AUTHZ(%s): subj: %s ## pk: %s\n", ctx, id->subject, pubkey);
//	fflush(stdout);
	return true;
}

/**
first, let's define a callback function that will be called each time
a message is received by the node that you are currently starting

.. code-block:: c

   \code
*/
bool receive_this_is_a_test(np_context* context, struct np_message* msg)
{
/**
\endcode
*/

/**
for this message exchange the message is send as a text element (if you used np_send_text)
otherwise inspect the properties and payload np_tree_t structures ...

.. code-block:: c

\code
*/
    char text[msg->data_length+1];
    memcpy(text, msg->data, msg->data_length);
/**
\endcode
*/
    char* ctx = (char*) np_get_userdata(context);
    fprintf(stdout, "REC  (%s): %s / %s\n", ctx, msg->uuid, text);
	fflush(stdout);

/**
return true to indicate successfull handling of the message. if you return false
the message may get delivered a second time

.. code-block:: c

\code
*/
    return true;
}
/**
   \endcode
*/


int main(int argc, char **argv)
{
	int no_threads = 8;
	char *j_key = NULL;
	char* proto = "udp4";
	char* port = NULL;
	char* publish_domain = NULL;
	int level = -2;
	char* logpath = ".";

	example_user_context* user_context;
	if ((user_context = parse_program_args(
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
		NULL)) == NULL) {
		exit(EXIT_FAILURE);
	}
	
	/**
	in your main program, initialize the logging of neuropil, but this time use the port for the filename

	.. code-block:: c

	   \code
	*/
	struct np_settings *settings_1 = np_default_settings(NULL);
	struct np_settings *settings_2 = np_default_settings(NULL);
	settings_1->n_threads = 4;
	settings_2->n_threads = 4;
	/**
	   \endcode
	*/

	snprintf(settings_1->log_file, 255, "%s%s_%s.log", logpath, "/neuropil_receiver_lb_1", port);
	snprintf(settings_2->log_file, 255, "%s%s_%s.log", logpath, "/neuropil_receiver_lb_2", port);
	fprintf(stdout, "logpath: %s\n", settings_1->log_file);
	fprintf(stdout, "logpath: %s\n", settings_2->log_file);
	// settings_1->log_level = level;
	// settings_2->log_level = level;

	np_context* context_1 = np_new_context(settings_1);
	np_set_userdata(context_1, "context 1");
	np_context* context_2 = np_new_context(settings_2);
	np_set_userdata(context_2, "context 2");

	// create a new identity and use it for both nodes
	struct np_token my_id = np_new_identity(context_1, np_time_now() + 3600.0, NULL);
	strncpy(my_id.subject, "urn:np:id:this.is.a.test.identity", 255);

	np_id fingerprint_id;
	char fingerprint_str[65];
	np_token_fingerprint(context_1, my_id, false, (np_id_ptr)&fingerprint_id);

	fingerprint_str[64] = '\0';
	sodium_bin2hex(fingerprint_str, 65, fingerprint_id, 32U);
	char pubkey[65];
	pubkey[64] = '\0';
	sodium_bin2hex(pubkey, 65, my_id.public_key, 32U);
	fprintf(stdout, "U: uuid: %s ## subj: %s ## pk: %s ## fp: %s\n", my_id.uuid, my_id.subject, pubkey, fingerprint_str);
	fflush(stdout);

	np_use_identity(context_1, my_id);
	np_use_identity(context_2, my_id);

	assert(np_ok == np_set_authorize_cb(context_1, authorize));
	assert(np_ok == np_set_authorize_cb(context_2, authorize));

	if (np_ok != np_listen(context_1, proto, publish_domain, atoi(port) )) {
		fprintf(stdout, "ERROR: Node could not listen");
		exit(EXIT_FAILURE);
	}

	if (np_ok != np_listen(context_2, proto, publish_domain, atoi(port)+1 )) {
		fprintf(stdout, "ERROR: Node could not listen");
		exit(EXIT_FAILURE);
	}

	/**
	   \endcode
	*/
	   

	/**nnp
	start up the job queue with 8 concurrent threads competing for job execution.
	you should start at least 2 threads (network io is non-blocking).

	.. code-block:: c

	   \code
	*/
	if (np_ok != np_run(context_1, 0)) {
		fprintf(stdout, "ERROR: Node could not start");
		exit(EXIT_FAILURE);
	}
	if (np_ok != np_run(context_2, 0)) {
		fprintf(stdout, "ERROR: Node could not start");
		exit(EXIT_FAILURE);
	}
	/**
	   \endcode
	*/
	enum np_error status = np_ok;
	if (NULL != j_key)
	{
		status |= np_join(context_1, j_key);
		status |= np_join(context_2, j_key);
	}
	NP_CHECK_ERROR(status);
	fflush(stdout);

	/**
	use the connect string that is printed to stdout and pass it to the np_controller to send a join message.
	wait until the node has received a join message before proceeding

	.. code-block:: c

	   \code
	*/
	while ( np_has_joined(context_1) && np_has_joined(context_2) && status == np_ok) {
		status |= np_run(context_1, 0.04);
		status |= np_run(context_2, 0.04);
	}
	NP_CHECK_ERROR(status);
	/**
	   \endcode
	*/


	/**
	*.. note::
	*   Make sure that you have implemented and registered the appropiate aaa callback functions
	*   to control with which nodes you exchange messages. By default everybody is allowed to interact
	*   with your node
	 */

	/**
	register the listener function to receive data from the sender

	.. code-block:: c

	   \code
	*/
	status |= np_add_receive_cb(context_1, "urn:np:subj:this.is.a.test",  receive_this_is_a_test);
	struct np_mx_properties mx_1 = np_get_mx_properties(context_1, "urn:np:subj:this.is.a.test");
	mx_1.max_parallel = 5;
	status |= np_set_mx_properties(context_1, "urn:np:subj:this.is.a.test", mx_1);
	NP_CHECK_ERROR(status);

	status |= np_add_receive_cb(context_2, "urn:np:subj:this.is.a.test", receive_this_is_a_test);
	struct np_mx_properties mx_2 = np_get_mx_properties(context_2, "urn:np:subj:this.is.a.test");
	mx_2.max_parallel = 5;
	status |= np_set_mx_properties(context_2, "urn:np:subj:this.is.a.test", mx_2);
	NP_CHECK_ERROR(status);
	/**
	   \endcode
	*/


	/**
	the loopback function will be triggered each time a message is received
	make sure that you've understood how to alter the message exchange to change
	receiving of message from the default values
	*/

	/**
	loop (almost) forever, you're done :-)

	.. code-block:: c

	   \code
	*/
	while (1)
	{
		status |= np_run(context_1, 0.04);
		NP_CHECK_ERROR(status);
		status |= np_run(context_2, 0.04);
		NP_CHECK_ERROR(status);
	}
	/**
	   \endcode
	*/
}
