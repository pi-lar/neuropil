//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include <inttypes.h>

#include "neuropil.h"
#include "np_types.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_scache.h"
#include "np_list.h"
#include "np_route.h"
#include "np_util.h"

#include "np_statistics.h"

struct np_statistics_element_s {
	np_bool watch_receive;
	np_bool watch_send;

	uint32_t total_received;
	uint32_t total_send;
	uint32_t last_total_received;
	uint32_t last_total_send;

	uint32_t last_min_received;
	uint32_t last_min_send;
	uint32_t last_total_min_received;
	uint32_t last_total_min_send;
	double last_mindiff_received;
	double last_mindiff_send;
	double last_min_check;

	uint32_t last_sec_received;
	uint32_t last_sec_send;
	uint32_t last_total_sec_received;
	uint32_t last_total_sec_send;
	double last_secdiff_received;
	double last_secdiff_send;
	double last_sec_check;

	double first_check;
};
typedef struct np_statistics_element_s np_statistics_element_t;

static np_simple_cache_table_t* _cache = NULL;
static np_sll_t(char_ptr, watched_subjects);
static np_bool _np_statistcs_initiated = FALSE;

np_bool _np_statistics_receive_msg_on_watched(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body)
{
	assert(_cache != NULL);
	assert(msg != NULL);
	assert(msg->msg_property != NULL);
	assert(msg->msg_property->msg_subject != NULL);
	np_cache_item_t* item = np_simple_cache_get(_cache, msg->msg_property->msg_subject);
	if (item != NULL) {
		((np_statistics_element_t*)item->value)->total_received += 1;
	}

	return TRUE;
}

np_bool _np_statistics_send_msg_on_watched(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body)
{
	assert(_cache != NULL);
	assert(msg != NULL);
	assert(msg->msg_property != NULL);
	assert(msg->msg_property->msg_subject != NULL);
	np_cache_item_t* item = np_simple_cache_get(_cache, msg->msg_property->msg_subject);
	if (item != NULL) {
		((np_statistics_element_t*)item->value)->total_send += 1;
	}

	return TRUE;
}

np_bool np_statistics_init() {
	_np_statistcs_initiated = TRUE;
	_cache = np_cache_init(SIMPLE_CACHE_NR_BUCKETS);
	sll_init(char_ptr, watched_subjects);
	return _np_statistcs_initiated;
}

np_bool np_statistics_destroy() {
	_np_statistcs_initiated = TRUE;

	sll_iterator(char_ptr) iter = sll_first(watched_subjects);
	while (iter != NULL)
	{
		free(np_simple_cache_get(_cache, iter->val)->value);
		free(iter->val);
		sll_next(iter);
	}

	sll_free(char_ptr, watched_subjects);
	free(_cache);

	_np_statistcs_initiated = FALSE;
	return _np_statistcs_initiated == FALSE;
}

void np_statistics_add_watch(char* subject) {
	if (FALSE == _np_statistcs_initiated) {
		np_statistics_init();
	}

	np_bool addtolist = TRUE;
	sll_iterator(char_ptr) iter_subjects = sll_first(watched_subjects);
	while (iter_subjects != NULL)
	{
		if (strncmp(iter_subjects->val, subject, strlen(subject) == 0)) {
			addtolist = FALSE;
			break;
		}
		sll_next(iter_subjects);
	}

	char* key = subject;
	if (addtolist == TRUE) {
		key = strdup(subject);
		sll_append(char_ptr, watched_subjects, key);
		np_simple_cache_insert(_cache, key, calloc(1, sizeof(np_statistics_element_t)));
	}

	np_statistics_element_t* container = np_simple_cache_get(_cache, key)->value;

	if (addtolist == TRUE) {
		CHECK_MALLOC(container);
		container->last_sec_check =
			container->last_min_check =
			container->first_check =
			np_time_now();
	}

	if (FALSE == container->watch_receive && np_msgproperty_get(INBOUND, key) != NULL) {
		container->watch_receive = TRUE;
		np_add_receive_listener(_np_statistics_receive_msg_on_watched, key);
	}

	if (FALSE == container->watch_send && np_msgproperty_get(OUTBOUND, key) != NULL) {
		container->watch_send = TRUE;
		np_add_send_listener(_np_statistics_send_msg_on_watched, key);
	}
}

void np_statistics_add_watch_internals() {
	
	//np_statistics_add_watch(_DEFAULT);
		
	np_statistics_add_watch(_NP_MSG_ACK);
	np_statistics_add_watch(_NP_MSG_HANDSHAKE);
	
	np_statistics_add_watch(_NP_MSG_PING_REQUEST);
	np_statistics_add_watch(_NP_MSG_LEAVE_REQUEST);
	np_statistics_add_watch(_NP_MSG_JOIN);
	np_statistics_add_watch(_NP_MSG_JOIN_REQUEST);
	np_statistics_add_watch(_NP_MSG_JOIN_ACK);
	np_statistics_add_watch(_NP_MSG_JOIN_NACK);
	
	np_statistics_add_watch(_NP_MSG_PIGGY_REQUEST);
	np_statistics_add_watch(_NP_MSG_UPDATE_REQUEST);	
	
	np_statistics_add_watch(_NP_MSG_DISCOVER_RECEIVER);
	np_statistics_add_watch(_NP_MSG_DISCOVER_SENDER);
	np_statistics_add_watch(_NP_MSG_AVAILABLE_RECEIVER);
	np_statistics_add_watch(_NP_MSG_AVAILABLE_SENDER);
	
	if(_np_state()->enable_realm_master || _np_state()->enable_realm_slave){
		np_statistics_add_watch(_NP_MSG_AUTHENTICATION_REQUEST);
		np_statistics_add_watch(_NP_MSG_AUTHENTICATION_REPLY);
		np_statistics_add_watch(_NP_MSG_AUTHORIZATION_REQUEST);
		np_statistics_add_watch(_NP_MSG_AUTHORIZATION_REPLY);
	}
	np_statistics_add_watch(_NP_MSG_ACCOUNTING_REQUEST);
	
}
char * np_statistics_print(char* asOneLine) {
	if (FALSE == _np_statistcs_initiated) {
		return NULL;
	}

	char * ret = NULL;

	char* new_line = "\n";
	if (asOneLine == TRUE) {
		new_line = "    ";
	}
	ret = _np_concatAndFree(ret, "--- Statistics START ---%s", new_line);

	sll_iterator(char_ptr) iter_subjects = sll_first(watched_subjects);

	double sec_since_start;

	double current_min_send;
	double current_min_received;
	double min_since_last_print;

	double current_sec_send;
	double current_sec_received;
	double sec_since_last_print;

	double now = np_time_now();


	uint32_t
		all_total_send		= 0,
		all_total_received	= 0;


	while (iter_subjects != NULL)
	{
		np_statistics_element_t* container = np_simple_cache_get(_cache, iter_subjects->val)->value;

		sec_since_start = (now - container->first_check);

		// per Min calc
		min_since_last_print = (now - container->last_min_check) / 60;

		if (min_since_last_print > 1) {
			current_min_received = (container->total_received - container->last_total_min_received) / min_since_last_print;
			current_min_send = (container->total_send - container->last_total_min_send) / min_since_last_print;

			container->last_mindiff_received = current_min_received - container->last_min_received;
			container->last_mindiff_send = current_min_send - container->last_min_send;

			container->last_min_received = current_min_received;
			container->last_min_send = current_min_send;
			container->last_min_check = now;
			container->last_total_min_received = container->total_received;
			container->last_total_min_send = container->total_send;
		}
		else if ((sec_since_start / 60) < 1) {
			current_min_received = container->total_received;
			current_min_send = container->total_send;

			container->last_mindiff_received = current_min_received;
			container->last_mindiff_send = current_min_send;
		}
		else {
			current_min_received = container->last_min_received;
			current_min_send = container->last_min_send;
		}
		// per Min calc end

		// per Sec calc
		sec_since_last_print = (now - container->last_sec_check);

		if (sec_since_last_print > 1) {
			current_sec_received = (container->total_received - container->last_total_sec_received) / sec_since_last_print;
			current_sec_send = (container->total_send - container->last_total_sec_send) / sec_since_last_print;

			container->last_secdiff_received = current_sec_received - container->last_sec_received;
			container->last_secdiff_send = current_sec_send - container->last_sec_send;

			container->last_sec_received = current_sec_received;
			container->last_sec_send = current_sec_send;
			container->last_sec_check = now;
			container->last_total_sec_received = container->total_received;
			container->last_total_sec_send = container->total_send;
		}
		else {
			current_sec_received = container->last_sec_received;
			current_sec_send = container->last_sec_send;
		}
		// per Sec calc end

		if (container->watch_receive) {
			all_total_received += container->total_received;
			ret = _np_concatAndFree(ret,
				"received total: %5"PRIu32" (%5.1f[%+5.1f] per sec) (%7.1f[%+7.1f] per min) %s%s",
				container->total_received,
				current_sec_received, container->last_secdiff_received,
				current_min_received, container->last_mindiff_received,
				iter_subjects->val, new_line);
		}

		if (container->watch_send) {
			all_total_send += container->total_send;
			ret = _np_concatAndFree(ret,
				"send     total: %5"PRIu32" (%5.1f[%+5.1f] per sec) (%7.1f[%+7.1f] per min) %s%s",
				container->total_send,
				current_sec_send, container->last_secdiff_send,
				current_min_send, container->last_mindiff_send,
				iter_subjects->val, new_line
			);
		}

		container->last_total_received = container->total_received;
		container->last_total_send = container->total_send;

		sll_next(iter_subjects);
	}

	ret = _np_concatAndFree(ret, "%s", new_line);


	uint32_t routes = _np_route_my_key_count_routes();	


	int tenth = 1;
	char* tmp_format[255] = { 0 };
	int minimize[] = { routes, all_total_received, all_total_send, };
	char s[32];

	for (int i = 0; i < sizeof(minimize); i++) {
		sprintf(s, "%d", minimize[i]);
		tenth = max(tenth, strlen(s));
	}
	
	sprintf(tmp_format, "%-17s %%%"PRId32""PRIu32"%%s", "received total:", tenth);
	ret = _np_concatAndFree(ret, tmp_format, all_total_received, new_line);
	sprintf(tmp_format, "%-17s %%%"PRId32""PRIu32"%%s", "send     total:", tenth);
	ret = _np_concatAndFree(ret, tmp_format, all_total_send, new_line);	
	
	ret = _np_concatAndFree(ret, "%s", new_line);

	sprintf(tmp_format, "%-17s %%%"PRId32""PRIu32"%%s", "Reachable nodes:", tenth);
	ret = _np_concatAndFree(ret, tmp_format, routes, new_line);
	sprintf(tmp_format, "%-17s %%%"PRId32""PRIu32"%%s", "Neighbours nodes:", tenth);
	ret = _np_concatAndFree(ret, tmp_format, _np_route_my_key_count_neighbours(), new_line);

	ret = _np_concatAndFree(ret, "--- Statistics END  ---%s", new_line);

	return ret;
}