//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <ctype.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <float.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#include "sodium.h"
#include "event/ev.h"
#include "json/parson.h"
#include "msgpack/cmp.h"
#include "tree/tree.h"

#include "np_util.h"


#include "np_log.h"
#include "neuropil.h"

#include "np_dhkey.h"
#include "np_keycache.h"
#include "np_treeval.h"
#include "np_message.h"
#include "np_tree.h"
#include "np_node.h"
#include "np_route.h"
#include "np_types.h"
#include "np_list.h"
#include "np_threads.h"

NP_SLL_GENERATE_IMPLEMENTATION(char_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(void_ptr);

char* np_uuid_create(const char* str, const uint16_t num, char** buffer)
{	
	char* uuid_out;
	if (buffer == NULL) {
		uuid_out = calloc(1, UUID_SIZE);
		CHECK_MALLOC(uuid_out);
	}
	else {
		uuid_out = *buffer;
	}
	char input[256] = { '\0' };
	unsigned char out[18] = { '\0' };

	double now = np_time_now();
	snprintf (input, 255, "%s:%u:%16.16f", str, num, now);
	// log_debug_msg(LOG_DEBUG, "created input uuid: %s", input);
	crypto_generichash(out, 18, (unsigned char*) input, 256, NULL, 0);
	sodium_bin2hex(uuid_out, UUID_SIZE, out, 18);
	// log_debug_msg(LOG_DEBUG, "created raw uuid: %s", uuid_out);
	uuid_out[8] = uuid_out[13] = uuid_out[18] = uuid_out[23] = '-';
	uuid_out[14] = '5';
	uuid_out[19] = '9';
	// log_debug_msg(LOG_DEBUG, "created new uuid: %s", uuid_out);

	return uuid_out;
}

// TODO: replace with function pointer, same for __np_tree_read_type
// typedef void (*write_type_function)(const np_treeval_t* val, cmp_ctx_t* ctx);
// write_type_function write_type_arr[np_treeval_type_npval_count] = {NULL};
// write_type_arr[np_treeval_type_npval_count] = &write_short_type;
// write_type_arr[np_treeval_type_npval_count] = NULL;


void _np_sll_remove_doublettes(np_sll_t(np_key_ptr, list_of_keys))
{
	sll_iterator(np_key_ptr) iter1 = sll_first(list_of_keys);
	sll_iterator(np_key_ptr) tmp = NULL;

	do
	{
		sll_iterator(np_key_ptr) iter2 = sll_get_next(iter1);

		if (NULL == iter2) break;

		do
		{
			if (0 == _np_dhkey_cmp(&iter1->val->dhkey,
								 &iter2->val->dhkey))
			{
				tmp = iter2;
			}

			sll_next(iter2);

			if (NULL != tmp)
			{
				sll_delete(np_key_ptr, list_of_keys, tmp);
				tmp = NULL;
			}
		} while(NULL != iter2);

		sll_next(iter1);

	} while (NULL != iter1);
}


JSON_Value* np_treeval2json(np_state_t* context, np_treeval_t val) {
	log_trace_msg(LOG_TRACE, "start: JSON_Value* np_treeval2json(context, np_treeval_t val) {");
	JSON_Value* ret = NULL;
	np_bool free_string = FALSE;
	char* tmp_str = NULL;
	//log_debug_msg(LOG_DEBUG, "np_treeval2json type: %"PRIu8,val.type);
	switch (val.type) {
	case np_treeval_type_short:
		ret = json_value_init_number(val.value.sh);
		break;
	case np_treeval_type_int:
		ret = json_value_init_number(val.value.i);
		break;
	case np_treeval_type_long:
		ret = json_value_init_number(val.value.l);
		break;
#ifdef x64
	case np_treeval_type_long_long:
		ret = json_value_init_number(val.value.ll);
		break;
#endif
	case np_treeval_type_float:
		ret = json_value_init_number(val.value.f);
		break;
	case np_treeval_type_double:
		ret = json_value_init_number(val.value.d);
		break;
	case np_treeval_type_unsigned_short:
		ret = json_value_init_number(val.value.ush);
		break;
	case np_treeval_type_unsigned_int:
		ret = json_value_init_number(val.value.ui);
		break;
	case np_treeval_type_unsigned_long:
		ret = json_value_init_number(val.value.ul);
		break;
#ifdef x64
	case np_treeval_type_unsigned_long_long:
		ret = json_value_init_number(val.value.ull);
		break;
#endif
	case np_treeval_type_uint_array_2:
		ret = json_value_init_array();
		json_array_append_number(json_array(ret), val.value.a2_ui[0]);
		json_array_append_number(json_array(ret), val.value.a2_ui[1]);
		break;
	case np_treeval_type_jrb_tree:
		ret = np_tree2json(context, val.value.tree);
		break;
		/*
	case np_treeval_type_dhkey:
		ret = json_value_init_array();
		json_array_append_number(json_array(ret), val.value.dhkey.t[0]);
		json_array_append_number(json_array(ret), val.value.dhkey.t[1]);
		json_array_append_number(json_array(ret), val.value.dhkey.t[2]);
		json_array_append_number(json_array(ret), val.value.dhkey.t[3]);
		json_array_append_number(json_array(ret), val.value.dhkey.t[4]);
		json_array_append_number(json_array(ret), val.value.dhkey.t[5]);
		json_array_append_number(json_array(ret), val.value.dhkey.t[6]);
		json_array_append_number(json_array(ret), val.value.dhkey.t[7]);
		break;
		*/
	default:
		tmp_str = np_treeval_to_str(val, &free_string);
		ret = json_value_init_string(tmp_str);
		if (free_string == TRUE) {
			free(tmp_str);
		}
		break;
	}
	return ret;
}

char* np_dump_tree2char(np_state_t* context, np_tree_t* tree) {
	log_trace_msg(LOG_TRACE, "start: char* np_dump_tree2char(context, np_tree_t* tree) {");
	JSON_Value * tmp = np_tree2json(context, tree);
	char* tmp2 = np_json2char(tmp,TRUE);
	free(tmp);
	return tmp2;
}
JSON_Value* np_tree2json(np_state_t* context, np_tree_t* tree) {
	log_trace_msg(LOG_TRACE, "start: JSON_Value* np_tree2json(context, np_tree_t* tree) {");
	JSON_Value* ret = json_value_init_object();
	JSON_Value* arr = NULL;

	if(NULL != tree) {
		// log_debug_msg(LOG_DEBUG, "np_tree2json (size: %"PRIu16", byte_size: %"PRIu64"):", tree->size, tree->byte_size);

		uint16_t i = 0;
		// write jrb tree
		if (0 < tree->size)
		{
			np_tree_elem_t* tmp = NULL;
			np_bool useArray = FALSE;
			RB_FOREACH(tmp, np_tree_s, tree)
			{
				char* name = NULL;
				if (np_treeval_type_int == tmp->key.type)
				{
					useArray = TRUE;
					int size = snprintf(NULL, 0, "%d", tmp->key.value.i);
					name = malloc(size + 1);
					CHECK_MALLOC(name);

					snprintf(name, size + 1, "%d", tmp->key.value.i);
				}
				else if (np_treeval_type_double == tmp->key.type)
				{
					int size = snprintf(NULL, 0, "%f", tmp->key.value.d);
					name = malloc(size + 1);
					CHECK_MALLOC(name);

					snprintf(name, size + 1, "%f", tmp->key.value.d);
				}
				else if (np_treeval_type_unsigned_long == tmp->key.type)
				{
					int size = snprintf(NULL, 0, "%u", tmp->key.value.ul);
					name = malloc(size + 1);
					CHECK_MALLOC(name);

					snprintf(name, size + 1, "%u", tmp->key.value.ul);
				}
				else if (np_treeval_type_char_ptr == tmp->key.type)
				{
					name = strndup( np_treeval_to_str(tmp->key,NULL), strlen( np_treeval_to_str(tmp->key, NULL)));
				}
				else if (np_treeval_type_special_char_ptr == tmp->key.type)
				{
					name = strdup(_np_tree_get_special_str( tmp->key.value.ush));
				}
				else
				{
					log_msg(LOG_WARN, "unknown key type for serialization. (type: %d)",tmp->key.type);
					continue;
				}

				//log_debug_msg(LOG_DEBUG, "np_tree2json set key %s:", name);
				JSON_Value* value = np_treeval2json(context, tmp->val);

				if(useArray == TRUE) {
					if(NULL == arr) {
						arr = json_value_init_array();
					}
					//log_debug_msg(LOG_DEBUG, "np_tree2json add to array");

					if(NULL != value) {
						json_array_append_value(json_array(arr), value);
						i++;
					}
				} else {

					if (NULL != name && NULL != value)
					{
						json_object_set_value(json_object(ret), name, value);
						i++;
					}
				}
				free(name);
			}
		}

		// sanity check and warning message
		if (i != tree->size)
		{
			log_msg(LOG_WARN, "serialized jrb size map size is %hd, but should be %hd", tree->size, i);
		}
	}

	if(NULL != arr) {
		json_value_free(ret);
		ret = arr;
	}

	return ret;
}

char* np_json2char(JSON_Value* data, np_bool prettyPrint) {
	log_trace_msg(LOG_TRACE, "start: char* np_json2char(JSON_Value* data, np_bool prettyPrint) {");
	char* ret;
	/*
	size_t json_size ;
	if(prettyPrint){
		json_size = json_serialization_size_pretty(data);
		ret = (char*) malloc(json_size * sizeof(char));
		CHECK_MALLOC(ret);
		json_serialize_to_buffer_pretty(data, ret, json_size);

	}else{
		json_size = json_serialization_size(data);
		ret = (char*) malloc(json_size * sizeof(char));
		CHECK_MALLOC(ret);
		json_serialize_to_buffer(data, ret, json_size);
	}
	 */
	if(prettyPrint){
		ret = json_serialize_to_string_pretty(data);
	}else{
		ret = json_serialize_to_string(data);
	}


	return ret;
}

void np_dump_tree2log(np_state_t* context, log_type category, np_tree_t* tree){
	log_trace_msg(LOG_TRACE, "start: void np_dump_tree2log(context, np_tree_t* tree){");
	if(NULL == tree){
		log_debug_msg(LOG_DEBUG | category , "NULL");
	}else{
		char* tmp = np_dump_tree2char(context, tree);
		log_debug_msg(LOG_DEBUG | category , "%s", tmp);
		json_free_serialized_string(tmp);
	}
}
/*
 * cancats target with source and applys the variable arguments as a string format on source
 * frees target and reasigns it with the new string
 * @param target
 * @param source
 * @return
 */
char* np_str_concatAndFree(char* target, char* source, ... ) {

	if(target== NULL){
		asprintf(&target,"%s","");
	}
	char* new_target = NULL;
	char* tmp = NULL;
	va_list args;
	va_start(args, source);
	vasprintf(&tmp, source, args);
	va_end(args);

	asprintf(&new_target ,"%s%s",target,tmp);

	free(tmp);
	free(target);
	target = new_target;
	//free(source);
	return new_target;
}


np_bool np_get_local_ip(np_state_t* context, char* buffer,int buffer_size){

	np_bool ret = FALSE;

	const char* ext_server = "37.97.143.153";//"neuropil.io";
	int dns_port = 53;

	struct sockaddr_in serv;

	int sock = socket ( AF_INET, SOCK_DGRAM, 0);

	if(sock < 0)
	{
		ret = FALSE;
		log_msg(LOG_ERROR,"Could not detect local ip. (1) Error: Socket could not be created");
	} else {

		memset( &serv, 0, sizeof(serv) );
		serv.sin_family = AF_INET;
		serv.sin_addr.s_addr = inet_addr( ext_server );
		serv.sin_port = htons( dns_port );

		int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );
		if(err < 0 ){
			ret = FALSE;
			log_msg(LOG_ERROR,"Could not detect local ip. (2) Error: %s (%d)", strerror(errno), errno);
		} else
		{
			struct sockaddr_in name;
			socklen_t namelen = sizeof(name);
			err = getsockname(sock, (struct sockaddr*) &name, &namelen);

			if(err < 0 )
			{
				ret = FALSE;
				log_msg(LOG_ERROR,"Could not detect local ip. (3) Error: %s (%d)", strerror(errno), errno);
			} else
			{
				const char* p = inet_ntop(AF_INET, &name.sin_addr, buffer, buffer_size);

				if(p == NULL) {
					ret = FALSE;
					log_msg(LOG_ERROR,"Could not detect local ip. (4) Error: %s (%d)", strerror(errno), errno);
				}
				if(strncmp(buffer,"0.0.0.0", 7) == 0){
					ret = FALSE;
					log_msg(LOG_ERROR,"Could not detect local ip. (5) Error: ip result 0.0.0.0");
				}else{
					ret = TRUE;
				}

			}


		}

		close(sock);

	}

	return ret;
}


char_ptr _sll_char_remove(np_sll_t(char_ptr, target), char* to_remove, size_t cmp_len) {
	char * ret = NULL;
	char * tmp = NULL;
	sll_iterator(char_ptr) iter = sll_first(target);
	while (iter != NULL)
	{
		tmp = (iter->val);
		if (strncmp(tmp, to_remove, cmp_len) == 0)
		{
			ret = tmp;
			sll_delete(char_ptr, target, iter);
			break;
		}
		sll_next(iter);
	}
	return ret;
}
/*
 * Takes a char pointer list and concatinates it to one string
 */
char* _sll_char_make_flat(np_state_t* context, np_sll_t(char_ptr, target)) {
	char* ret = NULL;

	sll_iterator(char_ptr) iter = sll_first(target);
	uint32_t i = 0;
	while (iter != NULL)
	{
		ret = np_str_concatAndFree(ret, "%"PRIu32":\"%s\"->", i, iter->val);
		i++;
		sll_next(iter);
	}
#ifdef DEBUG
	if (sll_size(target) != i) {
		log_msg(LOG_ERROR, "Size of original list (%"PRIu32") does not equal the size of the flattend string (items flattend: %"PRIu32").", sll_size(target),i);
		abort();
	}
#endif
	return (ret);
}

/**
 * Returns a part copy of the original list.
 * If amount is negative the part contains the last elements of the original list.
*/
sll_return(char_ptr) _sll_char_part(np_sll_t(char_ptr, target), int32_t amount) {

	sll_return(char_ptr) ret;
	sll_init(char_ptr, ret);

	int begin_copy_at = 0;

	if (amount < 0) {
		// get from tail
		amount = amount * -1;
		if (sll_size(target) <= (uint32_t)amount) {
			amount = (int32_t)sll_size(target);
		}
		else {
			begin_copy_at = (int32_t)sll_size(target) - amount;
		}
	}

	sll_iterator(char_ptr) iter = sll_first(target);
	int i = 0;
	while (iter != NULL)
	{
		if (i >= begin_copy_at) {
			sll_append(char_ptr, ret, iter->val);
		}
		i++;
		sll_next(iter);
	}
	return ret;
}

#ifdef DEBUG_CALLBACKS
np_sll_t(void_ptr, __np_debug_statistics) = NULL;

void __np_util_debug_statistics_init() {
	if (__np_debug_statistics == NULL) {
		sll_init(void_ptr, __np_debug_statistics);
	}
}
_np_util_debug_statistics_t* __np_util_debug_statistics_get(char* key) {
	__np_util_debug_statistics_init();
	_np_util_debug_statistics_t* ret = NULL;
	_LOCK_MODULE(np_utilstatistics_t) {
		sll_iterator(void_ptr) iter = sll_first(__np_debug_statistics);

		while (iter != NULL) {
			_np_util_debug_statistics_t* item = (_np_util_debug_statistics_t*)iter->val;
			if (strncmp(item->key, key, 255) == 0) {
				ret = item;
				break;
			}
			sll_next(iter);
		}
	}
	return ret;
}
_np_util_debug_statistics_t* _np_util_debug_statistics_add(char* key, double value) {
	__np_util_debug_statistics_init();

	_np_util_debug_statistics_t* item = __np_util_debug_statistics_get(key);
	if (item == NULL) {
		item = (_np_util_debug_statistics_t*)calloc(1, sizeof(_np_util_debug_statistics_t));
		item->min = DBL_MAX;
		item->max = 0;
		item->avg = 0;
		memcpy(item->key, key, strnlen(key, 254));
		_np_threads_mutex_init(context, &item->lock,"debug_statistics");

		_LOCK_MODULE(np_utilstatistics_t) {
			sll_append(void_ptr, __np_debug_statistics, (void_ptr)item);
		}
	}

	_LOCK_ACCESS(&item->lock)
	{
		item->avg = (item->avg * item->count + value) / (item->count + 1);
		item->count++;

		item->max = max(value, item->max);
		item->min = min(value, item->min);
	}

	return item;
}
#endif


char* np_util_stringify_pretty(enum np_util_stringify_e type, void* data, char buffer[255]) {
	
	if (type == np_util_stringify_bytes_per_sec)
	{
		double bytes = *((double*)data);
		double to_format;
		double divisor = 1;
		char* f = "b/s";
		if (bytes < (100 * (divisor = 1024))) {
			f = "kB/s";
		}
		else if (bytes < (100 * (divisor = 1024 * 1024))) {
			f = "MB/s";
		}
		else if (bytes < (100 * (divisor = 1024 * 1024 * 1024))) {
			f = "GB/s";
		}
		else if (bytes < (100 * (divisor = 1024 * 1024 * 1024 * 1024))) {
			f = "TB/s";
		}
		to_format = bytes / divisor;
		sprintf(buffer, "%5.2f %s", to_format, f);
	}
	else if (type == np_util_stringify_bytes)
	{
		uint32_t bytes = *((uint32_t*)data);
		double to_format;
		double divisor = 1;
		char* f = "b";
		if (bytes < (100 * (divisor = 1024))) {
			f = "kB";
		}
		else if (bytes < (100 * (divisor = 1024 * 1024))) {
			f = "MB";
		}
		else if (bytes < (100 * (divisor = 1024 * 1024 * 1024))) {
			f = "GB";
		}
		else if (bytes < (100 * (divisor = 1024 * 1024 * 1024 * 1024))) {
			f = "TB";
		}
		to_format = bytes / divisor;
		sprintf(buffer, "%5.2f %s", to_format, f);
	}
	else {
		strcpy(buffer, "<unknown type>");
	}

	return buffer;
}