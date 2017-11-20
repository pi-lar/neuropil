//
// neuropil is copyright 2016 by pi-lar GmbH
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

#include "sodium.h"
#include "event/ev.h"
#include "json/parson.h"
#include "msgpack/cmp.h"
#include "inttypes.h"

#include "np_util.h"


#include "np_log.h"
#include "neuropil.h"

#include "dtime.h"
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

char* np_uuid_create(const char* str, const uint16_t num)
{
	log_msg(LOG_TRACE, "start: char* np_uuid_create(const char* str, const uint16_t num){");
	char input[256] ="";
	unsigned char out[18]="";
	char* uuid_out = calloc(1,sizeof(char)*UUID_SIZE);
	CHECK_MALLOC(uuid_out);

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

np_bool _np_buffer_reader(struct cmp_ctx_s *ctx, void *data, size_t limit)
{
	log_msg(LOG_TRACE, "start: np_bool _np_buffer_reader(struct cmp_ctx_s *ctx, void *data, size_t limit){");
	memcpy(data, ctx->buf, limit);
	ctx->buf += limit;
	return TRUE;
}

np_bool _np_buffer_container_reader(struct cmp_ctx_s* ctx, void* data, size_t limit)
{
	log_msg(LOG_TRACE, "start: np_bool _np_buffer_container_reader(struct cmp_ctx_s* ctx, void* data, size_t limit){");
	np_bool ret = FALSE;
	_np_message_buffer_container_t* wrapper = ctx->buf;

	size_t nextCount = wrapper->bufferCount + limit;
	log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG,
			 "BUFFER CHECK Current size: %zu; Max size: %zu; Read size: %zu",
			 wrapper->bufferCount, wrapper->bufferMaxCount, limit);

	if(nextCount > wrapper->bufferMaxCount) {
		 log_msg(LOG_WARN,
				 "Read size exceeds buffer. May be invoked due to changed key (see: kb) Current size: %zu; Max size: %zu; Read size: %zu",
				 wrapper->bufferCount, wrapper->bufferMaxCount, nextCount);
	} else {
		log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "memcpy %p <- %p o %p",data, wrapper->buffer,wrapper);
		memcpy(data, wrapper->buffer, limit);
		wrapper->buffer += limit;
		wrapper->bufferCount = nextCount;
		ret = TRUE;
	}
	return ret;
}

size_t _np_buffer_container_writer(struct cmp_ctx_s* ctx, const void* data, size_t count)
{
	log_msg(LOG_TRACE, "start: size_t _np_buffer_container_writer(struct cmp_ctx_s* ctx, const void* data, size_t count){");
	_np_message_buffer_container_t* wrapper = ctx->buf;

	size_t nextCount = wrapper->bufferCount + count;
	log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG,
			 "BUFFER CHECK Current size: %zu; Max size: %zu; Read size: %zu",
			 wrapper->bufferCount, wrapper->bufferMaxCount, count);

	if(nextCount > wrapper->bufferMaxCount) {
		 log_msg(LOG_WARN,
				 "Write size exceeds buffer. Current size: %zu; Max size: %zu; Read size: %zu",
				 wrapper->bufferCount, wrapper->bufferMaxCount, nextCount);
	}
	memcpy(wrapper->buffer, data, count);
	wrapper->buffer += count;
	return count;
}

size_t _np_buffer_writer(struct cmp_ctx_s *ctx, const void *data, size_t count)
{
	log_msg(LOG_TRACE, "start: size_t _np_buffer_writer(struct cmp_ctx_s *ctx, const void *data, size_t count){");
	// log_debug_msg(LOG_DEBUG, "-- writing cmp->buf: %p size: %hd", ctx->buf, count);
	// printf( "-- writing cmp->buf: %p size: %hd\n", ctx->buf, count);

	memcpy(ctx->buf, data, count);
	ctx->buf += count;
	return count;
}


// TODO: replace with function pointer, same for __np_tree_read_type
// typedef void (*write_type_function)(const np_treeval_t* val, cmp_ctx_t* ctx);
// write_type_function write_type_arr[npval_count] = {NULL};
// write_type_arr[npval_count] = &write_short_type;
// write_type_arr[npval_count] = NULL;


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
			if (0 == _np_dhkey_comp(&iter1->val->dhkey,
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


JSON_Value* np_treeval2json(np_treeval_t val) {
	log_msg(LOG_TRACE, "start: JSON_Value* np_treeval2json(np_treeval_t val) {");
	JSON_Value* ret = NULL;
	//log_debug_msg(LOG_DEBUG, "np_treeval2json type: %"PRIu8,val.type);
	void* tmp;
	switch (val.type) {
	case short_type:
		ret = json_value_init_number(val.value.sh);
		break;
	case int_type:
		ret = json_value_init_number(val.value.i);
		break;
	case long_type:
		ret = json_value_init_number(val.value.l);
		break;
	case long_long_type:
		ret = json_value_init_number(val.value.ll);
		break;
	case float_type:
		ret = json_value_init_number(val.value.f);
		break;
	case double_type:
		ret = json_value_init_number(val.value.d);
		break;
	case char_ptr_type:
		ret = json_value_init_string(val.value.s);
		break;
	case char_type:
		ret = json_value_init_string(&val.value.c);
		break;
	case unsigned_short_type:
		ret = json_value_init_number(val.value.ush);
		break;
	case unsigned_int_type:
		ret = json_value_init_number(val.value.ui);
		break;
	case unsigned_long_type:
		ret = json_value_init_number(val.value.ul);
		break;
	case unsigned_long_long_type:
		ret = json_value_init_number(val.value.ull);
		break;
	case uint_array_2_type:
		ret = json_value_init_array();
		json_array_append_number(json_array(ret), val.value.a2_ui[0]);
		json_array_append_number(json_array(ret), val.value.a2_ui[1]);
		break;
	case bin_type:
		tmp =  malloc(sizeof(char)*64);
		CHECK_MALLOC(tmp);

		sprintf(tmp, "<binaray data (size: %"PRIu32")>", val.size);
		ret = json_value_init_string((char*)tmp);
		free(tmp);
		break;
	case jrb_tree_type:
		ret = np_tree2json(val.value.tree);
		break;
	case key_type:
		ret = json_value_init_array();
		json_array_append_number(json_array(ret), val.value.key.t[0]);
		json_array_append_number(json_array(ret), val.value.key.t[1]);
		json_array_append_number(json_array(ret), val.value.key.t[2]);
		json_array_append_number(json_array(ret), val.value.key.t[3]);
		break;
	default:
		log_msg(LOG_WARN, "please implement serialization for type %hhd",
				val.type);

		break;
	}
	return ret;
}

char* np_dump_tree2char(np_tree_t* tree) {
	log_msg(LOG_TRACE, "start: char* np_dump_tree2char(np_tree_t* tree) {");
	JSON_Value * tmp = np_tree2json(tree);
	char* tmp2 = np_json2char(tmp,TRUE);
	free(tmp);
	return tmp2;
}
JSON_Value* np_tree2json(np_tree_t* tree) {
	log_msg(LOG_TRACE, "start: JSON_Value* np_tree2json(np_tree_t* tree) {");
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
				if (int_type == tmp->key.type)
				{
					useArray = TRUE;
					int size = snprintf(NULL, 0, "%d", tmp->key.value.i);
					name = malloc(size + 1);
					CHECK_MALLOC(name);

					snprintf(name, size + 1, "%d", tmp->key.value.i);
				}
				else if (double_type == tmp->key.type)
				{
					int size = snprintf(NULL, 0, "%f", tmp->key.value.d);
					name = malloc(size + 1);
					CHECK_MALLOC(name);

					snprintf(name, size + 1, "%f", tmp->key.value.d);
				}
				else if (unsigned_long_type == tmp->key.type)
				{
					int size = snprintf(NULL, 0, "%u", tmp->key.value.ul);
					name = malloc(size + 1);
					CHECK_MALLOC(name);

					snprintf(name, size + 1, "%u", tmp->key.value.ul);
				}
				else if (char_ptr_type == tmp->key.type)
				{
					name = strndup(tmp->key.value.s, strlen(tmp->key.value.s));
				}
				else
				{
					log_msg(LOG_WARN, "unknown key type for serialization. (type: %d)",tmp->key.type);
					continue;
				}

				//log_debug_msg(LOG_DEBUG, "np_tree2json set key %s:", name);
				JSON_Value* value = np_treeval2json(tmp->val);

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
	log_msg(LOG_TRACE, "start: char* np_json2char(JSON_Value* data, np_bool prettyPrint) {");
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

void np_dump_tree2log(np_tree_t* tree){
	log_msg(LOG_TRACE, "start: void np_dump_tree2log(np_tree_t* tree){");
	if(NULL == tree){
		log_debug_msg(LOG_DEBUG, "NULL");
	}else{
		char* tmp = np_dump_tree2char(tree);
		log_debug_msg(LOG_DEBUG, "%s", tmp);
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
char* _np_concatAndFree(char* target, char* source, ... ) {

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


np_bool _np_get_local_ip(char* buffer,int buffer_size){

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
char* _sll_char_make_flat(np_sll_t(char_ptr, target)) {
	char* ret = NULL;

	sll_iterator(char_ptr) iter = sll_first(target);
	int i = 0;
	while (iter != NULL)
	{				
		ret = _np_concatAndFree(ret, "%d:\"%s\"->", i, iter->val);
		i++;
		sll_next(iter);
	}			
	if (sll_size(target) != i) {
		log_msg(LOG_ERROR, "Size of original list (%d) does not equal the size of the flattend string (items flattend: %d).", sll_size(target),i);
		abort();
	}
	return ret;
}

/** 
 * Returns a part copy of the original list. 
 * If amount is negative the part contains the last elements of the original list.
*/
sll_return(char_ptr) _sll_char_part(np_sll_t(char_ptr, target), int amount) {
	
	sll_return(char_ptr) ret;
	sll_init(char_ptr, ret);

	int begin_copy_at = 0;

	if (amount < 0) {
		// get from tail
		amount = amount * -1;
		if (sll_size(target) <= amount) {
			amount = sll_size(target);
		}
		else {
			begin_copy_at = sll_size(target) - amount;
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
		_np_threads_mutex_init(&item->lock,"debug_statistics");

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
/*
	compares pointers and returns 0 if both pointers are the same
*/
int _np_util_cmp_ref(void* a, void* b) {
	return a == b ? 0 : -1;
}