//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <ctype.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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
#include "np_tree.h"
#include "np_node.h"
#include "np_route.h"
#include "np_types.h"
#include "np_memory.h"
#include "assert.h"


char* np_uuid_create(const char* str, const uint16_t num)
{
	char input[256];
	unsigned char out[18];
	char* uuid_out = malloc(sizeof(char)*37);
	CHECK_MALLOC(uuid_out);

	double now = ev_time();
	snprintf (input, 255, "%s:%u:%16.16f", str, num, now);
	// log_msg(LOG_DEBUG, "created input uuid: %s", input);
	crypto_generichash(out, 18, (unsigned char*) input, 256, NULL, 0);
	sodium_bin2hex(uuid_out, 37, out, 18);
	// log_msg(LOG_DEBUG, "created raw uuid: %s", uuid_out);
	uuid_out[8] = uuid_out[13] = uuid_out[18] = uuid_out[23] = '-';
	uuid_out[14] = '5';
	uuid_out[19] = '9';
	// log_msg(LOG_DEBUG, "created new uuid: %s", uuid_out);

	return uuid_out;
}

np_bool _np_buffer_reader(struct cmp_ctx_s *ctx, void *data, size_t limit)
{
	if(ctx == NULL ){
		log_msg(LOG_DEBUG, "ctx is null");
	}

	memcpy(data, ctx->buf, limit);
	ctx->buf += limit;
	return TRUE;
}

size_t _np_buffer_writer(struct cmp_ctx_s *ctx, const void *data, size_t count)
{
	// log_msg(LOG_DEBUG, "-- writing cmp->buf: %p size: %hd", ctx->buf, count);
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


void _np_sll_remove_doublettes(np_sll_t(np_key_t, list_of_keys))
{
    sll_iterator(np_key_t) iter1 = sll_first(list_of_keys);
    sll_iterator(np_key_t) tmp = NULL;

    do
    {
        sll_iterator(np_key_t) iter2 = sll_get_next(iter1);

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
        		sll_delete(np_key_t, list_of_keys, tmp);
        		tmp = NULL;
        	}
        } while(NULL != iter2);

        sll_next(iter1);

    } while (NULL != iter1);
}


JSON_Value* np_treeval2json(np_treeval_t val) {
	JSON_Value* ret = NULL;
	//log_msg(LOG_DEBUG, "np_treeval2json type: %"PRIu8,val.type);
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
	JSON_Value * tmp = np_tree2json(tree);
	char* tmp2 = np_json2char(tmp,TRUE);
	free(tmp);
	return tmp2;
}
JSON_Value* np_tree2json(np_tree_t* tree) {
	JSON_Value* ret = json_value_init_object();
	JSON_Value* arr = NULL;

	if(NULL != tree) {
		// log_msg(LOG_DEBUG, "np_tree2json (size: %"PRIu16", byte_size: %"PRIu64"):", tree->size, tree->byte_size);

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

				//log_msg(LOG_DEBUG, "np_tree2json set key %s:", name);
				JSON_Value* value = np_treeval2json(tmp->val);

				if(useArray == TRUE) {
					if(NULL == arr) {
						arr = json_value_init_array();
					}
					//log_msg(LOG_DEBUG, "np_tree2json add to array");

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
	if(NULL == tree){
		log_msg(LOG_DEBUG, "NULL");
	}else{
 		char* tmp = np_dump_tree2char(tree);
		log_msg(LOG_DEBUG, "%s", tmp);
		json_free_serialized_string(tmp);
	}
}
