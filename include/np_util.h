//
// neuropil is copyright 2016-2020 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef	_NP_UTIL_H_
#define	_NP_UTIL_H_

#include <assert.h>

#include "msgpack/cmp.h"
#include "json/parson.h"

#include "util/np_tree.h"
#include "np_threads.h"
#include "np_settings.h"


#ifdef __cplusplus
extern "C" {
#endif

#ifndef _np_debug_log_bin
	#ifdef DEBUG
		#define _np_debug_log_bin0(bin, bin_size, log_category, log_msg) {   	\
			char hex[bin_size * 2 + 1];							 				\
			sodium_bin2hex(hex, bin_size * 2 + 1, bin, bin_size); 				\
			log_debug_msg(log_category, log_msg, hex );			                \
		}
		#define _np_debug_log_bin(bin, bin_size, log_category, log_msg, ...) {	\
			char hex[bin_size * 2 + 1];							 				\
			sodium_bin2hex(hex, bin_size * 2 + 1, bin, bin_size); 				\
			log_debug_msg(log_category, log_msg, __VA_ARGS__, hex );			\
		}
	#else
		#define _np_debug_log_bin0(bin, bin_size, log_category, log_msg)
		#define _np_debug_log_bin(bin, bin_size, log_category, log_msg, ...)
	#endif
#endif

#ifdef DEBUG
#define debugf(s, ...) fprintf(stdout, s, ##__VA_ARGS__);fflush(stdout)
#else
#define debugf(s, ...)
#endif
#define ARRAY_SIZE(array) ((int)( sizeof(array) / sizeof(array[0])))

#define FLAG_CMP(data,flag) (((data) & (flag)) == (flag))

#define STRINGIFY(x) #x
#define TO_STRING(x) STRINGIFY(x)

#ifdef DEBUG
#define ASSERT(expression, onfail_msg, ...)												\
	if(!(expression)){																	\
		fprintf(stderr, "Assert ERROR: "onfail_msg"\r\n", ##__VA_ARGS__);				\
		fflush(NULL);																	\
		assert((expression));															\
	}
#else
#define ASSERT(expression, onfail_msg, ...)												\
	if (!(expression)) {																\
			log_debug_msg(LOG_ERROR, onfail_msg, ##__VA_ARGS__);						\
	}
#endif

#ifndef MAX
	#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
	#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif


#define _NP_GENERATE_PROPERTY_SETVALUE(OBJ,PROP_NAME,TYPE)			\
static const char* PROP_NAME##_str = # PROP_NAME;					\
inline void _##OBJ##_set_##PROP_NAME(OBJ* obj, TYPE value) {		\
	obj->PROP_NAME = value;											\
}

#define _NP_GENERATE_PROPERTY_SETVALUE_IMPL(OBJ,PROP_NAME,TYPE)		\
void _##OBJ##_set_##PROP_NAME(OBJ* obj, TYPE value);

#define _NP_GENERATE_PROPERTY_SETSTR(OBJ,PROP_NAME)					\
inline void OBJ##_set_##PROP_NAME(OBJ* obj, const char* value) {	\
	obj->PROP_NAME = strndup(value, strlen(value));					\
}

#define _NP_GENERATE_MSGPROPERTY_SETVALUE(PROP_NAME,TYPE)			\
inline void np_set_##PROP_NAME(const char* subject, np_msg_mode_type mode_type, TYPE value) { \
	np_msgproperty_t* msg_prop = np_message_get_handler(state, mode_type, subject); \
	if (NULL == msg_prop)                                 				\
	{                                                     				\
		np_new_obj(np_msgproperty_t, msg_prop);           				\
		msg_prop->mode_type = mode_type;                  				\
		msg_prop->msg_subject = strndup(subject, 255);    				\
		np_message_register_handler(state, msg_prop);     				\
		np_unref_obj(np_msgproperty_t, msg_prop, ref_obj_creation);     \
	}                                                     				\
	msg_prop->PROP_NAME = value;                          				\
}


// create a sha156 uuid string, take the current date into account
NP_API_EXPORT
char* np_uuid_create(const char* str, const uint16_t num, char** buffer);

NP_API_INTERN
void _np_sll_remove_doublettes(np_sll_t(np_key_ptr, list_of_keys));

NP_API_INTERN
void np_key_ref_list(np_sll_t(np_key_ptr, sll_list), const char* reason, const char* reason_desc);

NP_API_INTERN
void np_key_unref_list(np_sll_t(np_key_ptr, sll_list) , const char* reason);

/**
.. c:function:: void np_tree2json()

  Create a json object from a given tree

*/
NP_API_EXPORT
JSON_Value* np_tree2json(np_state_t * context, np_tree_t* tree) ;
 /**
.. c:function:: void np_json2char()

   Create a string from a given JSON Object

*/
NP_API_EXPORT
char* np_json2char(JSON_Value* data,bool prettyPrint) ;
/**
 * convert np_treeval_t to JSON_Value
 */
NP_API_EXPORT
JSON_Value* np_treeval2json(np_state_t * context, np_treeval_t val);
/**
.. c:function:: void np_dump_tree2log()

   Dumps the given tree as json string into the debug log

*/
NP_API_EXPORT
void np_dump_tree2log(np_state_t * context, log_type category, np_tree_t* tree);
/**
.. c:function:: void np_dump_tree2log()

   Dumps the given tree as json string into a char array

*/
NP_API_EXPORT
char* np_dump_tree2char(np_state_t* context, np_tree_t* tree);

NP_API_PROTEC
char* np_str_concatAndFree(char* target, char* source, ... );

NP_API_PROTEC
bool np_get_local_ip(np_state_t* context, char* buffer, int buffer_size);

NP_API_PROTEC
uint8_t np_util_char_ptr_cmp(char_ptr const a, char_ptr const b) ;
NP_API_PROTEC
char* _sll_char_make_flat(np_state_t* context, np_sll_t(char_ptr, target));
NP_API_INTERN
char_ptr _sll_char_remove(np_sll_t(char_ptr, target), char* to_remove, size_t cmp_len);
NP_API_INTERN
sll_return(char_ptr) _sll_char_part(np_sll_t(char_ptr, target), int32_t amount);

enum np_util_stringify_e {
	np_util_stringify_time_ms,
	np_util_stringify_bytes,
	np_util_stringify_bytes_per_sec
}NP_API_EXPORT;
NP_API_EXPORT
char* np_util_stringify_pretty(enum np_util_stringify_e type, void* data, char buffer[255]);
NP_API_EXPORT
char* np_util_string_trim_left(char* target);

NP_API_EXPORT
void np_tree2buffer(np_state_t* context, np_tree_t* tree, void* buffer);
NP_API_EXPORT
void np_buffer2tree(np_state_t* context, void* buffer, np_tree_t* tree);

#ifdef __cplusplus
}
#endif

#endif // _NP_UTIL_H_
