//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef	_NP_UTIL_H_
#define	_NP_UTIL_H_

#include <assert.h>

#include "msgpack/cmp.h"
#include "json/parson.h"

#include "np_tree.h"
#include "np_threads.h"
#include "np_settings.h"
#include "np_statistics.h"


#ifdef __cplusplus
extern "C" {
#endif

	 

#ifdef DEBUG
#define debugf(s, ...) fprintf(stdout, s, ##__VA_ARGS__);fflush(stdout)
#else
#define debugf(s, ...)
#endif
	

#define FLAG_CMP(data,flag) (((data) & (flag)) == (flag))

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
	if (NULL == msg_prop)                                 \
	{                                                     \
		np_new_obj(np_msgproperty_t, msg_prop);           \
		msg_prop->mode_type = mode_type;                  \
		msg_prop->msg_subject = strndup(subject, 255);    \
		np_message_register_handler(state, msg_prop);     \
	}                                                     \
	msg_prop->PROP_NAME = value;                          \
}


// create a sha156 uuid string, take the current date into account
NP_API_EXPORT
char* np_uuid_create(const char* str, const uint16_t num, char** buffer);

NP_API_INTERN
void _np_sll_remove_doublettes(np_sll_t(np_key_ptr, list_of_keys));

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
char* _sll_char_make_flat(np_state_t* context, np_sll_t(char_ptr, target));
NP_API_INTERN
char_ptr _sll_char_remove(np_sll_t(char_ptr, target), char* to_remove, size_t cmp_len);
NP_API_INTERN
sll_return(char_ptr) _sll_char_part(np_sll_t(char_ptr, target), int32_t amount);

#ifdef DEBUG_CALLBACKS
typedef struct {
	char key[255];
	uint32_t count;
	np_mutex_t lock;
	double avg;
	double min;
	double max;
} _np_util_debug_statistics_t;

NP_API_INTERN
_np_util_debug_statistics_t* _np_util_debug_statistics_add(np_state_t * context, char* key, double value);
NP_API_INTERN
_np_util_debug_statistics_t* __np_util_debug_statistics_get(np_state_t * context, char* key);
NP_API_INTERN
char* __np_util_debug_statistics_print(np_state_t * context);
#endif

enum np_util_stringify_e {
	np_util_stringify_time_ms,
	np_util_stringify_bytes,
	np_util_stringify_bytes_per_sec
}NP_API_EXPORT;
NP_API_EXPORT
char* np_util_stringify_pretty(enum np_util_stringify_e type, void* data, char buffer[255]);
NP_API_EXPORT
char* np_util_string_trim_left(char* target);


#ifdef __cplusplus
}
#endif

#endif // _NP_UTIL_H_
