//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef	_NP_UTIL_H_
#define	_NP_UTIL_H_

#include <assert.h>

#include "msgpack/cmp.h"
#include "json/parson.h"

#include "np_tree.h"
#include "np_threads.h"

#ifdef __cplusplus
extern "C" {
#endif


#ifndef CEIL
#define CEIL(a) (((a-(int)a) > 0) ? ((int)a)+1:a)
#endif
#ifndef FLOOR
#define FLOOR(a) ((int)a)
#endif
#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif
#ifndef min
#define min(a,b) MIN(a,b)
#endif
#ifndef ceil
#define ceil(a) CEIL(a)
#endif
#ifndef floor
#define floor(a) FLOOR(a)
#endif
#ifndef max
#define max(a,b) MAX(a,b)
#endif


#define FLAG_CMP(data,flag) (((data) & (flag)) == (flag))

#ifdef DEBUG
#define ASSERT(expression, onfail_msg, ...)												\
	if(!(expression)){																	\
		log_debug_msg(LOG_ERROR, onfail_msg , ##__VA_ARGS__);							\
		fprintf(stderr, "Assert ERROR: "onfail_msg"\r\n", ##__VA_ARGS__);				\
		fflush(NULL);																	\
		assert((expression));															\
	}																						 
#else
#define ASSERT(expression, onfail_msg, ...)
	if (!(expression)) {																\
			log_debug_msg(LOG_ERROR, onfail_msg, ##__VA_ARGS__);						\
	}
#endif

#define NP_GENERATE_THREADSAFE_PROPERTY_PROTOTYPE(TYPE, PROPERTY_NAME)					\
	TYPE PROPERTY_NAME##_get();															\
	void PROPERTY_NAME##_set(TYPE obj);														

#define NP_GENERATE_THREADSAFE_PROPERTY_IMPL(TYPE, PROPERTY_NAME, PROPERTY)				\
	TYPE PROPERTY_NAME##_get() {														\
}



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

#define UUID_SIZE 37
// create a sha156 uuid string, take the current date into account
NP_API_EXPORT
char* np_uuid_create(const char* str, const uint16_t num);

NP_API_INTERN
void _np_tree2jsonobj(np_tree_t* jtree, JSON_Object* json_obj);

NP_API_INTERN
void _np_sll_remove_doublettes(np_sll_t(np_key_ptr, list_of_keys));

/**
.. c:function:: void np_tree2json()

  Create a json object from a given tree

*/
NP_API_EXPORT
JSON_Value* np_tree2json(np_tree_t* tree) ;
 /**
.. c:function:: void np_json2char()

   Create a string from a given JSON Object

*/
NP_API_EXPORT
char* np_json2char(JSON_Value* data,np_bool prettyPrint) ;
/**
 * convert np_treeval_t to JSON_Value
 */
NP_API_EXPORT
JSON_Value* np_treeval2json(np_treeval_t val);
/**
.. c:function:: void np_dump_tree2log()

   Dumps the given tree as json string into the debug log

*/
NP_API_EXPORT
void np_dump_tree2log(log_type category, np_tree_t* tree);
/**
.. c:function:: void np_dump_tree2log()

   Dumps the given tree as json string into a char array

*/
NP_API_EXPORT
char* np_dump_tree2char(np_tree_t* tree);

NP_API_PROTEC
char* np_str_concatAndFree(char* target, char* source, ... );

NP_API_PROTEC
np_bool np_get_local_ip(char* buffer, int buffer_size);

NP_API_PROTEC
char* _sll_char_make_flat(np_sll_t(char_ptr, target));
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
_np_util_debug_statistics_t* _np_util_debug_statistics_add(char* key, double value);
NP_API_INTERN
_np_util_debug_statistics_t* __np_util_debug_statistics_get(char* key);
#endif

#ifdef __cplusplus
}
#endif

#endif // _NP_UTIL_H_
