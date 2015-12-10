/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#ifndef	_NP_UTIL_H_
#define	_NP_UTIL_H_

#include "cmp.h"

#include "np_jtree.h"

#define _NP_GENERATE_PROPERTY_SETVALUE(OBJ,PROP_NAME,TYPE) \
inline void OBJ##_set_##PROP_NAME(OBJ* obj, TYPE value) {  \
	obj->PROP_NAME = value;                                \
}

#define _NP_GENERATE_PROPERTY_SETSTR(OBJ,PROP_NAME)              \
inline void OBJ##_set_##PROP_NAME(OBJ* obj, const char* value) { \
	obj->PROP_NAME = strndup(value, strlen(value));              \
}

#define _NP_GENERATE_MSGPROPERTY_SETVALUE(PROP_NAME,TYPE) \
inline void np_set_##PROP_NAME(const char* subject, np_msg_mode_type mode_type, TYPE value) { \
	np_msgproperty_t* msg_prop = np_message_get_handler(state, mode_type, subject); \
	if (NULL == msg_prop)                              \
	{                                                  \
		np_new_obj(np_msgproperty_t, msg_prop);        \
		msg_prop->mode_type = mode_type;               \
		msg_prop->msg_subject = strndup(subject, 255); \
		np_message_register_handler(state, msg_prop);  \
	}                                                  \
	msg_prop->PROP_NAME = value;                       \
}

// create a sha156 uuid string, take the current date into account
char* np_create_uuid(const char* str, const uint16_t num);

// the following four are helper functions for c-message-pack to work on jtree structures
np_bool buffer_reader(cmp_ctx_t *ctx, void *data, size_t count);
size_t buffer_writer(cmp_ctx_t *ctx, const void *data, size_t count);
void serialize_jrb_node_t(np_jtree_t* jrb, cmp_ctx_t* cmp);
void deserialize_jrb_node_t(np_jtree_t* jrb, cmp_ctx_t* cmp);

#endif // _NP_UTIL_H_
