//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef	_NP_UTIL_H_
#define	_NP_UTIL_H_

#include <assert.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "msgpack/cmp.h"
#include "parson/parson.h"

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
	}                                                                                   \
	assert(expression);
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


	#define GENERATE_ENUM_STR(...) VFUNC(GENERATE_ENUM_STR, __VA_ARGS__)
	#define __GENERATE_ENUM_STR_BEGIN(NAME) enum NAME##_e {
	#define __GENERATE_ENUM_STR_MID(NAME)   NAME##_END};static const char * NAME##_str[] = {
	#define __GENERATE_ENUM_STR_END(NAME)   "END"};
	#define GENERATE_ENUM_STR2(NAME, e1) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1, __GENERATE_ENUM_STR_MID(NAME) #e1, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR3(NAME, e1,e2) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR4(NAME, e1,e2,e3) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR5(NAME, e1,e2,e3,e4) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR6(NAME, e1,e2,e3,e4,e5) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR7(NAME, e1,e2,e3,e4,e5,e6) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR8(NAME, e1,e2,e3,e4,e5,e6,e7) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR9(NAME, e1,e2,e3,e4,e5,e6,e7,e8) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR10(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR11(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR12(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR13(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR14(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR15(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR16(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR17(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR18(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR19(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR20(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR21(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR22(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR23(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR24(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR25(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR26(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR27(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR28(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR29(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR30(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR31(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR32(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR33(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR34(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR35(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR36(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR37(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35,e36) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35,NAME##_##e36, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35,#e36, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR38(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35,e36,e37) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35,NAME##_##e36,NAME##_##e37, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35,#e36,#e37, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR39(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35,e36,e37,e38) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35,NAME##_##e36,NAME##_##e37,NAME##_##e38, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35,#e36,#e37,#e38, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR40(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35,e36,e37,e38,e39) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35,NAME##_##e36,NAME##_##e37,NAME##_##e38,NAME##_##e39, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35,#e36,#e37,#e38,#e39, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR41(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35,e36,e37,e38,e39,e40) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35,NAME##_##e36,NAME##_##e37,NAME##_##e38,NAME##_##e39,NAME##_##e40, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35,#e36,#e37,#e38,#e39,#e40, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR42(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35,e36,e37,e38,e39,e40,e41) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35,NAME##_##e36,NAME##_##e37,NAME##_##e38,NAME##_##e39,NAME##_##e40,NAME##_##e41, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35,#e36,#e37,#e38,#e39,#e40,#e41, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR43(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35,e36,e37,e38,e39,e40,e41,e42) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35,NAME##_##e36,NAME##_##e37,NAME##_##e38,NAME##_##e39,NAME##_##e40,NAME##_##e41,NAME##_##e42, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35,#e36,#e37,#e38,#e39,#e40,#e41,#e42, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR44(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35,e36,e37,e38,e39,e40,e41,e42,e43) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35,NAME##_##e36,NAME##_##e37,NAME##_##e38,NAME##_##e39,NAME##_##e40,NAME##_##e41,NAME##_##e42,NAME##_##e43, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35,#e36,#e37,#e38,#e39,#e40,#e41,#e42,#e43, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR45(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35,e36,e37,e38,e39,e40,e41,e42,e43,e44) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35,NAME##_##e36,NAME##_##e37,NAME##_##e38,NAME##_##e39,NAME##_##e40,NAME##_##e41,NAME##_##e42,NAME##_##e43,NAME##_##e44, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35,#e36,#e37,#e38,#e39,#e40,#e41,#e42,#e43,#e44, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR46(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35,e36,e37,e38,e39,e40,e41,e42,e43,e44,e45) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35,NAME##_##e36,NAME##_##e37,NAME##_##e38,NAME##_##e39,NAME##_##e40,NAME##_##e41,NAME##_##e42,NAME##_##e43,NAME##_##e44,NAME##_##e45, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35,#e36,#e37,#e38,#e39,#e40,#e41,#e42,#e43,#e44,#e45, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR47(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35,e36,e37,e38,e39,e40,e41,e42,e43,e44,e45,e46) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35,NAME##_##e36,NAME##_##e37,NAME##_##e38,NAME##_##e39,NAME##_##e40,NAME##_##e41,NAME##_##e42,NAME##_##e43,NAME##_##e44,NAME##_##e45,NAME##_##e46, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35,#e36,#e37,#e38,#e39,#e40,#e41,#e42,#e43,#e44,#e45,#e46, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR48(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35,e36,e37,e38,e39,e40,e41,e42,e43,e44,e45,e46,e47) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35,NAME##_##e36,NAME##_##e37,NAME##_##e38,NAME##_##e39,NAME##_##e40,NAME##_##e41,NAME##_##e42,NAME##_##e43,NAME##_##e44,NAME##_##e45,NAME##_##e46,NAME##_##e47, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35,#e36,#e37,#e38,#e39,#e40,#e41,#e42,#e43,#e44,#e45,#e46,#e47, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR49(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35,e36,e37,e38,e39,e40,e41,e42,e43,e44,e45,e46,e47,e48) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35,NAME##_##e36,NAME##_##e37,NAME##_##e38,NAME##_##e39,NAME##_##e40,NAME##_##e41,NAME##_##e42,NAME##_##e43,NAME##_##e44,NAME##_##e45,NAME##_##e46,NAME##_##e47,NAME##_##e48, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35,#e36,#e37,#e38,#e39,#e40,#e41,#e42,#e43,#e44,#e45,#e46,#e47,#e48, __GENERATE_ENUM_STR_END(NAME)
	#define GENERATE_ENUM_STR50(NAME, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15,e16,e17,e18,e19,e20,e21,e22,e23,e24,e25,e26,e27,e28,e29,e30,e31,e32,e33,e34,e35,e36,e37,e38,e39,e40,e41,e42,e43,e44,e45,e46,e47,e48,e49) __GENERATE_ENUM_STR_BEGIN(NAME) NAME##_##e1,NAME##_##e2,NAME##_##e3,NAME##_##e4,NAME##_##e5,NAME##_##e6,NAME##_##e7,NAME##_##e8,NAME##_##e9,NAME##_##e10,NAME##_##e11,NAME##_##e12,NAME##_##e13,NAME##_##e14,NAME##_##e15,NAME##_##e16,NAME##_##e17,NAME##_##e18,NAME##_##e19,NAME##_##e20,NAME##_##e21,NAME##_##e22,NAME##_##e23,NAME##_##e24,NAME##_##e25,NAME##_##e26,NAME##_##e27,NAME##_##e28,NAME##_##e29,NAME##_##e30,NAME##_##e31,NAME##_##e32,NAME##_##e33,NAME##_##e34,NAME##_##e35,NAME##_##e36,NAME##_##e37,NAME##_##e38,NAME##_##e39,NAME##_##e40,NAME##_##e41,NAME##_##e42,NAME##_##e43,NAME##_##e44,NAME##_##e45,NAME##_##e46,NAME##_##e47,NAME##_##e48,NAME##_##e49, __GENERATE_ENUM_STR_MID(NAME) #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9,#e10,#e11,#e12,#e13,#e14,#e15,#e16,#e17,#e18,#e19,#e20,#e21,#e22,#e23,#e24,#e25,#e26,#e27,#e28,#e29,#e30,#e31,#e32,#e33,#e34,#e35,#e36,#e37,#e38,#e39,#e40,#e41,#e42,#e43,#e44,#e45,#e46,#e47,#e48,#e49, __GENERATE_ENUM_STR_END(NAME)


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
