//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/**
np_list.h contains header only list implementations for the c language.

The three supported list type are double linked, single linked and priority list.
All functions are defined as macros and should be used as templates,
concrete list functions will be generated by the pre-processor per defined type

declare your list usage with the following macro in a header file:

*.. c:macro:: NP_PLL_GENERATE_PROTOTYPES(TYPE)
*             NP_SLL_GENERATE_PROTOTYPES(TYPE)
*             NP_DLL_GENERATE_PROTOTYPES(TYPE)


followed by the corresponding implementation macro in a source file:

*.. c:macro:: NP_PLL_GENERATE_IMPLEMENTATION(TYPE)
*             NP_SLL_GENERATE_IMPLEMENTATION(TYPE)
*             NP_DLL_GENERATE_IMPLEMENTATION(TYPE)

afterwards you can use the following function like macros in your source code like normal functions


*/

#ifndef _NP_LIST_H_
#define _NP_LIST_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
priority list macros (PLL)

function like macros are:

*.. c:macro:: np_pll_t(TYPE, NAME)
*             void pll_init(TYPE, priolist, compare_func)
*             void pll_insert(TYPE, priolist, value, dups_ok)
*             void pll_remove(TYPE, priolist, value)
*			  TYPE pll_replace(TYPE, priolist, value, cmp_func)
*			  TYPE pll_find(TYPE, priolist, value, cmp_func)
*			  TYPE pll_head(TYPE, priolist)
*			  TYPE pll_tail(TYPE, priolist)
*             void pll_free(TYPE, priolist)
*             void pll_clear(TYPE, priolist)
*/

#define np_pll_t(TYPE, NAME) TYPE##_pll_t* NAME;

#define pll_init(TYPE, priolist) priolist = TYPE##_pll_init();
#define pll_insert(TYPE, priolist, value, dups_ok, cmp_func) TYPE##_pll_insert(priolist, value, dups_ok, cmp_func)
#define pll_remove(TYPE, priolist, value, cmp_func) TYPE##_pll_remove(priolist, value, cmp_func);
#define pll_replace(TYPE, priolist, value, cmp_func) TYPE##_pll_replace(priolist, value, cmp_func);
#define pll_find(TYPE, priolist, value, cmp_func) TYPE##_pll_find(priolist, value, cmp_func);
#define pll_head(TYPE, priolist) TYPE##_pll_head(priolist);
#define pll_tail(TYPE, priolist) TYPE##_pll_tail(priolist);
#define pll_free(TYPE, priolist) TYPE##_pll_free(priolist);
#define pll_clear(TYPE, priolist) TYPE##_pll_clear(priolist);

/**
return type definition macros are

*.. c:macro:: pll_return(TYPE) TYPE##_pll_t*
*             pll_iterator(TYPE) TYPE##_pll_node_t*


*/
// return type definition
#define pll_return(TYPE) TYPE##_pll_t*
#define pll_iterator(TYPE) TYPE##_pll_node_t*

/**
real macros for convenience usage

*.. c:macro::  pll_empty(priolist)    (NULL == priolist->first)
*              pll_size(priolist)     (priolist->size)
*              pll_first(priolist)    (priolist->first)
*              pll_last(priolist)     (priolist->last)
*              pll_next(pll_elem)     (pll_elem = pll_elem->flink)
*              pll_get_next(pll_elem) (pll_elem->flink)
*              pll_has_next(pll_elem) (NULL != pll_elem->flink)
*              pll_previous(pll_elem) (pll_elem = pll_elem->blink)
*              pll_get_previous(pll_elem) (pll_elem->blink)
*              pll_has_previous(pll_elem) (NULL != pll_elem->blink)


*/
#define pll_empty(priolist)    (NULL == priolist->first)
#define pll_size(priolist)     (priolist->size)
#define pll_first(priolist)    (priolist->first)
#define pll_last(priolist)     (priolist->last)
#define pll_next(pll_elem)     (pll_elem = pll_elem->flink)
#define pll_get_next(pll_elem) (pll_elem->flink)
#define pll_has_next(pll_elem) (NULL != pll_elem->flink)
#define pll_previous(pll_elem) (pll_elem = pll_elem->blink)
#define pll_get_previous(pll_elem) (pll_elem->blink)
#define pll_has_previous(pll_elem) (NULL != pll_elem->blink)

//
// PLL (priority single linked list) prototype generator
//
#define NP_PLL_GENERATE_PROTOTYPES(TYPE)\
	typedef int8_t (*TYPE##_pll_cmp_func_t) (TYPE const value_1, TYPE const value_2 ); \
	int8_t TYPE##_pll_compare_type(TYPE const a, TYPE const b);                        \
	typedef struct TYPE##_pll_s TYPE##_pll_t;                                          \
	typedef struct TYPE##_pll_node_s TYPE##_pll_node_t;                                \
	struct TYPE##_pll_s                                                                \
	{                                                                                  \
		uint32_t size;\
		TYPE##_pll_node_t *first;\
		TYPE##_pll_node_t *last;\
	};\
	struct TYPE##_pll_node_s\
	{\
		TYPE##_pll_node_t *flink;\
		TYPE##_pll_node_t *blink;\
		TYPE val;\
	};\
	TYPE##_pll_t* TYPE##_pll_init(); 																			\
	np_bool TYPE##_pll_insert(TYPE##_pll_t* pll_list, TYPE value, np_bool dups_ok, TYPE##_pll_cmp_func_t cmp_func);	\
	void TYPE##_pll_remove(TYPE##_pll_t* pll_list, TYPE value, TYPE##_pll_cmp_func_t cmp_func);						\
	TYPE TYPE##_pll_replace(TYPE##_pll_t* list, TYPE value, TYPE##_pll_cmp_func_t cmp_func);   						\
	TYPE TYPE##_pll_find(TYPE##_pll_t* list, TYPE value, TYPE##_pll_cmp_func_t cmp_func);   						\
	TYPE TYPE##_pll_head(TYPE##_pll_t* list);                  													\
	TYPE TYPE##_pll_tail(TYPE##_pll_t* list);                  													\
	void TYPE##_pll_free(TYPE##_pll_t* list);                  													\
	void TYPE##_pll_clear(TYPE##_pll_t* list);                 													\


//
// PLL (priority single linked list) implementation generator
//
#define NP_PLL_GENERATE_IMPLEMENTATION(TYPE)                     \
int8_t TYPE##_pll_compare_type(TYPE const a, TYPE const b) {     \
	return (a == b) ? 0 : -1;                                      \
}                                                                \
TYPE##_pll_t* TYPE##_pll_init()                                  \
{ \
	TYPE##_pll_t* pll_list = (TYPE##_pll_t*) calloc(1,sizeof(TYPE##_pll_t)); \
	pll_list->size = 0; \
	pll_list->first = NULL; \
	pll_list->last = NULL; \
	return (pll_list); \
} \
np_bool TYPE##_pll_insert(TYPE##_pll_t* pll_list, TYPE value, np_bool dups_ok, TYPE##_pll_cmp_func_t cmp_func) 	\
{ 																											\
	TYPE##_pll_node_t* new_pll_node = (TYPE##_pll_node_t*) calloc(1,sizeof(TYPE##_pll_node_t)); 				\
	new_pll_node->val = value; 																				\
	new_pll_node->flink = NULL; 																			\
	new_pll_node->blink = NULL; 																			\
	if (pll_list->first == NULL) { 																			\
		pll_list->first = new_pll_node; 																	\
		pll_list->last = new_pll_node; 																		\
		pll_list->size++; 																					\
		return (TRUE); 																						\
	} 																										\
	TYPE##_pll_node_t* pll_current = pll_list->first; 														\
	while (NULL != pll_current) { 																			\
		int8_t cmp_res = cmp_func(pll_current->val, new_pll_node->val); 									\
		if (cmp_res < 0) { 																					\
			new_pll_node->flink = pll_current; 																\
			if (NULL != pll_current->blink) pll_current->blink->flink = new_pll_node; 						\
			new_pll_node->blink = pll_current->blink; 														\
			pll_current->blink = new_pll_node; 																\
			if (pll_current == pll_list->first) pll_list->first = new_pll_node; 							\
			break; 																							\
		} else if ((cmp_res == 0) && dups_ok == FALSE) { 													\
			free(new_pll_node); 																			\
			new_pll_node = NULL; 																			\
			return FALSE; 																					\
		}																									\
		if (pll_current == pll_list->last) { 																\
			pll_current->flink = new_pll_node; 																\
			new_pll_node->blink = pll_current; 																\
			pll_list->last = new_pll_node; 																	\
			break; 																							\
		} 																									\
		pll_current = pll_current->flink; 																	\
	} 																										\
	pll_list->size++; 																						\
	return (TRUE); 																							\
} 																											\
void TYPE##_pll_remove(TYPE##_pll_t* pll_list, TYPE value, TYPE##_pll_cmp_func_t cmp_func) {                \
	TYPE##_pll_node_t* pll_current = pll_list->first;                                                       \
	while (NULL != pll_current) {																			\
		int8_t cmp_res = cmp_func(pll_current->val, value);													\
		if (0 == cmp_res) {																					\
			if (NULL != pll_current->flink) pll_current->flink->blink = pll_current->blink;					\
			if (NULL != pll_current->blink) pll_current->blink->flink = pll_current->flink;					\
			if (pll_list->first == pll_current) pll_list->first = pll_current->flink;						\
			if (pll_list->last == pll_current) pll_list->last = pll_current->blink;							\
			free(pll_current);																				\
			pll_current = NULL;																				\
			pll_list->size--;																				\
			break;																							\
		} else {																							\
			pll_current = pll_current->flink;																\
		}																									\
	}																										\
}																											\
TYPE TYPE##_pll_replace(TYPE##_pll_t* pll_list, TYPE value, TYPE##_pll_cmp_func_t cmp_func) {               \
	TYPE ret_val = 0;                                                 \
	TYPE##_pll_node_t* pll_current = pll_list->first;                 \
	while (NULL != pll_current) {                                     \
		int8_t cmp_res = cmp_func(pll_current->val, value);           \
		if (0 == cmp_res) {                                           \
			TYPE old_val = pll_current->val;                          \
			pll_current->val = value;                                 \
			return (old_val);                                         \
		}                                                             \
		pll_next(pll_current);                                        \
	}                                                                 \
	return (ret_val);                                                 \
}                                                                     \
TYPE TYPE##_pll_find(TYPE##_pll_t* pll_list, TYPE value, TYPE##_pll_cmp_func_t cmp_func) { \
	TYPE ret_val = 0;                                                 \
	TYPE##_pll_node_t* pll_current = pll_list->first;                 \
	while (NULL != pll_current) {                                     \
		int8_t cmp_res = cmp_func(pll_current->val, value);           \
		if (0 == cmp_res) {                                           \
			return (pll_current->val);                                \
		}                                                             \
		pll_next(pll_current);                                        \
	}                                                                 \
	return (ret_val);                                                 \
}                                                                     \
TYPE TYPE##_pll_head(TYPE##_pll_t* pll_list) {                        \
	TYPE ret_val = 0;                                                 \
	if (NULL != pll_list->first) {                                    \
		TYPE##_pll_node_t* tmp = pll_list->first;                     \
		ret_val = tmp->val;                                           \
		pll_list->first = pll_list->first->flink;                     \
		if (NULL != pll_list->first) pll_list->first->blink = NULL;   \
		if (NULL == pll_list->first) pll_list->last = NULL;           \
		free(tmp);                                                    \
		tmp = NULL;                                                   \
		pll_list->size--;                                             \
	}                                                                 \
	return (ret_val);                                                 \
}                                                                     \
TYPE TYPE##_pll_tail(TYPE##_pll_t* pll_list) {                        \
	TYPE ret_val = 0;                                                 \
	if (NULL != pll_list->last) {                                     \
		TYPE##_pll_node_t* tmp = pll_list->last;                      \
		ret_val = tmp->val;                                           \
		pll_list->last = pll_list->last->blink;                       \
		if (NULL != pll_list->last) pll_list->last->flink = NULL;     \
		if (NULL == pll_list->last) pll_list->first = NULL;           \
		free(tmp);                                                    \
		tmp = NULL;                                                   \
		pll_list->size--;                                             \
	}                                                                 \
	return (ret_val);                                                 \
}                                                                     \
void TYPE##_pll_free(TYPE##_pll_t* pll_list) {                        \
	TYPE##_pll_clear(pll_list);                                       \
	free(pll_list);                                                   \
	pll_list = NULL;                                                  \
}                                                                     \
void TYPE##_pll_clear(TYPE##_pll_t* pll_list) {                       \
	TYPE##_pll_node_t *tmp;                                           \
	while (NULL != pll_list->first) {                                 \
		tmp = pll_list->first;                                        \
		pll_list->first = pll_list->first->flink;                     \
		free(tmp);                                                    \
		tmp = NULL;                                                   \
	}                                                                 \
	pll_list->first = NULL;                                           \
	pll_list->last = NULL;                                            \
	pll_list->size = 0;                                               \
}                                                                     \


/**

double linked list macros (DLL)

function like macros are:

*.. c:macro:: np_dll_t(TYPE, NAME)
*             void dll_init(TYPE, list)
*             void dll_append(TYPE, list, value)
*             void dll_prepend(TYPE, list, value)
*             TYPE dll_head(TYPE, list)
*             TYPE dll_tail(TYPE, list)
*             void dll_free(TYPE, list)
*             void dll_clear(TYPE, list)

*/

#define np_dll_t(TYPE, NAME) TYPE##_dll_t* NAME

// convenience wrapper definitions
#define dll_init(TYPE, dll_list) dll_list = TYPE##_dll_init();
#define dll_append(TYPE, dll_list, value) TYPE##_dll_append(dll_list, value);
#define dll_prepend(TYPE, dll_list, value) TYPE##_dll_prepend(dll_list, value);
#define	dll_head(TYPE, dll_list) TYPE##_dll_head(dll_list);
#define dll_tail(TYPE, dll_list) TYPE##_dll_tail(dll_list);
#define dll_free(TYPE, dll_list) { TYPE##_dll_free(dll_list); dll_list = NULL; }
#define dll_clear(TYPE, dll_list) TYPE##_dll_free(dll_list);

/**
return type definition macros are

*.. c:macro:: dll_return(TYPE) TYPE##_dll_t*
*             dll_iterator(TYPE) TYPE##_dll_node_t*


*/
// return type definition
#define dll_return(TYPE) TYPE##_dll_t*
#define dll_iterator(TYPE) TYPE##_dll_node_t*

// general purpose definitions
/**
real macros for convenience usage

*.. c:macro::  dll_empty(list)             (NULL == list->first)
*              dll_size(list)              (list->size)
*              dll_first(list)             (list->first)
*              dll_last(list)              (list->last)
*              dll_next(list_elem)         (pll_elem = list_elem->flink)
*              dll_get_next(list_elem)     (list_elem->flink)
*              dll_previous(list_elem)     (list_elem = list_elem->blink)
*              dll_get_previous(list_elem) (list_elem->blink)


*/
// #define dll_traverse(dll_list, iter_item, elem)  for (iter_item = dll_list->first, elem = iter_item->val; iter_item != NULL; iter_item = iter_item->flink, elem = iter_item->val)
// #define dll_rtraverse(dll_list, iter_item, elem) for (iter_item = dll_list->last,  elem = iter_item->val; iter_item != NULL; iter_item = iter_item->blink, elem = iter_item->val)
#define dll_empty(dll_list)    (NULL == dll_list->first)
#define dll_size(dll_list)     (dll_list->size)
#define dll_first(dll_list)    (dll_list->first)
#define dll_last(dll_list)     (dll_list->last)
#define dll_next(dll_elem)     (dll_elem = dll_elem->flink)
#define dll_get_next(sll_elem) (dll_elem->flink)
#define dll_previous(dll_elem) (dll_elem = dll_elem->blink)
#define dll_get_previous(sll_elem) (dll_elem->blink)

//
// DLL (double linked list) prototype generator
//
#define NP_DLL_GENERATE_PROTOTYPES(TYPE)\
	typedef struct TYPE##_dll_s TYPE##_dll_t;\
	typedef struct TYPE##_dll_node_s TYPE##_dll_node_t;\
	struct TYPE##_dll_s\
	{\
		uint32_t size;\
		TYPE##_dll_node_t *first;\
		TYPE##_dll_node_t *last;\
	};\
	struct TYPE##_dll_node_s\
	{\
		TYPE##_dll_node_t *flink;\
		TYPE##_dll_node_t *blink;\
		TYPE val;\
	};\
	TYPE##_dll_t* TYPE##_dll_init();\
	void TYPE##_dll_append(TYPE##_dll_t* dll_list, TYPE value);\
	void TYPE##_dll_prepend(TYPE##_dll_t* dll_list, TYPE value);\
	TYPE TYPE##_dll_head(TYPE##_dll_t* list);\
	TYPE TYPE##_dll_tail(TYPE##_dll_t* list);\
	void TYPE##_dll_free(TYPE##_dll_t* list);\
	void TYPE##_dll_clear(TYPE##_dll_t* list);\


//
// DLL (double linked list) implementation generator
//
#define NP_DLL_GENERATE_IMPLEMENTATION(TYPE)\
TYPE##_dll_t* TYPE##_dll_init() {\
	TYPE##_dll_t* dll_list = (TYPE##_dll_t*) calloc(1,sizeof(TYPE##_dll_t));\
	dll_list->size = 0;\
	dll_list->first = NULL;\
	dll_list->last = NULL;\
	return (dll_list);\
}\
void TYPE##_dll_append(TYPE##_dll_t* dll_list, TYPE value) {\
	TYPE##_dll_node_t* dll_node = (TYPE##_dll_node_t*) calloc(1,sizeof(TYPE##_dll_node_t));\
	dll_node->val = value;\
	dll_node->flink = NULL;\
	dll_node->blink = NULL;\
	if (NULL != dll_list->last) {\
		dll_list->last->flink = dll_node;\
		dll_node->blink = dll_list->last;\
		dll_list->last = dll_node;\
	} else {\
		dll_list->first = dll_node; \
		dll_list->last = dll_node;  \
	}\
	dll_list->size++;\
}\
void TYPE##_dll_prepend(TYPE##_dll_t* dll_list, TYPE value) {\
	TYPE##_dll_node_t* dll_node = (TYPE##_dll_node_t*) calloc(1,sizeof(TYPE##_dll_node_t));\
	dll_node->val = value;  \
	dll_node->flink = NULL; \
	dll_node->blink = NULL; \
	if (NULL != dll_list->first) { \
		dll_list->first->blink = dll_node; \
		dll_node->flink = dll_list->first; \
		dll_list->first = dll_node; \
	} else {\
		dll_list->first = dll_node; \
		dll_list->last = dll_node;  \
	}\
	dll_list->size++;\
}\
TYPE TYPE##_dll_head(TYPE##_dll_t* dll_list) {\
	TYPE* ret_val = 0;\
	if (NULL != dll_list->first) {\
		TYPE##_dll_node_t* tmp = dll_list->first;\
		ret_val = tmp->val;\
		dll_list->first = dll_list->first->flink;\
		if (NULL != dll_list->first) dll_list->first->blink = NULL;\
		if (NULL == dll_list->first) dll_list->last = NULL;\
		free(tmp);\
		dll_list->size--;\
	}\
	return (ret_val);\
}\
TYPE TYPE##_dll_tail(TYPE##_dll_t* dll_list) {\
	TYPE ret_val = 0;\
	if (NULL != dll_list->last) {\
		TYPE##_dll_node_t* tmp = dll_list->last;\
		ret_val = tmp->val;\
		dll_list->last = dll_list->last->blink;\
		if (NULL != dll_list->last) dll_list->last->flink = NULL;\
		if (NULL == dll_list->last) dll_list->first = NULL;\
		free(tmp);\
		dll_list->size--;\
	}\
	return (ret_val);\
}\
void TYPE##_dll_free(TYPE##_dll_t* dll_list) {\
	TYPE##_dll_node_t *tmp;\
	while (dll_list->first != NULL) {\
		tmp = dll_list->first;\
		dll_list->first = dll_list->first->flink;\
		free(tmp);\
	}\
	free(dll_list);\
}\
void TYPE##_dll_clear(TYPE##_dll_t* dll_list) {\
	TYPE##_dll_node_t *tmp;\
	while (dll_list->first != NULL) {\
		tmp = dll_list->first;\
		dll_list->first = dll_list->first->flink;\
		free(tmp);\
	}\
	dll_list->first = NULL; \
	dll_list->last = NULL;  \
	dll_list->size = 0;     \
}\


/**

single linked list macros (SLL)

function like macros are:

*.. c:macro:: np_sll_t(TYPE, NAME)
*             void sll_init(TYPE, list)
*             void sll_append(TYPE, list, value)
*             void sll_prepend(TYPE, list, value)
*			 TYPE sll_head(TYPE, list)
*			 TYPE sll_tail(TYPE, list)
*             void sll_free(TYPE, list)
*             void sll_clear(TYPE, list)
*             TYPE sll_delete(TYPE, list, iter)

*/
// definition
#define np_sll_t(TYPE, NAME) TYPE##_sll_t* NAME

// convenience wrapper definitions
#define sll_init(TYPE, sll_list) sll_list = TYPE##_sll_init();
#define sll_append(TYPE, sll_list, value) TYPE##_sll_append(sll_list, value);
#define sll_prepend(TYPE, sll_list, value) TYPE##_sll_prepend(sll_list, value);
#define	sll_head(TYPE, sll_list) TYPE##_sll_head(sll_list)
#define sll_tail(TYPE, sll_list) TYPE##_sll_tail(sll_list)
#define sll_free(TYPE, sll_list) { TYPE##_sll_free(sll_list); sll_list = NULL; }
#define sll_clear(TYPE, sll_list) TYPE##_sll_clear(sll_list)
#define sll_delete(TYPE, sll_list, iter) TYPE##_sll_delete(sll_list, iter)
#define sll_remove(TYPE, sll_list, value, fn_cmp) TYPE##_sll_remove(sll_list, value, fn_cmp)
#define sll_find(TYPE, sll_list, value, fn_cmp, default_return) TYPE##_sll_find(sll_list, value, fn_cmp, default_return)
#define sll_contains(TYPE, sll_list, value, fn_cmp) TYPE##_sll_contains(sll_list, value, fn_cmp)
#define sll_merge(TYPE, sll_list_a, sll_list_b, fn_cmp) TYPE##_sll_merge(sll_list_a,sll_list_b, fn_cmp)
#define sll_clone(TYPE, sll_list_source, sll_list_target)										\
	np_sll_t(TYPE, sll_list_target);															\
	sll_init(TYPE, sll_list_target);															\
	TYPE##_sll_clone(sll_list_source, sll_list_target);											\

/**
return type definition macros are

*.. c:macro:: sll_return(TYPE) TYPE##_sll_t*
*             sll_iterator(TYPE) TYPE##_sll_node_t*


*/
// return type definition
#define sll_return(TYPE) TYPE##_sll_t*
#define sll_iterator(TYPE) TYPE##_sll_node_t*

/**
real macros for convenience usage

*.. c:macro::  sll_empty(list)             (NULL == list->first)
*              sll_size(list)              (list->size)
*              sll_first(list)             (list->first)
*              sll_last(list)              (list->last)
*              sll_next(list_elem)         (sll_elem = list_elem->flink)
*              sll_get_next(list_elem)     (list_elem->flink)

*/
// general purpose definitions
// #define sll_traverse(sll_list, iter_item, elem) for (iter_item = sll_list->first, elem = iter_item->val; iter_item != NULL; iter_item = iter_item->flink, elem = iter_item->val)
// #define sll_rtraverse(sll_list, iter_item, elem) for (iter_item = sll_list->last,  elem = iter_item->val; iter_item != NULL; iter_item = iter_item->blink, elem = iter_item->val)
#define sll_empty(sll_list) (NULL == (sll_list)->first)
#define sll_size(sll_list) ((sll_list)->size)
#define sll_first(sll_list) ((sll_list)->first)
#define sll_last(sll_list) ((sll_list)->last)
#define sll_next(sll_elem) ((sll_elem) = sll_next_select(sll_elem))
#define sll_next_select(sll_elem) ((((sll_elem) == NULL || (sll_elem)->flink == (sll_elem)) ? NULL : (sll_elem)->flink))
#define sll_get_next(sll_elem) ((sll_elem)->flink)
// #define sll_previous(sll_elem) (sll_elem->blink)

//
// SLL (single linked list) prototype generator
//																  
#define NP_SLL_GENERATE_PROTOTYPES(TYPE)                          											\
	typedef int8_t (*TYPE##_sll_cmp_func_t) (TYPE const value_1, TYPE const value_2 );                      \
	int8_t TYPE##_sll_compare_type(TYPE const a, TYPE const b);                                             \
	typedef struct TYPE##_sll_s TYPE##_sll_t;                     											\
	typedef struct TYPE##_sll_node_s TYPE##_sll_node_t;           											\
	struct TYPE##_sll_s                                           											\
	{                                                             											\
		uint32_t size;                                            											\
		TYPE##_sll_node_t *first;                                 											\
		TYPE##_sll_node_t *last;                                  											\
	};                                                            											\
	struct TYPE##_sll_node_s                                      											\
	{                                                             											\
		TYPE##_sll_node_t *flink;                                 											\
		TYPE val;                                                											\
	};                                                            											\
	TYPE##_sll_t* TYPE##_sll_init();                              											\
	void TYPE##_sll_append(TYPE##_sll_t* sll_list, TYPE value);  											\
	void TYPE##_sll_prepend(TYPE##_sll_t* sll_list, TYPE value); 											\
	TYPE TYPE##_sll_head(TYPE##_sll_t* list);                    											\
	TYPE TYPE##_sll_tail(TYPE##_sll_t* list);                    											\
	void TYPE##_sll_free(TYPE##_sll_t* list);                     											\
	void TYPE##_sll_clear(TYPE##_sll_t* list);                    											\
	void TYPE##_sll_delete(TYPE##_sll_t* list, TYPE##_sll_node_t* tbr);										\
	void TYPE##_sll_clone(TYPE##_sll_t* sll_list_source, TYPE##_sll_t* sll_list_target);					\
	TYPE TYPE##_sll_find(TYPE##_sll_t* sll_list, TYPE value, TYPE##_sll_cmp_func_t fn_cmp, TYPE default_return); \
	np_bool TYPE##_sll_contains(TYPE##_sll_t* sll_list, TYPE value, TYPE##_sll_cmp_func_t fn_cmp);	    	\
	TYPE##_sll_t* TYPE##_sll_merge(TYPE##_sll_t* sll_list_a, TYPE##_sll_t* sll_list_b, TYPE##_sll_cmp_func_t  fn_cmp);	\
	void TYPE##_sll_remove(TYPE##_sll_t* sll_list, TYPE value, TYPE##_sll_cmp_func_t fn_cmp);							\
																											\
																											
//
// SLL (single linked list) implementation generator
//
#define NP_SLL_GENERATE_IMPLEMENTATION(TYPE)																\
int8_t TYPE##_sll_compare_type(TYPE const a, TYPE const b) {                                                \
	return a == b ? 0 : -1;                                                                                 \
}                                                                                                           \
TYPE##_sll_t* TYPE##_sll_merge(TYPE##_sll_t* sll_list_a, TYPE##_sll_t* sll_list_b, TYPE##_sll_cmp_func_t  fn_cmp) {		\
	np_sll_t(TYPE,ret);																					    \
	sll_init(TYPE,ret);																					    \
	sll_iterator(TYPE) iter_b = sll_first(sll_list_b);													    \
	while (iter_b != NULL)																				    \
	{																									    \
		if (sll_contains(TYPE, ret, iter_b->val, fn_cmp) == FALSE) {									    \
			sll_append(TYPE, ret, iter_b->val);															    \
		}																								    \
		sll_next(iter_b);																				    \
	}																									    \
	sll_iterator(TYPE) iter_a = sll_first(sll_list_a);													    \
	while (iter_a != NULL)																				    \
	{																									    \
		if (sll_contains(TYPE, ret, iter_a->val, fn_cmp) == FALSE) {									    \
			sll_append(TYPE, ret, iter_a->val);															    \
		}																								    \
		sll_next(iter_a);																				    \
	}																									    \
	return ret;																							    \
}																										    \
																										    \
TYPE TYPE##_sll_find(TYPE##_sll_t* sll_list, TYPE value, TYPE##_sll_cmp_func_t fn_cmp, TYPE default_return) {	\
	TYPE ret = default_return;																				\
	sll_iterator(TYPE) iter = sll_first(sll_list);															\
	while (iter != NULL)																					\
	{																										\
		if (fn_cmp(iter->val, value) == 0) {																\
			ret = iter->val;																				\
			break;																							\
		}																									\
		sll_next(iter);																						\
	}																										\
	return (ret);																							\
}																											\
np_bool TYPE##_sll_contains(TYPE##_sll_t* sll_list, TYPE value, TYPE##_sll_cmp_func_t fn_cmp) {				\
	np_bool ret = FALSE;																					\
	sll_iterator(TYPE) iter = sll_first(sll_list);															\
	while (iter != NULL)																					\
	{																										\
		if (fn_cmp(iter->val, value) == 0) {																\
			ret = TRUE;																						\
			break;																							\
		}																									\
		sll_next(iter);																						\
	}																										\
	return (ret);																							\
}																											\
void TYPE##_sll_remove(TYPE##_sll_t* sll_list, TYPE value, TYPE##_sll_cmp_func_t fn_cmp) {					\
	sll_iterator(TYPE) iter = sll_first(sll_list);															\
	while (iter != NULL)																					\
	{																										\
		if (fn_cmp(iter->val, value) == 0) {																\
			sll_delete(TYPE, sll_list, iter);																\
			break;																							\
		}																									\
		sll_next(iter);																						\
	}																										\
}																											\
void TYPE##_sll_clone(TYPE##_sll_t* sll_list_source, TYPE##_sll_t* sll_list_target) {						\
	sll_iterator(TYPE) iter = sll_first(sll_list_source);													\
	while (iter != NULL)																					\
	{																										\
		sll_append(TYPE, sll_list_target, iter->val)														\
		sll_next(iter);																						\
	}																										\
}																											\
TYPE##_sll_t* TYPE##_sll_init() {																			\
	TYPE##_sll_t* sll_list = (TYPE##_sll_t*) calloc(1,sizeof(TYPE##_sll_t));								\
	sll_list->size = 0;																						\
	sll_list->first = NULL;																					\
	sll_list->last = NULL;																					\
	return (sll_list);																						\
}																											\
void TYPE##_sll_append(TYPE##_sll_t* sll_list, TYPE value) {												\
	TYPE##_sll_node_t* sll_node = (TYPE##_sll_node_t*) calloc(1,sizeof(TYPE##_sll_node_t));					\
	CHECK_MALLOC(sll_node);																					\
	sll_node->val = value;																					\
	sll_node->flink = NULL;																					\
	if (sll_list->first == NULL) { 																			\
		sll_list->first = sll_node; 																		\
	} else {																								\
		sll_list->last->flink = sll_node;																	\
	}																										\
	sll_list->last = sll_node;																				\
	sll_list->size++;																						\
}																											\
void TYPE##_sll_prepend(TYPE##_sll_t* sll_list, TYPE value) {												\
	TYPE##_sll_node_t* sll_node = (TYPE##_sll_node_t*) calloc(1,sizeof(TYPE##_sll_node_t));					\
	sll_node->val = value;																					\
	sll_node->flink = sll_list->first;																		\
	if (sll_list->last == NULL) { sll_list->last = sll_node; }												\
	sll_list->first = sll_node;																				\
	sll_list->size++;																						\
}																											\
TYPE TYPE##_sll_head(TYPE##_sll_t* sll_list) {																\
	TYPE ret_val = 0;																						\
	if (NULL != sll_list->first) {																			\
		TYPE##_sll_node_t* tmp = sll_list->first;															\
		ret_val = tmp->val;																					\
		TYPE##_sll_delete(sll_list, tmp);																	\
	}																										\
	return (ret_val);																						\
}																											\
TYPE TYPE##_sll_tail(TYPE##_sll_t* sll_list) {																\
	TYPE ret_val = 0;																						\
	if (NULL != sll_list->last) {																			\
		TYPE##_sll_node_t* tmp = sll_list->last;															\
		ret_val = tmp->val;																					\
		TYPE##_sll_delete(sll_list, tmp);																	\
	}																										\
	return (ret_val);																						\
}																											\
void TYPE##_sll_free(TYPE##_sll_t* sll_list) {																\
	TYPE##_sll_clear(sll_list);																				\
	free(sll_list);																							\
	sll_list = NULL;																						\
}																											\
void TYPE##_sll_clear(TYPE##_sll_t* sll_list) {																\
	TYPE##_sll_node_t *tmp;																					\
	while (sll_list->first != NULL) {																		\
		tmp = sll_list->first;																				\
		sll_list->first = sll_list->first->flink;															\
		free(tmp);																							\
	}																										\
	sll_list->size = 0;																						\
}																											\
void TYPE##_sll_delete(TYPE##_sll_t* sll_list, TYPE##_sll_node_t *tbr) { 									\
	if (sll_list->first == tbr) {																			\
		if (sll_list->last == tbr) {																		\
			sll_list->first = NULL;																			\
			sll_list->last  = NULL;																			\
			sll_list->size = 0;																				\
		}else{																								\
			sll_list->first = tbr->flink;																	\
			sll_list->size--;																				\
		}																									\
		free(tbr);																							\
		tbr = NULL;																							\
	} else {																								\
		TYPE##_sll_node_t *tmp = sll_list->first;															\
		TYPE##_sll_node_t *mem = sll_list->first;															\
		while (tmp != NULL) {																				\
			tmp = tmp->flink;																				\
			if (tmp == tbr) {																				\
				if (sll_list->last == tbr) {																\
					sll_list->last = mem;																	\
					mem->flink = NULL;																		\
				}else{ 																						\
					mem->flink = tmp->flink;																\
				}																							\
				free(tmp);																					\
				tbr = NULL;																					\
				sll_list->size--;																			\
				break;	/*while*/																			\
			} 																								\
			mem = mem->flink;																				\
		}																									\
	}																										\
}

#ifdef __cplusplus
}
#endif

#endif // _NP_LIST_H_