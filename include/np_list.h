/**
 *  copyright 2015 pi-lar GmbH
 *  header only implementation to easily store datatypes in double or single linked lists
 *  taking the generating approach using the c preprocessor
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_LIST_H_
#define _NP_LIST_H_

/** double linked list header only implementation for neuropil
 **/
// definition
#define np_dll_t(TYPE, NAME) TYPE##_dll_t* NAME

// convenience wrapper definitions
#define dll_init(TYPE, dll_list) dll_list = TYPE##_dll_init();
#define dll_append(TYPE, dll_list, value) TYPE##_dll_append(dll_list, value);
#define dll_prepend(TYPE, dll_list, value) TYPE##_dll_prepend(dll_list, value);
#define	dll_head(TYPE, dll_list) TYPE##_dll_head(dll_list);
#define dll_tail(TYPE, dll_list) TYPE##_dll_tail(dll_list);
#define dll_free(TYPE, dll_list) TYPE##_dll_free(dll_list);
#define dll_clear(TYPE, dll_list) TYPE##_dll_free(dll_list);

// return type definition
#define dll_return(TYPE) TYPE##_dll_t*
#define dll_iterator(TYPE) TYPE##_dll_node_t*

// general purpose definitions
#define dll_traverse(dll_list, iter_item, elem)  for (iter_item = dll_list->first, elem = iter_item->val; iter_item != NULL; iter_item = iter_item->flink, elem = iter_item->val)
#define dll_rtraverse(dll_list, iter_item, elem) for (iter_item = dll_list->last,  elem = iter_item->val; iter_item != NULL; iter_item = iter_item->blink, elem = iter_item->val)
#define dll_empty(dll_list)    (NULL == dll_list->first)
#define dll_size(dll_list)     (dll_list->size)
#define dll_first(dll_list)    (dll_list->first)
#define dll_last(dll_list)     (dll_list->last)
#define dll_next(dll_elem)     (dll_elem->flink)
#define dll_previous(dll_elem) (dll_elem->blink)

/** DLL (double linked list) prototype generator
 **/
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
        TYPE* val;\
    };\
    TYPE##_dll_t* TYPE##_dll_init();\
    void TYPE##_dll_append(TYPE##_dll_t* dll_list, TYPE* value);\
    void TYPE##_dll_prepend(TYPE##_dll_t* dll_list, TYPE* value);\
	TYPE* TYPE##_dll_head(TYPE##_dll_t* list);\
    TYPE* TYPE##_dll_tail(TYPE##_dll_t* list);\
    void TYPE##_dll_free(TYPE##_dll_t* list);\
    void TYPE##_dll_clear(TYPE##_dll_t* list);

/** DLL (double linked list) implementation generator
 **/
#define NP_DLL_GENERATE_IMPLEMENTATION(TYPE)\
TYPE##_dll_t* TYPE##_dll_init() {\
	TYPE##_dll_t* dll_list = (TYPE##_dll_t*) malloc(sizeof(TYPE##_dll_t));\
	dll_list->size = 0;\
	dll_list->first = NULL;\
	dll_list->last = NULL;\
	return dll_list;\
}\
void TYPE##_dll_append(TYPE##_dll_t* dll_list, TYPE* value) {\
	TYPE##_dll_node_t* dll_node = (TYPE##_dll_node_t*) malloc(sizeof(TYPE##_dll_node_t));\
	dll_node->val = value;\
	dll_node->flink = NULL;\
	dll_node->blink = NULL;\
	if (NULL != dll_list->last) {\
		dll_node->blink = dll_list->last;\
		dll_list->last->flink = dll_node;\
		dll_list->last = dll_node;\
	} else {\
		dll_list->first = dll_node; dll_list->last = dll_node;\
	}\
	dll_list->size++;\
}\
void TYPE##_dll_prepend(TYPE##_dll_t* dll_list, TYPE* value) {\
	TYPE##_dll_node_t* dll_node = (TYPE##_dll_node_t*) malloc(sizeof(TYPE##_dll_node_t));\
	dll_node->val = value;\
	dll_node->flink = NULL;\
	dll_node->blink = NULL;\
	if (NULL != dll_list->first) {\
		dll_node->flink = dll_list->first;\
		dll_list->first->blink = dll_node;\
		dll_list->first = dll_node;\
	} else {\
		dll_list->first = dll_node; dll_list->last = dll_node;\
	}\
	dll_list->size++;\
}\
TYPE* TYPE##_dll_head(TYPE##_dll_t* dll_list) {\
	TYPE* ret_val = NULL;\
	if (NULL != dll_list->first) {\
		TYPE##_dll_node_t* tmp = dll_list->first;\
		ret_val = tmp->val;\
		dll_list->first = dll_list->first->flink;\
		if (dll_list->first != NULL) dll_list->first->blink = NULL;\
		if (dll_list->first == NULL) dll_list->last = NULL;\
		free(tmp);\
		dll_list->size--;\
	}\
	return ret_val;\
}\
TYPE* TYPE##_dll_tail(TYPE##_dll_t* dll_list) {\
	TYPE* ret_val = NULL;\
	if (NULL != dll_list->last) {\
		TYPE##_dll_node_t* tmp = dll_list->last;\
		ret_val = tmp->val;\
		dll_list->last = dll_list->last->blink;\
		if (dll_list->last != NULL) dll_list->last->flink = NULL;\
		if (dll_list->last == NULL) dll_list->first = NULL;\
		free(tmp);\
		dll_list->size--;\
	}\
	return ret_val;\
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
}

/** single linked list header only implementation for neuropil
 **/
// definition
#define np_sll_t(TYPE, NAME) TYPE##_sll_t* NAME

// convenience wrapper definitions
#define sll_init(TYPE, sll_list) sll_list = TYPE##_sll_init();
#define sll_append(TYPE, sll_list, value) TYPE##_sll_append(sll_list, value);
#define sll_prepend(TYPE, sll_list, value) TYPE##_sll_prepend(sll_list, value);
#define	sll_head(TYPE, sll_list) TYPE##_sll_head(sll_list)
#define sll_tail(TYPE, sll_list) TYPE##_sll_tail(sll_list)
#define sll_free(TYPE, sll_list) TYPE##_sll_free(sll_list)
#define sll_clear(TYPE, sll_list) TYPE##_sll_clear(sll_list)
#define sll_delete(TYPE, sll_list, iter) TYPE##_sll_delete(sll_list, iter)

// return type definition
#define sll_return(TYPE) TYPE##_sll_t*
#define sll_iterator(TYPE) TYPE##_sll_node_t*

// general purpose definitions
#define sll_traverse(sll_list, iter_item, elem) for (iter_item = sll_list->first, elem = iter_item->val; iter_item != NULL; iter_item = iter_item->flink, elem = iter_item->val)
// #define sll_rtraverse(sll_list, iter_item, elem) for (iter_item = sll_list->last,  elem = iter_item->val; iter_item != NULL; iter_item = iter_item->blink, elem = iter_item->val)
#define sll_empty(sll_list) (NULL == sll_list->first)
#define sll_size(sll_list) sll_list->size
#define sll_first(sll_list) (sll_list->first)
#define sll_last(sll_list) (sll_list->last)
#define sll_next(sll_elem) (sll_elem->flink)
// #define sll_previous(sll_elem) (sll_elem->blink)

/** SLL (single linked list) prototype generator
 **/
#define NP_SLL_GENERATE_PROTOTYPES(TYPE)\
	typedef struct TYPE##_sll_s TYPE##_sll_t;\
	typedef struct TYPE##_sll_node_s TYPE##_sll_node_t;\
	struct TYPE##_sll_s\
	{\
		uint32_t size;\
		TYPE##_sll_node_t *first;\
		TYPE##_sll_node_t *last;\
	};\
	struct TYPE##_sll_node_s\
	{\
		TYPE##_sll_node_t *flink;\
    	TYPE* val;\
	};\
	TYPE##_sll_t* TYPE##_sll_init();\
    void TYPE##_sll_append(TYPE##_sll_t* sll_list, TYPE* value);\
    void TYPE##_sll_prepend(TYPE##_sll_t* sll_list, TYPE* value);\
	TYPE* TYPE##_sll_head(TYPE##_sll_t* list);\
    TYPE* TYPE##_sll_tail(TYPE##_sll_t* list);\
    void TYPE##_sll_free(TYPE##_sll_t* list);\
    void TYPE##_sll_clear(TYPE##_sll_t* list);\
    void TYPE##_sll_delete(TYPE##_sll_t* list, TYPE##_sll_node_t* tbr);

/** SLL (single linked list) implementation generator
 **/
#define NP_SLL_GENERATE_IMPLEMENTATION(TYPE)\
TYPE##_sll_t* TYPE##_sll_init() {\
	TYPE##_sll_t* sll_list = (TYPE##_sll_t*) malloc(sizeof(TYPE##_sll_t));\
	sll_list->size = 0;\
	sll_list->first = NULL;\
	sll_list->last = NULL;\
	return sll_list;\
}\
void TYPE##_sll_append(TYPE##_sll_t* sll_list, TYPE* value) {\
	TYPE##_sll_node_t* sll_node = (TYPE##_sll_node_t*) malloc(sizeof(TYPE##_sll_node_t));\
	sll_node->val = value;\
	sll_node->flink = NULL;\
	if (sll_list->first == NULL) { sll_list->first = sll_node; sll_list->last = sll_node; }\
	if (sll_list->last != sll_node) {\
		sll_list->last->flink = sll_node;\
		sll_list->last = sll_node;\
	}\
	sll_list->size++;\
}\
void TYPE##_sll_prepend(TYPE##_sll_t* sll_list, TYPE* value) {\
	TYPE##_sll_node_t* sll_node = (TYPE##_sll_node_t*) malloc(sizeof(TYPE##_sll_node_t));\
	sll_node->val = value;\
	sll_node->flink = NULL;\
	if (sll_list->first == NULL) { sll_list->first = sll_node; sll_list->last = sll_node; }\
	if (sll_list->first != sll_node) {\
		sll_node->flink = sll_list->first;\
		sll_list->first = sll_node;\
	}\
	sll_list->size++;\
}\
TYPE* TYPE##_sll_head(TYPE##_sll_t* sll_list) {\
	TYPE* ret_val = NULL;\
	if (NULL != sll_list->first) {\
		TYPE##_sll_node_t* tmp = sll_list->first;\
		ret_val = tmp->val;\
		sll_list->first = sll_list->first->flink;\
		if (sll_list->first == NULL) sll_list->last = NULL; \
		free(tmp);\
		sll_list->size--;\
	}\
	return ret_val;\
}\
TYPE* TYPE##_sll_tail(TYPE##_sll_t* sll_list) {\
	TYPE* ret_val = NULL;\
	if (NULL != sll_list->last) {\
		TYPE##_sll_node_t* tmp = sll_list->last;\
		ret_val = tmp->val;\
		TYPE##_sll_node_t* tmp_list_elem = sll_list->first;\
		if(sll_list->first != sll_list->last) {\
		    while (tmp_list_elem->flink != sll_list->last) { tmp_list_elem = tmp_list_elem->flink; }\
		    sll_list->last = tmp_list_elem;\
		    sll_list->last->flink = NULL;\
		} else {\
			sll_list->last = NULL; sll_list->first = NULL; \
		}\
		free(tmp);\
		sll_list->size--;\
	}\
	return ret_val;\
}\
void TYPE##_sll_free(TYPE##_sll_t* sll_list) {\
	TYPE##_sll_node_t *tmp;\
	while (sll_list->first != NULL) {\
		tmp = sll_list->first;\
		sll_list->first = sll_list->first->flink;\
		free(tmp);\
	}\
	free(sll_list);\
}\
void TYPE##_sll_clear(TYPE##_sll_t* sll_list) {\
	TYPE##_sll_node_t *tmp;\
	while (sll_list->first != NULL) {\
		tmp = sll_list->first;\
		sll_list->first = sll_list->first->flink;\
		free(tmp);\
		sll_list->size--;\
	}\
}\
void TYPE##_sll_delete(TYPE##_sll_t* sll_list, TYPE##_sll_node_t *tbr) {\
	if (sll_list->first == tbr) {\
		sll_list->first = tbr->flink;\
	} else {\
		TYPE##_sll_node_t *tmp = sll_list->first;\
		TYPE##_sll_node_t *mem = sll_list->first;\
		while (tmp->flink != NULL) {\
			tmp = tmp->flink;\
			if (tmp == tbr) {\
				mem->flink = tbr->flink;\
				free(tmp);\
				sll_list->size--;\
				break;\
			} else {\
				mem = mem->flink;\
			}\
		}\
	}\
}

#endif // _NP_LIST_H_
