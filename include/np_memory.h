
#ifndef _NP_MEMORY_H
#define _NP_MEMORY_H

#include "include.h"

// enum to identify the correct type of objects
typedef enum np_obj_type {
	np_none_t_e = 0,
	np_message_t_e,
	np_node_t_e,
	np_key_t_e, // not yet used
	np_aaatoken_t_e,
	test_struct_t_e = 99
} np_obj_enum;

typedef void (*np_dealloc_t) (void* data);
typedef void (*np_alloc_t) (void* data);

void del_callback(void* data);
void new_callback(void* data);

/** np_obj_t
 **
 ** void* like wrapper around structures to allow ref counting and null pointer checking
 ** binding and object to an np_obj_t will increase the ref counter, unbind wil decrease it
 ** if you have successfully called np_bind for a structure, it cannot be "freed" without
 ** the corresponding np_unbind call.
 ** it should be safe to call np_free on np_obj_t structures, becuase ref counting protects
 ** side effects (in theory ;-)
 **/
struct np_obj_s {

	int ref_count;
	np_obj_enum type;
	void* ptr;

	np_dealloc_t del_callback;
	np_alloc_t   new_callback;

	np_obj_t* prev;
	np_obj_t* next;

	pthread_mutex_t lock;
};


/** np_obj_pool_t
 **
 ** global object pool to store and handle all heap objects
 **/
struct np_obj_pool_s {
	np_obj_t* current;
	np_obj_t* first;
	np_obj_t* last;

	np_obj_t* free_obj;
	// we need these two extensions
	unsigned int size;
	unsigned int available;

	pthread_mutex_t lock;
};

/**
 ** following this line: np_memory cache and object prototype definitions
 **/
#define np_mem_init() { \
	np_obj_pool.current = NULL; \
	np_obj_pool.first = NULL; \
	np_obj_pool.last = NULL; \
	np_obj_pool.free_obj = NULL; \
	np_obj_pool.size = 0; \
	np_obj_pool.available = 0; \
	if (0 != pthread_mutex_init (&(np_obj_pool.lock), NULL)) \
	{ \
		exit(1); \
	} \
}

// macro definitions to generate header prototype definitions
#define _NP_GENERATE_MEMORY_PROTOTYPES(TYPE) \
void TYPE##_new(void*); \
void TYPE##_del(void*); \
void TYPE##_ref(np_obj_t* obj); \
void TYPE##_unref(np_obj_t* obj);

// macro definitions to generate implementation of prototypes
#define _NP_GENERATE_MEMORY_IMPLEMENTATION(TYPE) \
void TYPE##_unref(np_obj_t* obj) { assert (obj != NULL); obj->ref_count--; } \
void TYPE##_ref(np_obj_t* obj)   { assert (obj != NULL); obj->ref_count++; }

/**
 ** following this line: np_obj bind, unbind, free definitions
 **/
// assert (n->ptr != NULL);
//	if (n->ref_count <= 0) {
//		np_free(TYPE, n);
//	};
#define np_ref(TYPE, n) \
{ \
    assert (n != NULL); \
    assert (n->type == TYPE##_e); \
    assert (n->ptr != NULL); \
	n->ref_count++; \
}

#define np_unref(TYPE,n)\
{ \
	assert (n != NULL); \
	assert (n->type == TYPE##_e); \
	n->ref_count--; \
}

// pthread_mutex_lock(&(n->lock));
#define np_bind(TYPE, n, obj)\
{ \
	assert (n      != NULL); \
	np_ref(TYPE, n); \
	assert (n->ptr != NULL); \
	obj = (TYPE*) n->ptr; \
}
// pthread_mutex_unlock(&(n->lock));
#define np_unbind(TYPE,n,obj) { \
	assert (NULL != n); \
	np_unref(TYPE, n); \
	obj = NULL; \
}

// np_new - allocate wrapper memory plus structure memory, returns wrapper struct pointer
// if (0 != pthread_mutex_init (&(np_obj_pool.current->lock), NULL))
// {
// 	exit(1);
// }
#define np_new_obj(TYPE, np_obj) \
{ \
    assert(NULL != &np_obj_pool); \
    pthread_mutex_lock(&(np_obj_pool.lock)); \
	if (NULL != np_obj_pool.free_obj) { \
    	np_obj_pool.current = np_obj_pool.free_obj; \
    	np_obj_pool.free_obj = np_obj_pool.free_obj->next; \
    	np_obj_pool.available--; \
	} else { \
    	np_obj_pool.current = (np_obj_t*) malloc (sizeof(np_obj_t) ); \
    	np_obj_pool.size++; \
    } \
	np_obj_pool.current->ptr = (TYPE*) malloc(sizeof(TYPE)); \
	np_obj_pool.current->new_callback = TYPE##_new; \
	np_obj_pool.current->del_callback = TYPE##_del; \
	np_obj_pool.current->type = TYPE##_e; \
	np_obj_pool.current->ref_count = 0; \
	np_obj_pool.current->new_callback(np_obj_pool.current->ptr); \
	np_obj_pool.current->prev = np_obj_pool.last; \
	np_obj_pool.current->next = NULL; \
	if (NULL == np_obj_pool.first) np_obj_pool.first = np_obj_pool.current; \
	if (NULL != np_obj_pool.last) np_obj_pool.last->next = np_obj_pool.current; \
	np_obj_pool.last = np_obj_pool.current; \
	np_obj = np_obj_pool.current->ptr; \
	np_obj->obj = np_obj_pool.current; \
	pthread_mutex_unlock(&(np_obj_pool.lock)); \
}

#define np_free_obj(TYPE, np_obj) \
{ \
	pthread_mutex_lock(&(np_obj_pool.lock)); \
	np_obj_t* obj = np_obj->obj;\
	if (obj && obj->ref_count <= 0 && obj->ptr) { \
		assert (obj->type == TYPE##_e); \
		if (obj == np_obj_pool.last)  np_obj_pool.last  = obj->prev; \
		if (obj == np_obj_pool.first) np_obj_pool.first = obj->next; \
		if (NULL != obj->prev) obj->prev->next = obj->next; \
		if (NULL != obj->next) obj->next->prev = obj->prev; \
		obj->del_callback(obj->ptr); \
		free(obj->ptr); \
		obj->ptr = NULL; \
		obj->type = np_none_t_e; \
		obj->prev = NULL; obj->next = np_obj_pool.free_obj; np_obj_pool.free_obj = obj; \
		np_obj_pool.available++; \
		np_obj_pool.current = NULL; \
	} \
	np_obj = NULL;\
	pthread_mutex_unlock(&(np_obj_pool.lock)); \
}

#define np_ref_obj(TYPE, np_obj) \
{ \
    assert (np_obj != NULL); \
	assert (np_obj->obj != NULL); \
    assert (np_obj->obj->type == TYPE##_e); \
    assert (np_obj->obj->ptr != NULL); \
    np_obj->obj->ref_count++; \
}

#define np_unref_obj(TYPE, np_obj)\
{ \
	assert (np_obj != NULL); \
	assert (np_obj->obj != NULL); \
	assert (np_obj->obj->type == TYPE##_e); \
	np_obj->obj->ref_count--; \
}



#define np_new(TYPE, n) \
{ \
    assert(NULL != &np_obj_pool); \
    pthread_mutex_lock(&(np_obj_pool.lock)); \
	if (NULL != np_obj_pool.free_obj) { \
    	np_obj_pool.current = np_obj_pool.free_obj; \
    	np_obj_pool.free_obj = np_obj_pool.free_obj->next; \
    	np_obj_pool.available--; \
	} else { \
    	np_obj_pool.current = (np_obj_t*) malloc (sizeof(np_obj_t) ); \
    	np_obj_pool.size++; \
    } \
	np_obj_pool.current->ptr = (TYPE*) malloc(sizeof(TYPE)); \
	np_obj_pool.current->new_callback = TYPE##_new; \
	np_obj_pool.current->del_callback = TYPE##_del; \
	np_obj_pool.current->type = TYPE##_e; \
	np_obj_pool.current->ref_count = 0; \
	np_obj_pool.current->new_callback(np_obj_pool.current->ptr); \
	np_obj_pool.current->prev = np_obj_pool.last; \
	np_obj_pool.current->next = NULL; \
	if (NULL == np_obj_pool.first) np_obj_pool.first = np_obj_pool.current; \
	if (NULL != np_obj_pool.last) np_obj_pool.last->next = np_obj_pool.current; \
	np_obj_pool.last = np_obj_pool.current; \
	n = np_obj_pool.current; \
	pthread_mutex_unlock(&(np_obj_pool.lock)); \
}

// np_free - free resources (but not object wrapper) if ref_count is <= 0
// in case of doubt, call np_free. it will not harm ;-)
// pthread_mutex_lock(&(n->lock));
// pthread_mutex_unlock(&(n->lock));
// assert (n->ptr != NULL);

#define np_free(TYPE, n) \
{ \
	pthread_mutex_lock(&(np_obj_pool.lock)); \
	if (n->ref_count <= 0 && n->ptr) { \
		assert (n->type == TYPE##_e); \
		if (n == np_obj_pool.last)  np_obj_pool.last  = n->prev; \
		if (n == np_obj_pool.first) np_obj_pool.first = n->next; \
		if (NULL != n->prev) n->prev->next = n->next; \
		if (NULL != n->next) n->next->prev = n->prev; \
		n->del_callback(n->ptr); \
		free(n->ptr); \
		n->ptr = NULL; \
		n->type = np_none_t_e; \
		n->prev = NULL; n->next = np_obj_pool.free_obj; np_obj_pool.free_obj = n; \
		np_obj_pool.available++; \
		np_obj_pool.current = NULL; \
	} \
	pthread_mutex_unlock(&(np_obj_pool.lock)); \
}

// print the complete object list and statistics
#define np_printpool { \
		pthread_mutex_lock(&(np_obj_pool.lock)); \
		printf("\n---memory table---\n"); \
		for (np_obj_t* iter = np_obj_pool.first; iter != NULL; iter = iter->next ) \
		{ \
			printf("obj %p (type %d ptr %p ref_count %d):(%p <- -> %p)\n", iter, iter->type, iter->ptr, iter->ref_count, iter->prev, iter->next ); \
		} \
		printf("---memory summary---\n"); \
		printf("size %d available %d, first free (%p)\n", np_obj_pool.size, np_obj_pool.available, np_obj_pool.free_obj); \
		printf("first %p last %p, current %p\n", np_obj_pool.first, np_obj_pool.last, np_obj_pool.current); \
		printf("---memory end---\n"); \
		pthread_mutex_unlock(&(np_obj_pool.lock)); \
}
#endif // _NP_MEMORY_H
