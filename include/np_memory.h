
#ifndef _NP_MEMORY_H
#define _NP_MEMORY_H

#include "include.h"

// eum to identify the correct type of objects
typedef enum np_obj_type {
	np_none_t_e = 0,
	np_message_t_e,
	np_node_t_e,
	np_key_t_e,
	np_aaatoken_t_e,
	test_struct_t_e
} np_obj_enum;

typedef void (*np_dealloc_t) (void* data);
typedef void (*np_alloc_t) (void* data);


void del_callback(void* data);
void new_callback(void* data);

// wrapper around structures to allow ref counting and null pointer checking
struct np_obj_s {
	int ref_count;
	np_obj_enum type;
	void* ptr;

	np_dealloc_t del_callback;
	np_alloc_t   new_callback;

	np_obj_t* prev;
	np_obj_t* next;
};

// global object pool to handle all objects
struct np_obj_pool_s {
	np_obj_t* current;
	np_obj_t* first;
	np_obj_t* last;

	np_obj_t* free_obj;
	// maybe in the future we will need these two extensions
	unsigned int size;
	unsigned int available;

	pthread_mutex_t lock;
};

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

// makro definitions to maintain objects and wrapping structures

// np_unref - decrease ref count
#define np_unref(TYPE,n) { \
	assert (n != NULL); \
	assert (n->type == TYPE ## _e); \
	assert (n->ptr != NULL); \
	n->ref_count--; \
	if (n->ref_count <= 0) { \
		np_free(TYPE, n); \
	}; \
}

#define np_unbind(TYPE,n,obj) { \
	np_unref(TYPE, n); \
	obj = NULL; \
}

#define np_ref(TYPE,n) { \
		assert(n != NULL); \
		assert (n->type == TYPE ## _e); \
		assert (n->ptr != NULL); \
		n->ref_count++; \
}

// np_ref - increase ref count and return object
#define np_bind(TYPE, n, obj) { \
		np_ref(TYPE, n); \
		obj = (TYPE*) n->ptr; \
}

// np_new - allocate wrapper memory plus structure memory, returns wrapper struct pointer
#define np_new(TYPE, n) { \
    	assert(&np_obj_pool != NULL); \
    	pthread_mutex_lock(&(np_obj_pool.lock)); \
		if (np_obj_pool.free_obj != NULL) { \
    		np_obj_pool.current = np_obj_pool.free_obj; \
    		np_obj_pool.free_obj = np_obj_pool.free_obj->next; \
    		np_obj_pool.available--; \
    	} else { \
    		np_obj_pool.current = (np_obj_t*) malloc (sizeof(np_obj_t) ); \
    		np_obj_pool.size++; \
    	} \
		np_obj_pool.current->ptr = (TYPE*) malloc(sizeof(TYPE)); \
		np_obj_pool.current->new_callback = TYPE ## _new; \
		np_obj_pool.current->del_callback = TYPE ## _del; \
		np_obj_pool.current->type = TYPE ## _e; \
		np_obj_pool.current->ref_count = 1; \
		np_obj_pool.current->new_callback(np_obj_pool.current->ptr); \
		np_obj_pool.current->prev = np_obj_pool.last; \
		np_obj_pool.current->next = NULL; \
		if (!np_obj_pool.first) np_obj_pool.first = np_obj_pool.current; \
		if (np_obj_pool.last) np_obj_pool.last->next = np_obj_pool.current; \
		np_obj_pool.last = np_obj_pool.current; \
		n = np_obj_pool.current; \
		pthread_mutex_unlock(&(np_obj_pool.lock)); \
}

// np_free - decrease ref counter once more and free resources (but not object wrapper)
// n->ref_count--;
#define np_free(TYPE, n) { \
	assert (n->ptr != NULL); \
	assert (n->type == TYPE ## _e); \
	pthread_mutex_lock(&(np_obj_pool.lock)); \
	if (n->ref_count <= 0) { \
		printf("--- memory freeing now %p ---\n", n); \
		if (n == np_obj_pool.last)  np_obj_pool.last  = n->prev; \
		if (n == np_obj_pool.first) np_obj_pool.first = n->next; \
		if (n->prev) n->prev->next = n->next; \
		if (n->next) n->next->prev = n->prev; \
		n->del_callback(n->ptr); \
		free(n->ptr); \
		n->ptr = NULL; \
		n->type = np_none_t_e; \
		n->prev = NULL; n->next = np_obj_pool.free_obj; np_obj_pool.free_obj = n; \
		np_obj_pool.available++; \
		np_obj_pool.current = NULL; \
	} \
	np_printpool; \
	pthread_mutex_unlock(&(np_obj_pool.lock)); \
}

// print the complete object list and statistics
#define np_printpool { \
		printf("\n---memory table---\n"); \
		for (np_obj_t* iter = np_obj_pool.first; iter != NULL; iter = iter->next ) \
		{ \
			printf("obj %p (type %d ptr %p ref_count %d):(%p <- -> %p)\n", iter, iter->type, iter->ptr, iter->ref_count, iter->prev, iter->next ); \
		} \
		printf("---memory summary---\n"); \
		printf("size %d available %d, first free (%p)\n", np_obj_pool.size, np_obj_pool.available, np_obj_pool.free_obj); \
		printf("first %p last %p, current %p\n", np_obj_pool.first, np_obj_pool.last, np_obj_pool.current); \
		printf("---memory end---\n"); \
}
#endif // _NP_MEMORY_H
