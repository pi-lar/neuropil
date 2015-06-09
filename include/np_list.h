/*
Libraries for fields, doubly-linked lists and red-black trees.
Copyright (C) 2001 James S. Plank

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

---------------------------------------------------------------------------
Please see http://www.cs.utk.edu/~plank/plank/classes/cs360/360/notes/Libfdr/
for instruction on how to use this library.

Jim Plank
plank@cs.utk.edu
http://www.cs.utk.edu/~plank

Associate Professor
Department of Computer Science
University of Tennessee
203 Claxton Complex
1122 Volunteer Blvd.
Knoxville, TN 37996-3450

     865-974-4397
Fax: 865-974-4404
*/
#ifndef _NP_LIST_H_
#define _NP_LIST_H_

#include "jval.h"


/** double linked list header only implementation for neuropil
 **/
typedef struct np_dll_list_s np_dll_list_t;
typedef struct np_dll_node_s np_dll_node_t;

struct np_dll_list_s
{
	int size;
	np_dll_node_t *first;
	np_dll_node_t *last;
};

struct np_dll_node_s
{
	np_dll_node_t *flink;
	np_dll_node_t *blink;
    np_jval_t val;
};

#define NP_DLL_LIST_INIT(dll_list) { \
	dll_list = (np_dll_list_t*) malloc(sizeof(np_dll_list_t)); \
	dll_list.size = 0; \
	dll_list.first = NULL; \
	dll_list.last = NULL; \
}

#define NP_DLL_LIST_APPEND(dll_list, elem) { \
	np_dll_node_t* dll_node = (np_dll_node_t*) malloc(sizeof(np_dll_node_t)); \
	dll_node->val = new_jval_v(elem); \
	dll_node->flink = NULL; \
	dll_node->blink = NULL; \
	if (dll_list->first == NULL) { dll_list->first = dll_node; dll_list->last = dll_node; } \
	if (dll_list->last != dll_node) { \
		dll_node->blink = dll_list->last; \
		dll_list->last->flink = dll_node; \
		dll_list->last = dll_node; \
	} \
	dll_list->size++; \
}

#define NP_DLL_LIST_PREPEND(dll_list, elem) \
	np_dll_node_t* dll_node = (np_dll_node_t*) malloc(sizeof(np_dll_node_t)); \
	dll_node->val = new_jval_v(elem); \
	dll_node->flink = NULL; \
	dll_node->blink = NULL; \
	if (dll_list->first == NULL) { dll_list->first = dll_node; dll_list->last = dll_node; } \
	if (dll_list->first != dll_node) { \
		dll_node->flink = dll_list->first; \
		dll_list->first->blink = dll_node; \
		dll_list->first = dll_node; \
	} \
	dll_list->size++;

#define NP_DLL_LIST_TRAVERSE(dll_list, node_iter, elem)  for (node_iter = dll_list->first, elem = dll_list->first->val.value.v; node_iter != NULL; node_iter = iter->flink, elem = iter->flink->val.value.v)
#define NP_DLL_LIST_RTRAVERSE(dll_list, node_iter, elem) for (node_iter = dll_list->last, elem = dll_list->last->val.value.v; node_iter != NULL; node_iter = iter->blink, elem = iter->blink->val.value.v)

#define NP_DLL_LIST_EMPTY(dll_list) dll_list->first == NULL

#define NP_DLL_LIST_TOP(dll_list, list_elem) \
	if (dll_list->first) { \
		tmp = dll_list->first; \
		list_elem = tmp->val.value.v;\
		dll_list->first = dll_list->first->flink; \
		dll_list->first->blink = NULL; \
		free(tmp); \
		dll_list->size--; \
	}

#define NP_DLL_LIST_TAIL(dll_list, list_elem) \
	if (dll_list->last) { \
		tmp = dll_list->last; \
		list_elem = tmp->val.value.v;\
		dll_list->last = dll_list->last->blink; \
		dll_list->last->flink = NULL; \
		free(tmp); \
		dll_list->size--; \
	}

#define NP_DLL_LIST_FREE(dll_list) \
	np_dll_node_t *tmp, *node; \
	while (dll_list->first != NULL) { \
		tmp = dll_list->first; \
		dll_list->first = dll_list->first->flink; \
		dll_list->first->blink = NULL; \
		free(tmp); \
	} \
	free(dll_list);

#define NP_DLL_LIST_FIRST(dll_list) (dll_list->first)
#define NP_DLL_LIST_LAST(dll_list) (dll_list->last)

#define NP_DLL_LIST_NEXT(dll_elem) (dll_list->flink)
#define NP_DLL_LIST_PREV(dll_elem) (dll_list->blink)

/** single linked list header only implementation for neuropil
 **/
typedef struct np_sll_list_s np_sll_list_t;
typedef struct np_sll_node_s np_sll_node_t;

struct np_sll_list_s
{
	int size;
	np_sll_node_t *first;
	np_sll_node_t *last;
};

struct np_sll_node_s
{
	np_dll_node_t *flink;
    np_jval_t val;
};

#define NP_SLL_LIST_INIT(sll_list) { \
	sll_list = (np_sll_list_t*) malloc(sizeof(np_sll_list_t)); \
	sll_list.size = 0; \
	sll_list.first = NULL; \
	sll_list.last = NULL; \
}

#define NP_SLL_LIST_APPEND(sll_list, elem) { \
	np_dll_node_t* dll_node = (np_dll_node_t*) malloc(sizeof(np_dll_node_t)); \
	dll_node->val = new_jval_v(elem); \
	dll_node->flink = NULL; \
	if (sll_list->first == NULL) { sll_list->first = dll_node; sll_list->last = dll_node; } \
	if (sll_list->last != dll_node) { \
		sll_list->last->flink = dll_node; \
		sll_list->last = dll_node; \
	} \
	sll_list->size++; \
}

#define NP_SLL_LIST_PREPEND(sll_list, elem) { \
	np_dll_node_t* dll_node = (np_dll_node_t*) malloc(sizeof(np_dll_node_t)); \
	dll_node->val = new_jval_v(elem); \
	dll_node->flink = NULL; \
	if (sll_list->first == NULL) { sll_list->first = dll_node; sll_list->last = dll_node; } \
	if (sll_list->first != dll_node) { \
		dll_node->flink = sll_list->first; \
		sll_list->first = dll_node; \
	} \
	sll_list->size++; \
}

#define NP_SLL_LIST_TRAVERSE(sll_list, node_iter, elem) for (node_iter = sll_list->first, elem = sll_list->first->val.value.v; node_iter != NULL; node_iter = iter->flink, elem = iter->flink->val.value.v)
#define NP_SLL_LIST_EMPTY(sll_list) sll_list->first == NULL

#define NP_SLL_LIST_TOP(sll_list, list_elem) \
	if (sll_list->first) { \
		tmp = sll_list->first; \
		list_elem = tmp->val.value.v;\
		sll_list->first = sll_list->first->flink; \
		free(tmp); \
		sll_list->size--; \
	}

#define NP_SLL_LIST_TAIL(sll_list, list_elem) \
	if (sll_list->last) { \
		tmp = sll_list->last; \
		list_elem = tmp->val.value.v;\
		np_sll_node_t* tmp_list_elem = sll_list->first; \
		while (tmp_list_elem != sll_list->last) { tmp_list_elem = tmp_list_elem->flink; } \
		sll_list->last = tmp_list_elem; \
		sll_list->last->flink = NULL; \
		free(tmp); \
		sll_list->size--; \
	}

#define NP_DL_LIST_FREE(sll_list) \
	np_dll_node_t *tmp, *node; \
	while (sll_list->first != NULL) { \
		tmp = sll_list->first; \
		sll_list->first = sll_list->first->flink; \
		free(tmp); \
	} \
	free(sll_list);

#define NP_DL_LIST_FIRST(sll_list) (sll_list->first)
#define NP_DL_LIST_LAST(sll_list) (sll_list->last)

#define NP_DL_LIST_NEXT(sll_elem) (sll_list->flink)

#endif // _NP_LIST_H_
