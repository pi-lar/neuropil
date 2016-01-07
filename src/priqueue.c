#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "priqueue.h"
#include "log.h"

/* Function which takes a heap rooted at the given index and make sure
 * that is conforms to the heap critera. Adapted from Introduction to
 * Algorithms (Cormen, Leiserson, Rivest 1990) page 143 */
void heapify(binary_heap *a, int16_t i) {

	int16_t l,r,largest;
  
	l = LEFT(i);
	r = RIGHT(i);

	/* check the left child */
	largest = ((l <= a->heap_size && compare_priority(a->elements[l],a->elements[i])) ? l : i);
	/* check the right child */
	if (r <= a->heap_size && compare_priority(a->elements[r],a->elements[largest])) largest = r;

	if (largest != i) {
		/* swap nodes largest and i, then heapify */
		SWAP(node,a->elements[i],a->elements[largest]);
		heapify(a, largest);
	}
}

/* Function to return the max (first) node of a heap */
np_pqueue_node* heap_max(binary_heap *a) {
	return ((a->heap_size <= 0) ? NULL : &(a->elements[1]));
}

/* Function to remove the max node from the heap and return it.  The
 * running time is O(lg(n)) since it performs only a constant amount of
 * work on top of the O(lg(n)) of heapify(). Adapted from Introduction
 * to Algorithms (Cormen, Leiserson, Rivest 1990) page 150 */
np_pqueue_node heap_extract_max(binary_heap *a) {
	np_pqueue_node max;
	max.sentinel = 1;
	/*
	 * if there are elements in the heap, make the last item in the heap
	 * the first one, shorten the heap by one and call heapify().
	 */
	if (a->heap_size >= 1) {
		max = a->elements[1];
		a->elements[1] = a->elements[(a->heap_size)--];
		heapify(a,1);
	}
	return max;
}

/*
 * Function to insert an element into the heap, worst case running
 * time is O(lg(n)) on an n element heap, since the path traced from
 * the new leaf to the root has at most length lg(n). This occurs when
 * the new leaf should be the root node.  Adapted from Introduction to
 * Algorithms (Cormen, Leiserson, Rivest 1990) page 150
 */
void heap_insert(binary_heap *a, np_pqueue_node key) {
	int16_t i;
	/*
	 * if the heap already has the max number of elements we do not
	 * allow more elements to be added
	 */
	if (a->heap_size >= a->max_elems) {
		log_msg(LOG_WARN, "Heap capacity exceeded, new element not added.");
		return;
	}
	/*
	 * increase the heap size to accomidate the new node, and set the
	 * inital position of this node to be the last node in the heap
	 */
	i = ++(a->heap_size);
	/*
	 * traverse the path from the leaf to the root to find the a proper
	 * place for the new element
	 */
	while (i > 1 && compare_priority(key,a->elements[PARENT(i)])) {
		a->elements[i] = a->elements[PARENT(i)];
		i = PARENT(i);
	}
	/* insert the element at the position that was determined */
	a->elements[i] = key;
}

/* Function to delete a node from the heap. Adapted from Introduction
 * to Algorithms (Cormen, Leiserson, Rivest 1990) page 151 Exercise
 * 7.5-5 */

void heap_delete(binary_heap *a, int16_t i) {
	np_pqueue_node deleted;
	/* return with an error if the input is invalid, ie trying to delete
	 * elements that are outside of the heap bounds, 1 to heap_size */
	if (i > a->heap_size || i < 1) {
		log_msg(LOG_DEBUG, "heap_delete(): %hd, no such element", i);
		return;
	}
	/* switch the item to be deleted with the last item, and then
	 * shorten the heap by one */
	deleted = a->elements[i];
	a->elements[i] = a->elements[(a->heap_size)--];

	heapify(a,i);
	/* (compare_priority(a->elements[i],deleted)) ? heap_up(a,i) : heap_down(a,i); */
}

/* Function to increase the key value of a node from in the
 * heap. Adapted from Introduction to Algorithms (Cormen, Leiserson,
 * Rivest 1990) page 151 Exercise 7.5-4 */
void heap_increase_key(binary_heap *a, int16_t i, priority p) {
	/* return with an error if the input is invalid, ie trying to
	 * increase elements that are outside of the heap bounds, 1 to
	 * heap_size */
	if (i > a->heap_size || i < 1) {
		log_msg(LOG_DEBUG, "heap_increase_key(): %hd, no such element", i);
		return;
	}
	/* change and propagate */
	a->elements[i].prio = p;
	heapify(a,i);
}

/* function to initalize a given binary heap */
void heap_initialize(binary_heap *a, int16_t nodes) {
	/* We initalize heap_size to zero, since a newly created heap
	 * contains no elements. */
	a->heap_size = 0;
	/* we set the max elems to the requested number of nodes, and the
	 * allocate enough space for this + 1 number of nodes, since the
	 * heap is always numbered from 1, but array/pointer accesses are
	 * always from 0. */
	a->max_elems = nodes;
	a->elements = (np_pqueue_node*) malloc(sizeof(struct np_pqueue_node)*((a->max_elems)+1));
	/* mark the zero'th element of the heap a to be empty, just in case
	 * it is ever accessed */
	a->elements[0].sentinel = 1;
}

/* function to clean up after we are done with the heap */
void heap_finalize(binary_heap *a) {
	FREE(a->elements);
}

/* function to create a node */
np_pqueue_node node_create(uint16_t id,
		 priority p,
		 int16_t duration,
		 int16_t niceness,
		 int16_t cpu_usage) {
	np_pqueue_node n;
	n.id = id;
	n.prio = p;
	n.duration = duration;
	n.niceness = niceness;
	n.cpu_usage = cpu_usage;
	n.sentinel = 0;
	return n;
}

/* function to compare the priority of two given nodes, this is a
 * wrapper for the given compare routine, since in all heap
 * comparisions, we are only interested in greater than or less than
 * operations */
int16_t compare_priority(np_pqueue_node i,np_pqueue_node j) {
	if (i.id > j.id) return 1;
	else             return 0;
}

/* function to find if a node is in the heap, O(n) worst case, since
 * we will have to consider every element in a failed search */
int16_t np_pqueue_node_find(binary_heap a, uint16_t id) {
	int16_t i;
	for (i = 1; i<=a.heap_size; i++)
		if (id == a.elements[i].id) return i;
	return FAILED;
}

