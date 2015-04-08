#ifndef NP_PQUEUE_H
#define NP_PQUEUE_H

/* define some constants,  */
#define MSGSIZE 128       /* max size of a debug message */
#define FAILED   -1       /* define -1 to indicate failure of some operations */
#define EMPTY     1       /* define  1 to indicate that the heap is empty */ 

/* define some macros */
#define FREE(x)  free(x) ; x = NULL            /* core if free'ed pointer is used */
#define LEFT(x)  (2*x)                         /* left child of a node */
#define RIGHT(x) ((2*x)+1)                     /* right child of a node */
#define PARENT(x) (x/2)                        /* parent of a node */
#define SWAP(t,x,y) tmp = x ; x = y ; y = tmp  /* swap to variables */

typedef unsigned long long priority;

/* define a structure representing an individual node in the heap, and
 * make it a valid type for convenience */
typedef struct np_pqueue_node {
  priority p;
  unsigned int id;
  int duration;
  int niceness;
  int cpu_usage;
  short sentinel;
} np_pqueue_node;

/* create a global node tmp, for swaping purposes */
np_pqueue_node tmp;

/* for convience in function declarations, typedef a pointer to a node
 * as its own type, node_ptr */
typedef np_pqueue_node* np_pqueue_node_ptr;

/* define a structure representing the heap, and make it a valid type
 * for convenience */

typedef struct binary_heap {
  int heap_size;
  int max_elems;
  np_pqueue_node_ptr elements;
} binary_heap;

/* function prototypes for functions which operate on a binary heap */ 

void        	   heapify(binary_heap *a, int i);
np_pqueue_node_ptr heap_max(binary_heap *a);
np_pqueue_node     heap_extract_max(binary_heap *a);
void        	   heap_insert(binary_heap *a, np_pqueue_node key);
void               heap_delete(binary_heap *a, int i);
void               heap_increase_key(binary_heap *a, int i,priority p);
void               heap_initialize(binary_heap *a, int nodes);
void               heap_finalize(binary_heap *a);

/* function prototypes for functions which operate on a node */
int            np_pqueue_node_find(binary_heap a,unsigned int id);
np_pqueue_node np_pqueue_node_create(unsigned int id,priority p, int duration, int niceness, int cpu_usage);

/* function prototypes for helper functions */
int         compare_priority(np_pqueue_node i, np_pqueue_node j);

#endif // NP_PQUEUE_H
