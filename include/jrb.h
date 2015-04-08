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
#ifndef	_NP_JRB_H_
#define	_NP_JRB_H_

#include "include.h"

#include "jval.h"

/* Main jrb_node.  You only ever use the fields
   flink
   blink
   k.key or k.ikey
   v.val
*/
struct np_jrb_t
{
    unsigned char red;
    unsigned char internal;
    unsigned char left;
    unsigned char roothead;	/* (bit 1 is root, bit 2 is head) */

    np_jrb_t *flink;
    np_jrb_t *blink;
    np_jrb_t *parent;

    Jval key;
    Jval val;
};

np_jrb_t* make_jrb ();		/* Creates a new rb-tree */

/* Creates a node with key key and val val and inserts it into the tree.
   jrb_insert uses strcmp() as comparison funcion.  jrb_inserti uses <>=,
   jrb_insertg uses func() */
extern np_jrb_t* jrb_insert_str (np_jrb_t *tree, const char *key, Jval val);
extern np_jrb_t* jrb_insert_int (np_jrb_t *tree, int ikey, Jval val);
extern np_jrb_t* jrb_insert_ulong (np_jrb_t *tree, unsigned long ulkey, Jval val);
extern np_jrb_t* jrb_insert_dbl (np_jrb_t *tree, double dkey, Jval val);
extern np_jrb_t* jrb_insert_gen (np_jrb_t *tree, Jval key, Jval val, int (*func) (Jval, Jval));

/* returns an external node in t whose value is equal k. Returns NULL if
   there is no such node in the tree */
extern np_jrb_t* jrb_find_str (np_jrb_t* root, const char *key);
extern np_jrb_t* jrb_find_int (np_jrb_t* root, int ikey);
extern np_jrb_t* jrb_find_ulong (np_jrb_t* root, unsigned long ikey);
extern np_jrb_t* jrb_find_dbl (np_jrb_t* root, double dkey);
extern np_jrb_t* jrb_find_gen (np_jrb_t* root, Jval, int (*func) (Jval, Jval));

/* returns an external node in t whose value is equal
  k or whose value is the smallest value greater than k. Sets found to
  1 if the key was found, and 0 otherwise.  */
extern np_jrb_t* jrb_find_gte_str (np_jrb_t* root, const char *key, int *found);
extern np_jrb_t* jrb_find_gte_int (np_jrb_t* root, int ikey, int *found);
extern np_jrb_t* jrb_find_gte_ulong (np_jrb_t* root, unsigned long ikey, int *found);
extern np_jrb_t* jrb_find_gte_dbl (np_jrb_t* root, double dkey, int *found);
extern np_jrb_t* jrb_find_gte_gen (np_jrb_t* root, Jval key, int (*func) (Jval, Jval), int *found);

/* Creates a node with key key and val val and inserts it into the 
   tree before/after node nd.  Does not check to ensure that you are 
   keeping the correct order */
extern void jrb_delete_node (np_jrb_t* node);	/* Deletes and frees a node (but not the key or val) */
extern void jrb_free_tree (np_jrb_t* root);	/* Deletes and frees an entire tree */

extern Jval jrb_val (np_jrb_t* node);	/* Returns node->v.val -- this is to shut lint up */
extern int jrb_nblack (np_jrb_t* n);	/* returns # of black nodes in path from n to the root */

int jrb_plength (np_jrb_t* n);	/* returns the # of nodes in path from n to the root */

#define jrb_first(n) (n->flink)
#define jrb_last(n) (n->blink)
#define jrb_next(n) (n->flink)
#define jrb_prev(n) (n->blink)
#define jrb_empty(t) (t->flink == t)
#ifndef jrb_nil
#define jrb_nil(t) (t)
#endif

#define jrb_traverse(ptr, lst) \
  for(ptr = jrb_first(lst); ptr != jrb_nil(lst); ptr = jrb_next(ptr))

#define jrb_rtraverse(ptr, lst) \
  for(ptr = jrb_last(lst); ptr != jrb_nil(lst); ptr = jrb_prev(ptr))

#endif // _NP_JRB_H_
