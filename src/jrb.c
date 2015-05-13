/* Revision 1.2.  Jim Plank */

/* Original code by Jim Plank (plank@cs.utk.edu) */
/* modified for THINK C 6.0 for Macintosh by Chris Bartley */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>

#include "jrb.h"
#include "jval.h"
#include "log.h"


void mk_new_int (np_jrb_t* l, np_jrb_t* r, np_jrb_t* p, int il);
np_jrb_t* lprev (np_jrb_t* n);
np_jrb_t* rprev (np_jrb_t* n);
void recolor (np_jrb_t* n);
void single_rotate (np_jrb_t* y, int l);
void jrb_print_tree (np_jrb_t* t, int level);


#define isred(n)     (n->jrb_type & JRB_RED)
#define isblack(n)   (0 == (n->jrb_type & JRB_RED))
#define setred(n)    (n->jrb_type |= JRB_RED)
#define setblack(n)  (n->jrb_type &= JRB_BLACK)

#define isleft(n)    (n->jrb_type & JRB_LEFT)
#define isright(n)   (0 == (n->jrb_type & JRB_LEFT))
#define setleft(n)   (n->jrb_type |= JRB_LEFT)
#define setright(n)  (n->jrb_type &= JRB_RIGHT)

#define isint(n)     (n->jrb_type & JRB_INTERNAL)
#define isext(n)     (0 == (n->jrb_type & JRB_INTERNAL))
// #define isext(n)     (!isint(n))
#define setint(n)    (n->jrb_type |= JRB_INTERNAL)
#define setext(n)    (n->jrb_type &= JRB_EXTERNAL)

#define ishead(n)    (n->jrb_type & JRB_HEAD)
#define isnothead(n) (0 == (n->jrb_type & JRB_HEAD))
#define isroot(n)    (n->jrb_type & JRB_ROOT)
#define isnotroot(n) (0 == (n->jrb_type & JRB_ROOT))
#define sethead(n)   (n->jrb_type |= JRB_HEAD)
#define setroot(n)   (n->jrb_type |= JRB_ROOT)
#define setnormal(n) (n->jrb_type &= (JRB_NOTROOT & JRB_NOTHEAD))

#define getlext(n) ((np_jrb_t *)(n->key.value.v))
#define setlext(node, newval) node->key.value.v = (void *) (newval)
#define getrext(n) ((np_jrb_t *)(n->val.value.v))
#define setrext(n, newval) n->val.value.v = (void *) (newval)
#define sibling(n) ((isleft(n)) ? n->parent->blink : n->parent->flink)


#define mk_new_ext(new, kkkey, vvval) {\
  new = (np_jrb_t*) malloc (sizeof(np_jrb_t));\
  new->val = vvval;\
  new->key = kkkey;\
  setext(new);\
  setblack(new);\
  setnormal(new);\
}

void insert (np_jrb_t* item, np_jrb_t* list)	/* Inserts to the end of a list */
{
	assert(item != NULL);
	assert(list != NULL);

    np_jrb_t* last_node;

    last_node = list->blink;

    list->blink = item;
    last_node->flink = item;
    item->blink = last_node;
    item->flink = list;
}

void delete_item (np_jrb_t* item)	/* Deletes an arbitrary iterm */
{
	assert(item != NULL);

	item->flink->blink = item->blink;
    item->blink->flink = item->flink;
    /* TODO: DELETE item itself ? */
}

void mk_new_int (np_jrb_t* l, np_jrb_t* r, np_jrb_t* p, int il)
{
	assert(l != NULL);
	assert(r != NULL);
	assert(p != NULL);

    np_jrb_t* newnode;

    newnode = (np_jrb_t*) malloc (sizeof (np_jrb_t));

    // log_msg(LOG_DEBUG, "creating internal jrb node %p", newnode);
    newnode->key.type = np_special;
    newnode->val.type = np_special;

    setint (newnode);
    setred (newnode);
    setnormal (newnode);
    newnode->flink = l;
    newnode->blink = r;
    newnode->parent = p;
    setlext (newnode, l);
    setrext (newnode, r);
    l->parent = newnode;
    r->parent = newnode;
    setleft (l);
    setright (r);
    if (ishead (p))
	{
	    p->parent = newnode;
	    setroot (newnode);
	}
    else if (il)
	{
	    setleft (newnode);
	    p->flink = newnode;
	}
    else
	{
	    setright (newnode);
	    p->blink = newnode;
	}
    recolor (newnode);
}


np_jrb_t* lprev (np_jrb_t* n)
{
	assert(n != NULL);

	if (ishead (n)) return n;

	while (isnotroot (n))
	{
	    if (isright (n))
		return n->parent;
	    n = n->parent;
	}
    return n->parent;
}

np_jrb_t* rprev (np_jrb_t* n)
{
	assert(n != NULL);

	if (ishead (n)) return n;

	while (isnotroot (n))
	{
	    if (isleft (n))
		return n->parent;
	    n = n->parent;
	}
    return n->parent;
}

np_jrb_t* make_jrb ()
{
    np_jrb_t* head;

    head = (np_jrb_t*) malloc (sizeof (np_jrb_t));
    head->jrb_type = 0x0;

    head->key.type = np_special;
    head->val.type = np_special;

    head->flink = head;
    head->blink = head;
    head->parent = head;
    sethead (head);
    head->size = 0;
    // initial size to serialize a jrb tree, even with 0 elements
    head->byte_size = 1 + sizeof(uint32_t);

	assert(head != NULL);
    return head;
}

extern np_jrb_t* jrb_find_gte_key (np_jrb_t* n, np_key_t* key, int* fnd)
{
	assert(n   != NULL);
	assert(key != NULL);
	assert(fnd != NULL);

    *fnd = 0;
    if (isnothead (n))
	{
	    log_msg (LOG_WARN, "jrb_find_gte_int called on non-head %p %x", n, n->jrb_type);
    	return NULL;
	}
    if (n->parent == n) return n;

    if (key_equal(key, n->blink->key.value.key))
	{
	    *fnd = 1;
	    return n->blink;
	}

    if (key_comp(key,n->blink->key.value.key) > 0) return n;
    else n = n->parent;

    // TODO: potentially dangerous infinite loop !!!
    while (1)
	{
	    if (isext (n)) return n;

	    if (key_equal(key, getlext(n)->key.value.key))
		{
		    *fnd = 1;
		    return getlext (n);
		}
	    n = (key_comp(key, getlext(n)->key.value.key) < 0) ? n->flink : n->blink;
	}

    log_msg(LOG_WARN, "stsw:jrb_find_gte_int returning NULL");
    return NULL;
}


np_jrb_t* jrb_find_gte_str (np_jrb_t* n, const char *key, int *fnd)
{
	assert(n   != NULL);
	assert(key != NULL);
	assert(fnd != NULL);

	int cmp;

    *fnd = 0;
    if (isnothead (n))
	{
    	log_msg(LOG_WARN, "jrb_find_gte_str called on non-head %p %x", n, n->jrb_type);
    	return NULL;
	}

    // log_msg(LOG_DEBUG, "search   %p: key type: %d, value type: %d", n, n->key.type, n->val.type);
    if (n->parent == n) return n;


    cmp = strncmp (key, n->blink->key.value.s, 255);
    if (cmp == 0)
	{
	    *fnd = 1;
	    // log_msg(LOG_DEBUG, "search   %p: key type: %d, value type: %d", n->blink, n->blink->key.type, n->blink->val.type);
	    return n->blink;
	}

    if (cmp > 0) return n;
    else 		 n = n->parent;

    while (1)
	{
	    if (isext (n)) return n;

	    cmp = strncmp (key, getlext(n)->key.value.s, 255);
	    if (cmp == 0)
		{
		    *fnd = 1;
		    // log_msg(LOG_DEBUG, "search   %p: key type: %d, value type: %d", getlext(n), getlext(n)->key.type, getlext(n)->val.type);
		    return getlext(n);
		}
	    if (cmp < 0) n = n->flink;
	    else         n = n->blink;
	}
    log_msg(LOG_WARN, "jrb_find_gte_str returning NULL");
    return NULL;
}

np_jrb_t* jrb_find_str (np_jrb_t* n, const char *key)
{
	assert(n   != NULL);
	assert(key != NULL);

    int fnd;
    np_jrb_t* j;
    // log_msg(LOG_DEBUG, "search  %p: blink: %p, flink: %p parent: %p", n, n->blink, n->flink, n->parent);
    j = jrb_find_gte_str (n, key, &fnd);
    // log_msg(LOG_DEBUG, "found   %p: key type: %d, value type: %d", j, j->key.type, j->val.type);
    if (fnd) return j;
    else     return NULL;
}

np_jrb_t* jrb_find_gte_int (np_jrb_t* n, int ikey, int *fnd)
{
	assert(n   != NULL);
	assert(fnd != NULL);

	*fnd = 0;
    if (isnothead (n))
	{
	    log_msg (LOG_WARN, "jrb_find_gte_int called on non-head %p %x", n, n->jrb_type);
    	return NULL;
	}
    if (n->parent == n) return n;

    if (ikey == n->blink->key.value.i)
	{
	    *fnd = 1;
	    return n->blink;
	}
    if (ikey > n->blink->key.value.i) return n;
    else n = n->parent;

    while (1)
	{
	    if (isext (n)) return n;
	    if (ikey == getlext (n)->key.value.i)
		{
		    *fnd = 1;
		    return getlext (n);
		}
	    n = (ikey < getlext (n)->key.value.i) ? n->flink : n->blink;
	}
    log_msg(LOG_WARN, "stsw:jrb_find_gte_int returning NULL");
    return NULL;
}

np_jrb_t* jrb_find_gte_ulong (np_jrb_t* n, unsigned long ulkey, int *fnd)
{
	assert(n   != NULL);
	assert(fnd != NULL);

	*fnd = 0;

//    np_jrb_t* s = n;
//    while (isnothead (s)) s = s->parent;

    if (isnothead (n))
	{
    	log_msg(LOG_WARN, "jrb_find_gte_ulong called on non-head %p %x", n, n->jrb_type);
    	return NULL;
	}
    if (n->parent == n) return n;

    if (ulkey == n->blink->key.value.ul)
	{
	    *fnd = 1;
	    return n->blink;
	}
    if (ulkey > n->blink->key.value.ul) return n;
    else n = n->parent;

    while (1)
	{
	    if (isext (n)) return n;
	    if (ulkey == getlext (n)->key.value.ul)
		{
		    *fnd = 1;
		    return getlext (n);
		}
	    n = (ulkey < getlext (n)->key.value.ul) ? n->flink : n->blink;
	}
    log_msg(LOG_WARN, "stsw:jrb_find_gte_ulong returning NULL");
    return NULL;
}

extern np_jrb_t* jrb_find_key (np_jrb_t* n, np_key_t* key)
{
	assert(n   != NULL);
	assert(key != NULL);

	int fnd;
    np_jrb_t* j;
    j = jrb_find_gte_key (n, key, &fnd);
    if (fnd) return j;
    else     return NULL;
}

np_jrb_t* jrb_find_int (np_jrb_t* n, int ikey)
{
	assert(n   != NULL);

	int fnd;
    np_jrb_t* j;

    j = jrb_find_gte_int (n, ikey, &fnd);
    if (fnd) return j;
    else return NULL;
}

np_jrb_t* jrb_find_ulong (np_jrb_t* n, unsigned long ulkey)
{
	assert(n   != NULL);

	int fnd;
    np_jrb_t* j;

    j = jrb_find_gte_ulong (n, ulkey, &fnd);
    if (fnd) return j;
    else return NULL;
}

np_jrb_t* jrb_find_dbl (np_jrb_t* n, double dkey)
{
	assert(n   != NULL);

	int fnd;
    np_jrb_t* j;

    j = jrb_find_gte_dbl (n, dkey, &fnd);
    if (fnd) return j;
    else return NULL;
}

np_jrb_t* jrb_find_gen (np_jrb_t* n, np_jval_t key, int (*fxn) (np_jval_t, np_jval_t))
{
	assert(n   != NULL);

	int fnd;
    np_jrb_t* j;

    j = jrb_find_gte_gen (n, key, fxn, &fnd);
    if (fnd) return j;
    else return NULL;
}

np_jrb_t* jrb_find_gte_dbl (np_jrb_t* n, double dkey, int *fnd)
{
	assert(n   != NULL);
	assert(fnd != NULL);

	*fnd = 0;
    if (isnothead (n))
	{
	    log_msg(LOG_ERROR, "jrb_find_gte_dbl called on non-head %p %x", n, n->jrb_type);
    	return NULL;
	}
    if (n->parent == n) return n;

    if (dkey == n->blink->key.value.d)
	{
	    *fnd = 1;
	    return n->blink;
	}

    if (dkey > n->blink->key.value.d) return n;
    else n = n->parent;

    while (1)
	{
	    if (isext (n)) return n;
	    if (dkey == getlext (n)->key.value.d)
		{
		    *fnd = 1;
		    return getlext (n);
		}
	    n = (dkey < getlext (n)->key.value.d) ? n->flink : n->blink;
	}
    log_msg(LOG_WARN, "stsw:jrb_find_gte_dbl returning NULL");
    return NULL;
}

np_jrb_t* jrb_find_gte_gen (np_jrb_t* n, np_jval_t key, int (*fxn) (np_jval_t, np_jval_t), int *fnd)
{
	assert(n   != NULL);
	assert(fnd != NULL);

	int cmp;

    *fnd = 0;
    if (isnothead (n))
	{
    	log_msg(LOG_WARN, "jrb_find_gte_str called on non-head %p %x", n, n->jrb_type);
    	return NULL;
	}
    if (n->parent == n) return n;
    cmp = (*fxn) (key, n->blink->key);
    if (cmp == 0)
	{
	    *fnd = 1;
	    return n->blink;
	}

    if (cmp > 0) return n;
    else n = n->parent;

    while (1)
	{
	    if (isext (n)) return n;
	    cmp = (*fxn) (key, getlext (n)->key);
	    if (cmp == 0)
		{
		    *fnd = 1;
		    return getlext (n);
		}
	    if (cmp < 0) n = n->flink;
	    else n = n->blink;
	}
    log_msg( LOG_WARN, "stsw:jrb_find_gte_gen returning NULL");
    return NULL;
}

np_jrb_t* jrb_insert_b (np_jrb_t* n, np_jval_t key, np_jval_t val)
{
	assert(n   != NULL);

	np_jrb_t *newleft, *newright, *newnode, *p;

    if (ishead (n))
	{
	    if (n->parent == n)
		{	/* Tree is empty */
		    mk_new_ext (newnode, key, val);
		    insert (newnode, n);
		    n->parent = newnode;
		    newnode->parent = n;
		    setroot (newnode);

		    // log_msg(LOG_DEBUG, "insert h %p: key type: %d, value type: %d", n, n->key.type, n->val.type);
		    // log_msg(LOG_DEBUG, "insert h %p: key type: %d, value type: %d", newnode, newnode->key.type, newnode->val.type);
		    // log_msg(LOG_DEBUG, "insert h %p: blink: %p, flink: %p parent: %p", n, n->blink, n->flink, n->parent);
		    return newnode;
		}
	    else
		{
		    mk_new_ext (newright, key, val);
		    insert (newright, n);
		    newleft = newright->blink;
		    setnormal (newleft);
		    mk_new_int (newleft, newright, newleft->parent, isleft (newleft));
		    p = rprev (newright);
		    if (isnothead (p)) setlext (p, newright);
		    // log_msg(LOG_DEBUG, "insert r %p: key type: %d, value type: %d", newright, newright->key.type, newright->val.type);
		    return newright;
		}
	}
    else
	{
	    mk_new_ext (newleft, key, val);
	    insert (newleft, n);
	    setnormal (n);
	    mk_new_int (newleft, n, n->parent, isleft (n));
	    p = lprev (newleft);
	    if (isnothead (p)) setrext (p, newleft);
	    // log_msg(LOG_DEBUG, "insert l %p: key type: %d, value type: %d", newleft, newleft->key.type, newleft->val.type);
	    return newleft;
	}
}

void recolor (np_jrb_t* n)
{
	assert(n   != NULL);

	np_jrb_t *p, *gp, *s;
    int done = 0;

    while (!done)
	{
	    if (isroot (n))
		{
		    setblack (n);
		    return;
		}

	    p = n->parent;

	    if (isblack (p)) return;

	    if (isroot (p))
		{
		    setblack (p);
		    return;
		}

	    gp = p->parent;
	    s = sibling (p);
	    if (isred (s))
		{
		    setblack (p);
		    setred (gp);
		    setblack (s);
		    n = gp;
		}
	    else
		{
		    done = 1;
		}
	}

    /* p's sibling is black, p is red, gp is black */
    if ((isleft (n) == 0) == (isleft (p) == 0))
	{
	    single_rotate (gp, isleft (n));
	    setblack (p);
	    setred (gp);
	}
    else
	{
	    single_rotate (p, isleft (n));
	    single_rotate (gp, isleft (n));
	    setblack (n);
	    setred (gp);
	}
}

void single_rotate (np_jrb_t* y, int l)
{
	assert(y   != NULL);

	int rl, ir;
    np_jrb_t *x, *yp;

    ir = isroot (y);
    yp = y->parent;
    if (!ir)
	{
	    rl = isleft (y);
	}

    if (l)
	{
	    x = y->flink;
	    y->flink = x->blink;
	    setleft (y->flink);
	    y->flink->parent = y;
	    x->blink = y;
	    setright (y);
	}
    else
	{
	    x = y->blink;
	    y->blink = x->flink;
	    setright (y->blink);
	    y->blink->parent = y;
	    x->flink = y;
	    setleft (y);
	}

    x->parent = yp;
    y->parent = x;
    if (ir)
	{
	    yp->parent = x;
	    setnormal (y);
	    setroot (x);
	}
    else
	{
	    if (rl)
		{
		    yp->flink = x;
		    setleft (x);
		}
	    else
		{
		    yp->blink = x;
		    setright (x);
		}
	}
}

void jrb_delete_node (np_jrb_t* n)
{
	assert(n   != NULL);

	if (n == NULL)
		return;

    np_jrb_t *s, *p, *gp;
    char ir;

    if (isint (n))
	{
	    log_msg(LOG_WARN, "Cannot delete an internal node: %p %x", n, n->jrb_type);
    	return;
	}

    if (ishead (n))
	{
	    log_msg(LOG_WARN, "Cannot delete the head of an jrb_tree: %p %x", n, n->jrb_type);
    	return;
	}

    // TODO: check if this is working
    s = n;
    while (isnothead (s)) s = s->parent;
    s->size--;
    s->byte_size -= jrb_get_byte_size(n);

    // delete the string key object (created with strndup)
    // if (n->key.type == char_ptr_type)
    // free (n->key.value.s);

    delete_item (n);	/* Delete it from the list */
    p = n->parent;		/* The only node */
    if (isroot (n))
	{
	    p->parent = p;
	    free (n);
	    return;
	}
    s = sibling (n);		/* The only node after deletion */
    if (isroot (p))
	{
	    s->parent = p->parent;
	    s->parent->parent = s;
	    setroot (s);
	    free (p);
	    free (n);
	    return;
	}
    gp = p->parent;		/* Set parent to sibling */
    s->parent = gp;
    if (isleft (p))
	{
	    gp->flink = s;
	    setleft (s);
	}
    else
	{
	    gp->blink = s;
	    setright (s);
	}
    ir = isred (p);
    free (p);
    free (n);

    if (isext (s))
	{			/* Update proper rext and lext values */
	    p = lprev (s);
	    if (isnothead (p))
		setrext (p, s);
	    p = rprev (s);
	    if (isnothead (p))
		setlext (p, s);
	}
    else if (isblack (s))
	{
	    log_msg(LOG_WARN,"DELETION PROB -- sib is black, internal");
	    return;
	}
    else
	{
	    p = lprev (s);
	    if (isnothead (p))
		setrext (p, s->flink);
	    p = rprev (s);
	    if (isnothead (p))
		setlext (p, s->blink);
	    setblack (s);
	    return;
	}

    if (ir) return;

    /* Recolor */

    n = s;
    p = n->parent;
    s = sibling (n);
    while (isblack (p) && isblack (s) && isint (s) &&
	   isblack (s->flink) && isblack (s->blink))
	{
	    setred (s);
	    n = p;
	    if (isroot (n)) return;
	    p = n->parent;
	    s = sibling (n);
	}

    if (isblack (p) && isred (s))
	{	/* Rotation 2.3b */
	    single_rotate (p, isright (n));
	    setred (p);
	    setblack (s);
	    s = sibling (n);
	}

    np_jrb_t *x, *z;
	char il;

	if (isext (s)) {
		log_msg(LOG_WARN, "DELETION ERROR: sibling not internal");
		return;
	}

	il = isleft (n);
	x = il ? s->flink : s->blink;
	z = sibling (x);

	if (isred (z)) {
		/* Rotation 2.3f */
		single_rotate (p, !il);
		setblack (z);
		if (isred (p))
		    setred (s);
		else
		    setblack (s);
		setblack (p);
	} else if (isblack (x)) {
		/* Recoloring only (2.3c) */
		if (isred (s) || isblack (p)) {
			log_msg(LOG_WARN, "DELETION ERROR: 2.3c not quite right");
			return;
		}
		setblack (p);
		setred (s);
		return;
	} else if (isred (p)) {
		/* 2.3d */
		single_rotate (s, il);
		single_rotate (p, !il);
		setblack (x);
		setred (s);
		return;
	} else {
		/* 2.3e */
		single_rotate (s, il);
		single_rotate (p, !il);
		setblack (x);
		return;
	}
}


void jrb_print_tree (np_jrb_t* t, int level)
{
	assert(t     != NULL);
	assert(level >= 0);

	int i;
    if (ishead (t) && t->parent == t)
	{
	    log_msg(LOG_INFO,"tree %p is empty", t);
	}
    else if (ishead (t))
	{
	    log_msg(LOG_DEBUG, "%0d head node: %p.  Root = %p", level, t, t->parent);
	    jrb_print_tree (t->parent, 0);
	}
    else
	{
	    if (isext (t))
		{
		    for (i = 0; i < level; i++) putchar (' ');

		    log_msg(LOG_DEBUG, "%0d ext  node: %p: %c,%c: p=%p, k=%s",
		    		level, t, isred (t) ? 'R' : 'B', isleft (t) ? 'l' : 'r',
		    		t->parent, t->key.value.s);
		}
	    else
		{
		    jrb_print_tree (t->flink, level + 2);
		    jrb_print_tree (t->blink, level + 2);

		    log_msg(LOG_DEBUG,"%0d int  node: %p: %c,%c: l=%p, r=%p, p=%p, lr=(%s,%s)",
		    		level, t, isred (t) ? 'R' : 'B', isleft (t) ? 'l' : 'r', t->flink,
		    		t->blink, t->parent, getlext (t)->key.value.s, getrext (t)->key.value.s);
		}
	}
}

void jrb_iprint_tree (np_jrb_t* t, int level)
{
	assert(t     != NULL);
	assert(level >= 0);

	// int i;
    if (ishead (t) && t->parent == t)
	{
	    printf ("tree %p is empty", t);
	}
    else if (ishead (t))
	{
	    log_msg(LOG_DEBUG, "%0d head node: %p. Root = %p, < = %p, > = %",
	    		level, t, t->parent, t->blink, t->flink);
	    jrb_iprint_tree (t->parent, 0);
	}
    else
	{
	    if (isext (t))
		{
		    log_msg(LOG_DEBUG,
		    		"%0d ext  node: %p: %c,%c: p=%p, <=%p, >=%p k=%d",
		    		level, t, isred (t) ? 'R' : 'B', isleft (t) ? 'l' : 'r', t->parent,
		    		t->blink, t->flink, t->key.value.i);
		}
	    else
		{
		    jrb_iprint_tree (t->flink, level + 2);
		    jrb_iprint_tree (t->blink, level + 2);
		    log_msg(LOG_DEBUG,
		    		"%0d int  node: %p: %c,%c: l=%p, r=%p, p=%p, lr=(%d,%d)",
		    		level, t, isred (t) ? 'R' : 'B', isleft (t) ? 'l' : 'r', t->flink,
		    		t->blink, t->parent, getlext (t)->key.value.i, getrext (t)->key.value.i);
		}
	}
}

int jrb_nblack (np_jrb_t* n)
{
	assert(n     != NULL);

	int nb = 0;
    if (ishead (n) || isint (n))
	{
	    log_msg (LOG_WARN, "jrb error: jrb_nblack called on a non-external node %p %x", n, n->jrb_type);
	    return nb;
	}
    while (isnothead (n))
	{
	    if (isblack (n)) nb++;
	    n = n->parent;
	}
    return nb;
}

int jrb_plength (np_jrb_t* n)
{
	assert(n     != NULL);

	int pl = 0;
    if (ishead (n) || isint (n))
	{
	    log_msg (LOG_WARN, "jrb error: jrb_plength called on a non-external node %p %x", n, n->jrb_type);
	    return pl;
	}
    while (isnothead (n))
	{
	    pl++;
	    n = n->parent;
	}
    return pl;
}

void jrb_free_tree (np_jrb_t* n)
{
	assert(n     != NULL);

	if (isnothead (n))
	{
	    log_msg (LOG_WARN, "ERROR: jrb_free_tree called on a non-head node %p %x", n, n->jrb_type);
	    return;
	}

    if (n->size > 0) {
    	while (jrb_first (n) != jrb_nil (n))
    	{
    		jrb_delete_node (jrb_first (n));
    	}
    }
    free (n);
}

void jrb_replace_all_with_str(np_jrb_t* n, const char* key, np_jval_t val)
{
	assert(n     != NULL);
	assert(key   != NULL);

	if (isnothead (n))
	{
	    log_msg (LOG_WARN, "ERROR: jrb_free_tree called on a non-head node %p %x", n, n->jrb_type);
	    return;
	}

    if (n->size > 0) {
    	while (jrb_first (n) != jrb_nil (n))
    	{
    		jrb_delete_node (jrb_first (n));
    	}
    }
    jrb_insert_str(n, key, val);
}

np_jval_t jrb_val (np_jrb_t* n)
{
	assert(n     != NULL);
    return n->val;
}

long long jrb_get_byte_size(np_jrb_t* node)
{
	assert(node  != NULL);

	// if (isint(node)) return 0;

	// log_msg(LOG_DEBUG, "c: %p -> key/value size calculation", node);

	long long byte_size = 0;
	switch(node->key.type) {
		// length is always 1 (to identify the type) + the length of the type
//  		case short_type: 		  byte_size += 1 + sizeof(short); break;
		case int_type: 			  byte_size += 1 + sizeof(int16_t); break;
		case long_type: 		  byte_size += 1 + sizeof(int32_t); break;
		case long_long_type:	  byte_size += 1 + sizeof(int64_t); break;
 		case float_type: 		  byte_size += 1 + sizeof(float); break;
		case double_type: 		  byte_size += 1 + sizeof(double); break;
		case char_ptr_type: 	  byte_size += 1 + sizeof(uint32_t) + node->key.size; break;
		case char_type: 		  byte_size += 1 + sizeof(char); break;
		case unsigned_char_type:  byte_size += 1 + sizeof(unsigned char); break;
// 		case unsigned_short_type: byte_size += 1 + sizeof(unsigned short); break;
		case unsigned_int_type:   byte_size += 1 + sizeof(uint16_t); break;
		case unsigned_long_type:  byte_size += 1 + sizeof(uint32_t); break;
		case unsigned_long_long_type:  byte_size += 1 + sizeof(uint64_t); break;
// 		case int_array_2_type:    byte_size += 1 + 2*sizeof(int); break;
// 		case float_array_2_type:  byte_size += 1 + 2*sizeof(float); break;
// 		case char_array_8_type:   byte_size += 1 + 8*sizeof(char); break;
// 		case unsigned_char_array_8_type: byte_size += 1 +8*sizeof(unsigned char); break;
// 		case void_type: 		  byte_size += 1 + sizeof(void*); break;
// 		case bin_type: 			  byte_size += 1 + node->key.size; break;
// 		case jrb_tree_type:       byte_size += jrb_get_byte_size(node->key.value.tree); break;
		case key_type:            byte_size += 1 + (4 * sizeof(unsigned long)); break;
		default:                  log_msg(LOG_WARN, "unsupported length calculation for key type %d", node->key.type); break;
	}
	assert(byte_size  >= 2);
	// log_msg(LOG_DEBUG, "key size (%d) calculated to %d", node->key.type, byte_size);

	switch(node->val.type) {
//  		case short_type: 		  byte_size += 1 + sizeof(short); break;
		case int_type: 			  byte_size += 1 + sizeof(int16_t); break;
		case long_type: 		  byte_size += 1 + sizeof(int32_t); break;
		case long_long_type:	  byte_size += 1 + sizeof(int64_t); break;
 		case float_type: 		  byte_size += 1 + sizeof(float); break;
		case double_type: 		  byte_size += 1 + sizeof(double); break;
		case char_ptr_type: 	  byte_size += 1 + sizeof(uint32_t) + node->val.size; break;
		case char_type: 		  byte_size += 1 + sizeof(char); break;
		case unsigned_char_type:  byte_size += 1 + sizeof(unsigned char); break;
// 		case unsigned_short_type: byte_size += 1 + sizeof(unsigned short); break;
		case unsigned_int_type:   byte_size += 1 + sizeof(uint16_t); break;
		case unsigned_long_type:  byte_size += 1 + sizeof(uint32_t); break;
		case unsigned_long_long_type:  byte_size += 1 + sizeof(uint64_t); break;
 		case int_array_2_type:    byte_size += 1 + 2*sizeof(int16_t); break;
 		case float_array_2_type:  byte_size += 1 + 2*sizeof(float); break;
 		case char_array_8_type:   byte_size += 1 + 8*sizeof(char); break;
 		case unsigned_char_array_8_type: byte_size += 1+8*sizeof(unsigned char); break;
 		case void_type: 		  byte_size += 1 + sizeof(void*); break;
 		case bin_type: 			  byte_size += 1 + sizeof(uint32_t) + node->val.size; break;
		case jrb_tree_type:       byte_size += 1 + node->val.size; break;
		case key_type:            byte_size += 1 + (4 * sizeof(unsigned long)); break;
		default:                  log_msg(LOG_WARN, "unsupported length calculation for value type %d", node->val.type ); break;
	}
	// log_msg(LOG_DEBUG, "value size (%d) calculated to %d", node->val.type, byte_size);
	// log_msg(LOG_DEBUG, "c: %p -> key/value size calculated to %d", node, byte_size);
	assert(byte_size  >= 4);

	return byte_size;
}

extern np_jrb_t* jrb_insert_key (np_jrb_t *tree, np_key_t* key, np_jval_t val)
{
	assert(tree    != NULL);
	assert(key     != NULL);

	int fnd;

    np_jval_t k;
    k.value.key = key;
    k.type = key_type;

    np_jrb_t* ret_val = jrb_insert_b (jrb_find_gte_key (tree, key, &fnd), k, val);
    // log_msg(LOG_DEBUG, "%p: key type: %d, value type: %d", ret_val, ret_val->key.type, ret_val->val.type);

    tree->size++;
    tree->byte_size += jrb_get_byte_size(ret_val);
    return ret_val;
}

np_jrb_t* jrb_insert_str (np_jrb_t* tree, const char *key, np_jval_t val)
{
	assert(tree    != NULL);
	assert(key     != NULL);

	np_jval_t k;
    int fnd;
    // log_msg(LOG_DEBUG, "inserting new string jrb node, key is: %s (%d)", key, strlen(key));
    // k.value.s = key;
    k.value.s = strndup(key, 255);
    k.type = char_ptr_type;
    k.size = strlen(key);

    // log_msg(LOG_DEBUG, "inserting %p: key type: %d, value type: %d", tree, tree->key.type, tree->val.type);
    np_jrb_t* ret_val = jrb_insert_b (jrb_find_gte_str (tree, key, &fnd), k, val);
    // log_msg(LOG_DEBUG, "inserted  %p: key type: %d, value type: %d", ret_val, ret_val->key.type, ret_val->val.type);
    // log_msg(LOG_DEBUG, "inserted  %p: blink: %p, flink: %p parent: %p", tree, tree->blink, tree->flink, tree->parent);

    tree->size++;
    tree->byte_size += jrb_get_byte_size(ret_val);
    return ret_val;
}

np_jrb_t* jrb_insert_int (np_jrb_t* tree, int ikey, np_jval_t val)
{
	assert(tree    != NULL);

	np_jval_t k;
    int fnd;

    k.value.i = ikey;
    k.type = int_type;

    np_jrb_t* ret_val = jrb_insert_b (jrb_find_gte_int (tree, ikey, &fnd), k, val);
    // log_msg(LOG_DEBUG, "%p: key type: %d, value type: %d", ret_val, ret_val->key.type, ret_val->val.type);

    tree->size++;
    // log_msg(LOG_DEBUG, "should: key type: %d, value type: %d", k.type, val.type);
    tree->byte_size += jrb_get_byte_size(ret_val);
    // log_msg(LOG_DEBUG, "%p / s: %d -> bs: %d -> vs: %d -> sts: %d (%d)", tree, tree->size, tree->byte_size, val.size, ret_val->val.value.tree->size, ret_val->val.value.tree->byte_size);
    return ret_val;
}

np_jrb_t* jrb_insert_ulong (np_jrb_t* tree, unsigned long ulkey, np_jval_t val)
{
	assert(tree    != NULL);

	np_jval_t k;
    int fnd;

    k.value.ul = ulkey;
    k.type = unsigned_long_type;
    np_jrb_t* ret_val = jrb_insert_b (jrb_find_gte_ulong (tree, ulkey, &fnd), k, val);
    // log_msg(LOG_DEBUG, "%p: key type: %d, value type: %d", ret_val, ret_val->key.type, ret_val->val.type);
    tree->size++;
    tree->byte_size += jrb_get_byte_size(ret_val);
    return ret_val;
}

np_jrb_t* jrb_insert_dbl (np_jrb_t* tree, double dkey, np_jval_t val)
{
	assert(tree    != NULL);

	np_jval_t k;
    int fnd;

    k.value.d = dkey;
    k.type = double_type;
    np_jrb_t* ret_val = jrb_insert_b (jrb_find_gte_dbl (tree, dkey, &fnd), k, val);
    // log_msg(LOG_DEBUG, "%p: key type: %d, value type: %d", ret_val, ret_val->key.type, ret_val->val.type);
    tree->size++;
    tree->byte_size += jrb_get_byte_size(ret_val);
    return ret_val;
}

np_jrb_t* jrb_insert_gen (np_jrb_t* tree, np_jval_t key, np_jval_t val, int (*func) (np_jval_t, np_jval_t))
{
	assert(tree    != NULL);

	int fnd;
    np_jrb_t* ret_val = jrb_insert_b (jrb_find_gte_gen (tree, key, func, &fnd), key, val);
    // log_msg(LOG_DEBUG, "%p: key type: %d, value type: %d", ret_val, ret_val->key.type, ret_val->val.type);
    tree->size++;
    tree->byte_size += jrb_get_byte_size(ret_val);
    return ret_val;
}

