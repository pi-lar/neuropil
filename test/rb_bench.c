#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#define NDEBUG
#include <assert.h>
#include "tree/tree.h"

#define NNODES 1500
#define NSETS 25
#define NSEARCH 0
#define NITER 0

//#define VERBOSE

typedef struct node_s node_t;

struct node_s {
#define NODE_MAGIC 0x9823af7e
	uint32_t magic;
	RB_ENTRY(node_s) link;
	long key;
};
typedef struct tree_s tree_t;
RB_HEAD(tree_s, node_s);

static inline int nodeCmpEq(node_t *aA, node_t *aB) {
	assert(aA->magic == NODE_MAGIC);
	assert(aB->magic == NODE_MAGIC);
	return (aA->key > aB->key) - (aA->key < aB->key);
}

static inline int nodeCmpIdent(node_t *aA, node_t *aB) {
	int rVal = nodeCmpEq(aA, aB);
	if (rVal == 0) {
		// Duplicates are not allowed in the tree, so force an arbitrary
		// ordering for non-identical items with equal keys.
		rVal = (((uintptr_t) aA) > ((uintptr_t) aB))
				- (((uintptr_t) aA) < ((uintptr_t) aB));
	}
	return rVal;
}

RB_GENERATE_STATIC(tree_s, node_s, link, nodeCmpIdent);

static unsigned treeIterate(tree_t *aTree) {
	unsigned i;
	node_t *node, *sNode, key;

	i = 0;
	node = RB_MIN(tree_s, aTree);
	while (node != NULL) {
		assert(node->magic == NODE_MAGIC);

		/* Test rb_search(). */
		key.key = node->key;
		key.magic = NODE_MAGIC;
		sNode = RB_FIND(tree_s, aTree, &key);
		assert(sNode != NULL);
		assert(sNode->key == key.key);

		/* Test rb_nsearch(). */
		sNode = RB_NFIND(tree_s, aTree, &key);
		assert(sNode != NULL);
		assert(sNode->key == key.key);

		i++;
		node = RB_NEXT(tree_s, aTree, node);
	}

	return i;
}

static unsigned treeIterateReverse(tree_t *aTree) {
	unsigned i;
	node_t *node, *sNode, key;

	i = 0;
	node = RB_MAX(tree_s, aTree);
	while (node != NULL) {
		assert(node->magic == NODE_MAGIC);

		/* Test rb_search(). */
		key.key = node->key;
		key.magic = NODE_MAGIC;
		sNode = RB_FIND(tree_s, aTree, &key);
		;
		assert(sNode != NULL);
		assert(sNode->key == key.key);

		/* Test rb_nsearch(). */
		sNode = RB_NFIND(tree_s, aTree, &key);
		assert(sNode != NULL);
		assert(sNode->key == key.key);

		i++;
		node = RB_PREV(tree_s, aTree, node);
	}

	return i;
}

int main(void) {
	tree_t tree;
	long set[NNODES];
	node_t nodes[NNODES], key, *sNode;
	unsigned i, j, k, l, m;

	srandom(42);
	for (i = 0; i < NSETS; i++) {
		for (j = 0; j < NNODES; j++) {
			set[j] = (long) (((double) NNODES)
					* ((double) random() / ((double) RAND_MAX)));
		}

		for (j = 1; j <= NNODES; j++) {
#ifdef VERBOSE
			fprintf(stderr, "Tree %u, %u node%s\n", i, j, j != 1 ? "s" : "");
#endif

			/* Initialize tree and nodes. */
			RB_INIT(&tree);
			for (k = 0; k < j; k++) {
				nodes[k].magic = NODE_MAGIC;
				nodes[k].key = set[k];
			}

			/* Insert nodes. */
			for (k = 0; k < j; k++) {
				RB_INSERT(tree_s, &tree, &nodes[k]);

				for (l = 0; l < NSEARCH; l++) {
					for (m = 0; m <= k; m++) {
						sNode = RB_MIN(tree_s, &tree);
						sNode = RB_MAX(tree_s, &tree);

						key.key = nodes[m].key;
						key.magic = NODE_MAGIC;
						sNode = RB_FIND(tree_s, &tree, &key);
						sNode = RB_NFIND(tree_s, &tree, &key);
					}
				}
			}

			for (k = 0; k < NITER; k++) {
				treeIterate(&tree);
				treeIterateReverse(&tree);
			}

			/* Remove nodes. */
			for (k = 0; k < j; k++) {
				for (l = 0; l < NSEARCH; l++) {
					for (m = 0; m <= k; m++) {
						sNode = RB_MIN(tree_s, &tree);
						sNode = RB_MAX(tree_s, &tree);

						key.key = nodes[m].key;
						key.magic = NODE_MAGIC;
						sNode = RB_FIND(tree_s, &tree, &key);
						sNode = RB_NFIND(tree_s, &tree, &key);
					}
				}

				RB_REMOVE(tree_s, &tree, &nodes[k]);

				nodes[k].magic = 0;
			}
		}
	}

	return 0;
}
