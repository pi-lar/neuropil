#include <stdlib.h>
#include "pthread.h"

#include "np_memory.h"
#include "np_node.h"
#include "np_key.h"
#include "np_tree.h"
#include "np_log.h"
#include "cmp.h"
#include "np_util.h"

#include "include.h"

int main(int argc, char **argv) {

	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_ROUTING | LOG_NETWORKDEBUG | LOG_KEYDEBUG;

	log_init("test_node_ser.log", log_level);

	np_tree_t* test_jrb = make_jtree();
	tree_insert_str(test_jrb, "test", new_val_s("test"));

	np_val_t t1;
	np_val_t t2 = new_val_tree(test_jrb);

	t1 = t2;
	log_msg(LOG_DEBUG, "%p np_val_t t1: %d %d %p", test_jrb, t1.type, t1.size, t1.value.tree);

	np_nodecache_t* nc = np_node_cache_create(5);
    np_node_t** node_list = (np_node_t **) malloc (sizeof (np_node_t *)*5);

    log_msg(LOG_DEBUG, "creating 1st key/node");
	np_key_t* key1 = key_create_from_hostport("test1.pi-lar.net", 0);
	node_list[0] = np_node_lookup(nc, key1, 0);
	np_node_update(node_list[0], "test1.pi-lar.net", 0);

    log_msg(LOG_DEBUG, "creating 2nd key/node");
	np_key_t* key2 = key_create_from_hostport("test2.pi-lar.net", 0);
	node_list[1] = np_node_lookup(nc, key2, 0);
	np_node_update(node_list[1], "test2.pi-lar.net", 0);

    log_msg(LOG_DEBUG, "creating 3rd key/node");
	np_key_t* key3 = key_create_from_hostport("test3.pi-lar.net", 0);
	node_list[2] = np_node_lookup(nc, key3, 0);
	np_node_update(node_list[2], "test3.pi-lar.net", 0);

    log_msg(LOG_DEBUG, "creating 4th key/node");
	np_key_t* key4 = key_create_from_hostport("test4.pi-lar.net", 0);
	node_list[3] = np_node_lookup(nc, key4, 0);
	np_node_update(node_list[3], "test4.pi-lar.net", 0);

    log_msg(LOG_DEBUG, "serializing");
	np_tree_t* node_jrb = make_jree();
	np_encode_nodes_to_jrb(node_jrb, node_list, TRUE);

	cmp_ctx_t cmp;
    void* buffer = malloc(node_jrb->byte_size);
    memset(buffer, 0, node_jrb->byte_size);
    cmp_init(&cmp, buffer, buffer_reader, buffer_writer);
    serialize_jrb_node_t(node_jrb, &cmp);

	np_nodecache_t* out_nc = np_node_cache_create(5);
	np_jrb_t* out_tree = make_jrb();
	cmp_ctx_t out_cmp;

	log_msg(LOG_DEBUG, "deserializing");
	cmp_init(&out_cmp, buffer, buffer_reader, buffer_writer);
	deserialize_jrb_node_t(out_tree, &out_cmp);
	np_decode_nodes_from_jrb(out_nc, node_jrb);

}
