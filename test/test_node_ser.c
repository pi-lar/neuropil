

#include "node.h"
#include "key.h"
#include "jrb.h"
#include "log.h"

int main(int argc, char **argv) {

	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_ROUTING | LOG_NETWORKDEBUG | LOG_KEYDEBUG;

	log_init("test_node_ser.log", log_level);

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
	np_jrb_t* node_jrb = make_jrb();
	np_encode_nodes_to_amqp(node_jrb, node_list);

    log_msg(LOG_DEBUG, "deserializing");
	np_decode_nodes_from_amqp(nc, node_jrb);

}
