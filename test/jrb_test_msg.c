
#include <uuid/uuid.h>
#include <assert.h>

#include "pthread.h"

#include "np_memory.h"
#include "message.h"
#include "jrb.h"
#include "jval.h"
#include "cmp.h"
#include "log.h"
#include "np_util.h"

#include "include.h"


int main(int argc, char **argv) {

	char log_file[256];
	sprintf(log_file, "%s.log", "./jrb_test_msg");
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_ROUTING | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	log_init(log_file, level);

	np_jrb_t* test_jrb = make_jrb();

	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb->size, test_jrb->byte_size);
    cmp_ctx_t cmp_empty;
    char empty_buffer[NP_MESSAGE_SIZE];
    void* empty_buf_ptr = empty_buffer;
    memset(empty_buf_ptr, 0, NP_MESSAGE_SIZE);

    cmp_init(&cmp_empty, empty_buf_ptr, buffer_reader, buffer_writer);
	serialize_jrb_node_t(test_jrb, &cmp_empty);

	// np_jrb_t* node = NULL;
	// cmp_write_array(&cmp_empty, 1);
	// if (!cmp_write_map(&cmp_empty, test_jrb->size*2 )) log_msg(LOG_WARN, cmp_strerror(&cmp_empty));
	// node = test_jrb;
	// log_msg(LOG_DEBUG, "for %p; %p!=%p; %p=%p", test_jrb->flink, node, test_jrb, node, node->flink);
	//	jrb_traverse(node, test_jrb) {
	//		log_msg(LOG_INFO, "serializing now: %s", node->key.value.s);
	//		serialize_jrb_node_t(node, &cmp_empty);
	//	}
	// free (empty_buffer);
	jrb_free_tree(test_jrb);

	test_jrb = make_jrb();
	char* from = "from";
	char* to = "to";
	char* id = "id";
	char* exp = "exp";
	char* mail = "mail";

	char* me = "me";
	char* you = "you";
	char* mail_t = "signed.by.me@test.de";

	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb->size, test_jrb->byte_size);
	jrb_insert_str(test_jrb, from, new_jval_s(me));
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb->size, test_jrb->byte_size);
	jrb_insert_str(test_jrb, to,   new_jval_s(you));
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb->size, test_jrb->byte_size);
	jrb_insert_str(test_jrb, id,   new_jval_i(18000));
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb->size, test_jrb->byte_size);
	jrb_insert_str(test_jrb, exp,  new_jval_d(5.0));
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb->size, test_jrb->byte_size);
	jrb_insert_str(test_jrb, mail, new_jval_s(mail_t));
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb->size, test_jrb->byte_size);

	// log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb->size, test_jrb->byte_size);
	log_msg(LOG_INFO, "----------------------");
	log_msg(LOG_INFO, "serializing message:  ");

    cmp_ctx_t cmp;
    void* buffer = malloc(NP_MESSAGE_SIZE);
    memset(buffer, 0, NP_MESSAGE_SIZE);

    cmp_init(&cmp, buffer, buffer_reader, buffer_writer);
	serialize_jrb_node_t(test_jrb, &cmp);

	log_msg(LOG_INFO, "serialized message is: %p %s (size: %d)", buffer, buffer, cmp.buf-buffer);
	log_msg(LOG_INFO, "----------------------");
	log_msg(LOG_INFO, "deserializing message:");

	np_jrb_t* out_jrb = make_jrb();
	cmp_ctx_t cmp_out;
	// int cmp_err_out;
	cmp_init(&cmp_out, buffer, buffer_reader, buffer_writer);

	// unsigned int map_size = 0;
	// cmp_err_out = cmp_read_map(&cmp_out, &map_size);
	// if (!cmp_err_out) log_msg(LOG_WARN, cmp_strerror(&cmp_out));
	// log_msg(LOG_INFO, "deserialized buffer contains %d elements", map_size);
	deserialize_jrb_node_t(out_jrb, &cmp_out);

	log_msg(LOG_INFO, "deserialized tree is: %p (size %d)", out_jrb, out_jrb->size);
	log_msg(LOG_INFO, "id: %d", jrb_find_str(out_jrb, "id")->val.value.i);
	log_msg(LOG_INFO, "from: %s", jrb_find_str(out_jrb, "from")->val.value.s);
	log_msg(LOG_INFO, "mail: %s", jrb_find_str(out_jrb, "mail")->val.value.s);
	log_msg(LOG_INFO, "to: %s", jrb_find_str(out_jrb, "to")->val.value.s);
	log_msg(LOG_INFO, "exp: %f", jrb_find_str(out_jrb, "exp")->val.value.d);

	log_msg(LOG_INFO, "----------------------");
	log_msg(LOG_INFO, "out jrb has size: %d %d", out_jrb->size, out_jrb->byte_size);
	log_msg(LOG_INFO, "removing entries from jrb message:");

	jrb_delete_node(jrb_find_str(out_jrb, "from"));
	np_jrb_t* test = jrb_find_str(out_jrb, "from");
	if(test == NULL) log_msg(LOG_INFO, "deleted node not found");
	log_msg(LOG_INFO, "out jrb has size: %d %d", out_jrb->size, out_jrb->byte_size);




	log_msg(LOG_INFO, "----------------------");
	np_message_t* msg;
	np_obj_t* o_msg;
	np_new(np_message_t, o_msg);
	np_bind(np_message_t, o_msg, msg);

	// TODO:
	// strange behaviour: msg->header->flink points to somewhere else, although it was never modified
	// np_message_create_empty simply call make_jrb() (see test case #1 in this file)
	// !!!
	log_msg(LOG_DEBUG, "now serializing message #1 (%p: %p->%p)", msg, msg->header, msg->header->flink);

	char send_buffer[120000];
	void* send_buf_ptr = send_buffer;
	unsigned long send_buf_len;

	log_msg(LOG_DEBUG, "now serializing message #1 (%p->%p)", msg->header, msg->header->flink);
	np_message_serialize(msg, send_buf_ptr, &send_buf_len);

	jrb_insert_str(msg->instructions, "_np.ack", new_jval_i(1));
	jrb_insert_str(msg->instructions, "_np.seq", new_jval_ul(2));
	jrb_insert_str(msg->instructions, "_np.part", new_jval_i(3));

	// char send_buffer[120000];
	// void* send_buf_ptr = send_buffer;
	// unsigned long send_buf_len;

	log_msg(LOG_DEBUG, "now serializing message #2");
	np_message_serialize(msg, send_buf_ptr, &send_buf_len);

}
