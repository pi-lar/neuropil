//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <criterion/criterion.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../test_macros.c"
#include "msgpack/cmp.h"
#include "pthread.h"

#include "neuropil_log.h"

#include "util/np_tree.h"

#include "np_aaatoken.h"
#include "np_dhkey.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_node.h"
#include "np_types.h"
#include "np_util.h"

TestSuite(np_node_t);

Test(np_node_t,
     _node_create,
     .description = "test the creation of node structure") {
  CTX() {
    np_node_t *new_node_1 = NULL;
    np_new_obj(np_node_t, new_node_1);

    log_debug(LOG_DEBUG, NULL, "creating 1st key/node");
    _np_node_update(new_node_1, IPv4 | UDP, "localhost", "1111");

    np_aaatoken_t *node_token_1 = _np_token_factory_new_node_token(context);
    np_node_t *node_1 = _np_node_from_token(node_token_1, node_token_1->type);

    np_node_t *node_key_2 =
        _np_node_decode_from_str(context,
                                 "e596f97cec7761a0a228451b4fa69b1f0cf7409ad5b83"
                                 "0b173c2f264c97a0522:udp4:localhost:2222");

    np_node_t *node_key_3 = _np_node_decode_from_str(
        context,
        "e596f97cec7761a0a228451b4fa69b1f0cf7409ad5b830b173c2f264c97a0522:udp4:"
        "fd00::101c:e90f:f6d7:1077:2222");
  }
}

Test(np_node_t,
     _node_list_serialize,
     .description = "test the serialization of a node list") {
  /*	CTX() {
          // _np_node_encode_to_str
          np_sll_t(np_node_ptr, node_list);
          sll_init(np_node_ptr, node_list);

          np_dhkey_t* key1 = dhkey_create_from_hostport("test1.pi-lar.net", 0);
          sll_append(np_node_ptr, node_list, key1);

          np_node_update(node_list[0], "test1.pi-lar.net", 0);

      log_msg(LOG_DEBUG, NULL, "creating 2nd key/node");
      np_dhkey_t* key2 = dhkey_create_from_hostport("test2.pi-lar.net", 0);
          node_list[1] = np_node_lookup(nc, key2, 0);
          np_node_update(node_list[1], "test2.pi-lar.net", 0);

      log_msg(LOG_DEBUG, NULL, "creating 3rd key/node");
      np_dhkey_t* key3 = dhkey_create_from_hostport("test3.pi-lar.net", 0);
          node_list[2] = np_node_lookup(nc, key3, 0);
          np_node_update(node_list[2], "test3.pi-lar.net", 0);

      log_msg(LOG_DEBUG,NULL,  "creating 4th key/node");
      np_dhkey_t* key4 = dhkey_create_from_hostport("test4.pi-lar.net", 0);
          node_list[3] = np_node_lookup(nc, key4, 0);
          np_node_update(node_list[3], "test4.pi-lar.net", 0);

      log_msg(LOG_DEBUG, NULL, "serializing");
          np_tree_t* node_jrb = np_tree_create();
          _np_encode_nodes_to_jrb(node_jrb, node_list, true);

          cmp_ctx_t cmp;
      void* buffer = malloc(node_jrb->byte_size);
      memset(buffer, 0, node_jrb->byte_size);
      cmp_init(&cmp, buffer, buffer_reader, buffer_writer);
      serialize_jrb_node_t(node_jrb, &cmp);

          np_jrb_t* out_tree = make_jrb();
          cmp_ctx_t out_cmp;

          log_msg(LOG_DEBUG, NULL, "deserializing");
          cmp_init(&out_cmp, buffer, buffer_reader, buffer_writer);
          deserialize_jrb_node_t(out_tree, &out_cmp);
          np_decode_nodes_from_jrb(out_nc, node_jrb);
          }
  */
}
