//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#ifdef NP_USE_QCBOR

#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"

#include "neuropil_attributes.h"

TestSuite(test_serialization_qcbor);

Test(test_serialization_qcbor,
     serialize_qcbor_np_dhkey_t,
     .description = "test the serialization of a dhkey") {
  CTX() {
    char  buffer[512];
    void *buffer_ptr = buffer;

    log_msg(LOG_INFO, NULL, "buffer_ptr\t\t %p\n", buffer_ptr);
    memset(buffer_ptr, 0, 512);

    struct q_useful_buf qmp_write       = {.ptr = buffer_ptr, .len = 512};
    QCBOREncodeContext  qcbor_ctx_write = {0};
    QCBOREncode_Init(&qcbor_ctx_write, qmp_write);

    np_dhkey_t tst;
    tst.t[0] = 1;
    tst.t[1] = 2;
    tst.t[2] = 3;
    tst.t[3] = 4;
    tst.t[4] = 5;
    tst.t[5] = 6;
    tst.t[6] = 7;
    tst.t[7] = 8;

    cr_expect(total_write_count == 0,
              "Expected empty buffer. But size is %" PRIu32,
              total_write_count);

    np_treeval_t val = np_treeval_new_dhkey(tst);
    cr_expect(val.type == np_treeval_type_dhkey,
              "Expected source val to be of type np_treeval_type_dhkey. But "
              "is: %" PRIu8,
              val.type);

    __np_tree_serialize_write_type(context, val, &qcbor_ctx_write);
    struct q_useful_buf_c out_buf = {0};
    QCBOREncode_Finish(&qcbor_ctx_write, &out_buf);

    cr_expect(qcbor_ctx_write.uError == 0,
              "expect no error on write. But is: %" PRIu8,
              qcbor_ctx_write.uError);

    // 8 * (marker of uint32 + content of uint32)
    uint32_t expected_obj_size = (8 * (sizeof(uint8_t) + sizeof(uint32_t)));
    // marker EXT32  + size of EXT32    + type of EXT32
    uint32_t expected_write_size = (sizeof(uint8_t) + sizeof(uint16_t) +
                                    sizeof(uint8_t) + expected_obj_size);

    cr_expect(out_buf.len == expected_write_size,
              "Expected write size is %d but is %d",
              expected_write_size,
              out_buf.len);
    uint32_t expected_read_count = out_buf.len;

    // Beginn reading section
    struct q_useful_buf_c qmp_read       = {.ptr = buffer_ptr, .len = 512};
    QCBORDecodeContext    qcbor_ctx_read = {0};
    QCBORDecode_Init(&qcbor_ctx_read, qmp_read, QCBOR_DECODE_MODE_NORMAL);

    //    QCBORDecode_VGetNext(&qcbor_ctx_read, &item);
    np_treeval_t read_tst = {.type = np_treeval_type_undefined, .size = 0};
    //    cr_expect(qcbor_ctx_read.uLastError == 0, "Expected no error on object
    //    read. But is: %"PRIu8, qcbor_ctx_read.uLastError);
    //    cr_expect(item.uDataType == QCBOR_TYPE_ARRAY, "Expected obj to be of
    //    type CMP_TYPE_EXT32. But is: %"PRIu8, item.uDataType);
    //    cr_expect(item.uTags[0] == (NP_CBOR_REGISTRY_ENTRIES +
    //    np_treeval_type_dhkey), "Expected obj to be of type EXT type
    //    np_treeval_type_dhkey. But is: %"PRIu8, read_tst.type);
    //    cr_expect(item.val.uCount == 8, "Expected array to have %"PRIu32"
    //    elements. But is has: %"PRIu32, 8, item.val.uCount);

    __np_tree_deserialize_read_type(context,
                                    np_tree_create(),
                                    &qcbor_ctx_read,
                                    &read_tst,
                                    "test read");

    QCBORError cbor_err = QCBORDecode_Finish(&qcbor_ctx_read);
    cr_expect(qcbor_ctx_read.uLastError == 0,
              "Expected no error on val read. But is: %" PRIu8,
              qcbor_ctx_read.uLastError);
    cr_expect(qcbor_ctx_read.InBuf.cursor == expected_read_count,
              "Expected read size is %" PRIu32 " but is %" PRIu32,
              qcbor_ctx_read.InBuf.cursor,
              total_read_count);

    cr_expect(read_tst.type == np_treeval_type_dhkey,
              "Expected read val to be of type np_treeval_type_dhkey. But is: "
              "%" PRIu8,
              read_tst.type);
    cr_expect(read_tst.size == sizeof(np_dhkey_t),
              "Expected val to be of dhkey size. But is: %" PRIu32,
              read_tst.size);
    cr_expect(read_tst.value.dhkey.t[0] == 1,
              "Expected read val value 0 to be the same as predefined, But is: "
              "%" PRIu32,
              read_tst.value.dhkey.t[0]);
    cr_expect(read_tst.value.dhkey.t[1] == 2,
              "Expected read val value 1 to be the same as predefined, But is: "
              "%" PRIu32,
              read_tst.value.dhkey.t[1]);
    cr_expect(read_tst.value.dhkey.t[2] == 3,
              "Expected read val value 2 to be the same as predefined, But is: "
              "%" PRIu32,
              read_tst.value.dhkey.t[2]);
    cr_expect(read_tst.value.dhkey.t[3] == 4,
              "Expected read val value 3 to be the same as predefined, But is: "
              "%" PRIu32,
              read_tst.value.dhkey.t[3]);
    cr_expect(read_tst.value.dhkey.t[4] == 5,
              "Expected read val value 4 to be the same as predefined, But is: "
              "%" PRIu32,
              read_tst.value.dhkey.t[4]);
    cr_expect(read_tst.value.dhkey.t[5] == 6,
              "Expected read val value 5 to be the same as predefined, But is: "
              "%" PRIu32,
              read_tst.value.dhkey.t[5]);
    cr_expect(read_tst.value.dhkey.t[6] == 7,
              "Expected read val value 6 to be the same as predefined, But is: "
              "%" PRIu32,
              read_tst.value.dhkey.t[6]);
    cr_expect(read_tst.value.dhkey.t[7] == 8,
              "Expected read val value 7 to be the same as predefined, But is: "
              "%" PRIu32,
              read_tst.value.dhkey.t[7]);
  }
}

Test(test_serialization_qcbor,
     serialize_qcbor_np_token,
     .description = "test the serialization of a np_token") {
  CTX() {

    bool            ret = true;
    char           *buffer[10240];
    struct np_token node_token    = {0};
    np_aaatoken_t  *node_aaatoken = _np_key_get_token(context->my_node_key);
    np_aaatoken4user(&node_token, node_aaatoken, false);
    np_set_ident_attr_bin(context,
                          &node_token,
                          NP_ATTR_INTENT_AND_IDENTITY,
                          "test",
                          "test",
                          4);

    size_t max_buffer_size = 10240;
    ret = np_serializer_write_nptoken(&node_token, buffer, &max_buffer_size);
    cr_expect(ret == true, "expect the result of the serialization to be true");

    memset(&node_token, 0, sizeof(struct np_token));
    ret = np_serializer_read_nptoken(buffer, &max_buffer_size, &node_token);

    struct np_data_conf  conf     = {0};
    struct np_data_conf *conf_ptr = &conf;
    char                *test;
    np_get_token_attr_bin(&node_token, "test", &conf_ptr, &test);

    cr_expect(strncmp(test, "test", 4) == 0,
              "expect the attribute value to be the same");

    np_aaatoken_t *read_token = NULL;
    np_new_obj(np_aaatoken_t, read_token);
    np_user4aaatoken(read_token, &node_token);

    cr_expect(strncmp(node_aaatoken->subject, read_token->subject, 255) == 0,
              "expect the subject to match");
    cr_expect(memcmp(node_aaatoken->uuid, read_token->uuid, NP_UUID_BYTES) == 0,
              "expect the uuid to match");
    cr_expect(ret == true, "expect the result of the serialization to be true");
  }
}

Test(test_serialization_qcbor,
     serialize_qcbor_np_handshake_t,
     .description = "test the serialization of a handshake token") {

  CTX() {
    struct np_e2e_message_s *hs_message = NULL;
    np_new_obj(np_message_t, hs_message);

    np_dhkey_t example = {.t[0] = 1,
                          .t[1] = 1,
                          .t[2] = 1,
                          .t[3] = 1,
                          .t[4] = 1,
                          .t[5] = 1,
                          .t[6] = 1,
                          .t[7] = 1};
    _np_message_create(hs_message, example, example, example, NULL);

    np_tree_t *jrb_body = np_tree_create();
    np_tree_t *msg_body = np_tree_create();
    // get our node identity from the cache
    np_handshake_token_t *my_token =
        _np_token_factory_new_handshake_token(context,
                                              UDP | IPv4,
                                              "127.0.0.1",
                                              "4000");

    np_aaatoken_encode(jrb_body, my_token);
    np_tree_insert_str(msg_body,
                       _NP_URN_HANDSHAKE_PREFIX,
                       np_treeval_new_cwt(jrb_body));
    _np_message_setbody(hs_message, msg_body);

    bool serialize_ok = _np_message_serialize_chunked(context, hs_message);

    _np_node_build_network_packet(hs_message->msg_chunks[0]);
    char *packet = hs_message->msg_chunks[0]->msg_chunk;

    struct np_n2n_messagepart_s *msg_part = NULL;
    np_new_obj(np_messagepart_t, msg_part);

    bool is_header_deserialization_successful =
        _np_message_deserialize_header_and_instructions(packet, msg_part);

    struct np_e2e_message_s *msg_in = NULL;
    np_new_obj(np_message_t, msg_in);

    uint16_t count_of_chunks = 0;
    _np_message_add_chunk(msg_in, msg_part, &count_of_chunks);

    cr_expect(is_header_deserialization_successful == true,
              "expect the header serialization to be successful");
    cr_expect(count_of_chunks == 1, "expect the number of chunks to be 1");

    bool is_deserialization_successful = _np_message_deserialize_chunks(msg_in);
    cr_expect(is_deserialization_successful == true,
              "expect the de-chunking to be successful");

    cr_expect(msg_in->state == msgstate_binary,
              "expect the message to be in state binary");

    _np_message_readbody(msg_in);
    cr_expect(msg_in->state == msgstate_raw,
              "expect the message to be in state raw");

    np_tree_t *hs_token =
        np_tree_find_str(msg_in->msg_body, _NP_URN_HANDSHAKE_PREFIX)
            ->val.value.tree;

    np_aaatoken_t *read_token = NULL;
    np_new_obj(np_aaatoken_t, read_token);

    np_aaatoken_decode(hs_token, read_token);

    struct np_data_conf conf        = {0};
    np_data_value       val_hs_prio = {0};
    cr_expect(
        np_data_ok ==
        np_get_data(read_token->attributes, NP_HS_PRIO, &conf, &val_hs_prio));
  }
}

#endif