//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#ifdef NP_USE_CMP

#include "msgpack/cmp.c"

size_t
buffer_writer_counter(struct cmp_ctx_s *ctx, const void *data, size_t count);
size_t
buffer_writer_counter(struct cmp_ctx_s *ctx, const void *data, size_t count) {
  total_write_count += count;
  return __np_buffer_writer(ctx, data, count);
}
bool buffer_reader_counter(struct cmp_ctx_s *ctx, void *data, size_t limit);
bool buffer_reader_counter(struct cmp_ctx_s *ctx, void *data, size_t limit) {
  total_read_count += limit;
  return __np_buffer_reader(ctx, data, limit);
}

TestSuite(test_serialization_cmp);

Test(test_serialization_cmp,
     serialize_np_dhkey_t,
     .description = "test the serialization of a dhkey") {
  CTX() {
    cmp_ctx_t cmp_read;
    cmp_ctx_t cmp_write;

    char  buffer[512];
    void *buffer_ptr = buffer;

    cr_log_info("buffer_ptr\t\t %p\n", buffer_ptr);
    memset(buffer_ptr, 0, 512);
    reset_buffer_counter();

    cmp_init(&cmp_write,
             buffer_ptr,
             buffer_reader_counter,
             NULL,
             buffer_writer_counter);

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

    __np_tree_serialize_write_type(context, val, &cmp_write);

    cr_assert(cmp_write.error == ERROR_NONE,
              "expect no error on write. But is: %" PRIu8,
              cmp_write.error);

    // 8 * (marker of uint32 + content of uint32)
    uint32_t expected_obj_size = (8 * (sizeof(uint8_t) + sizeof(uint32_t)));

    // marker EXT32  + size of EXT32    + type of EXT32
    uint32_t expected_write_size = (sizeof(uint8_t) + sizeof(uint32_t) +
                                    sizeof(uint8_t) + expected_obj_size);

    cr_expect(total_write_count == expected_write_size,
              "Expected write size is %d but is %d",
              expected_write_size,
              total_write_count);
    uint32_t expected_read_count = total_write_count;

    // Beginn reading section
    cmp_init(&cmp_read,
             buffer_ptr,
             buffer_reader_counter,
             NULL,
             buffer_writer_counter);
    reset_buffer_counter();

    cmp_object_t obj;
    np_treeval_t read_tst = {.type = np_treeval_type_undefined, .size = 0};
    cmp_read_object(&cmp_read, &obj);

    cr_assert(cmp_read.error == ERROR_NONE,
              "Expected no error on object read. But is: %" PRIu8,
              cmp_read.error);
    cr_assert(obj.type == CMP_TYPE_EXT32,
              "Expected obj to be of type CMP_TYPE_EXT32. But is: %" PRIu8,
              obj.type);
    cr_expect(obj.as.ext.type == np_treeval_type_dhkey,
              "Expected obj to be of type EXT type np_treeval_type_dhkey. But "
              "is: %" PRIu8,
              read_tst.type);
    cr_expect(obj.as.ext.size == expected_obj_size,
              "Expected obj to be of size %" PRIu32 ". But is: %" PRIu32,
              expected_obj_size,
              obj.as.ext.size);

    __np_tree_deserialize_read_type(context,
                                    np_tree_create(),
                                    &obj,
                                    &cmp_read,
                                    &read_tst,
                                    "test read");

    cr_assert(cmp_read.error == ERROR_NONE,
              "Expected no error on val read. But is: %" PRIu8,
              cmp_read.error);
    cr_expect(total_read_count == expected_read_count,
              "Expected read size is %" PRIu32 " but is %" PRIu32,
              expected_read_count,
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

#endif
