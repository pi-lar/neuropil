//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "msgpack/cmp.h"

#include "util/np_serialization.h"

#include "np_log.h"
#include "np_util.h"

bool __np_buffer_reader(struct cmp_ctx_s *ctx, void *data, size_t limit) {
  // log_trace_msg(LOG_TRACE, "start: bool _np_buffer_reader(struct cmp_ctx_s
  // *ctx, void *data, size_t limit){");
  memmove(data, ctx->buf, limit);
  ctx->buf += limit;
  return true;
}

bool __np_buffer_skipper(struct cmp_ctx_s *ctx, size_t limit) {
  ctx->buf += limit;
  return true;
}

size_t
__np_buffer_writer(struct cmp_ctx_s *ctx, const void *data, size_t count) {
  // log_trace_msg(LOG_TRACE, "start: size_t _np_buffer_writer(struct cmp_ctx_s
  // *ctx, const void *data, size_t count){"); log_debug(LOG_DEBUG, NULL, "--
  // writing cmp->buf: %p size: %hd", ctx->buf, count); printf( "-- writing
  // cmp->buf: %p size: %hd\n", ctx->buf, count);
  memmove(ctx->buf, data, count);
  ctx->buf += count;
  return count;
}

uint8_t __np_tree_serialize_read_type_dhkey(cmp_ctx_t    *cmp_key,
                                            np_treeval_t *target) {
  log_trace_msg(LOG_TRACE,
                "start: uint8_t __np_tree_serialize_read_type_dhkey(void* "
                "buffer_ptr, np_treeval_t* target) {");

  // cmp_ctx_t cmp_key;
  // cmp_init(&cmp_key, buffer_ptr, _np_buffer_reader, _np_buffer_skipper,
  // _np_buffer_writer);

  np_dhkey_t empty_key = {0};
  np_dhkey_t new_key;

  target->value.dhkey = empty_key;
  target->type        = np_treeval_type_dhkey;
  target->size        = sizeof(np_dhkey_t);

  bool read_ok = true;
  read_ok &= cmp_read_u32(cmp_key, &(new_key.t[0]));
  read_ok &= cmp_read_u32(cmp_key, &(new_key.t[1]));
  read_ok &= cmp_read_u32(cmp_key, &(new_key.t[2]));
  read_ok &= cmp_read_u32(cmp_key, &(new_key.t[3]));
  read_ok &= cmp_read_u32(cmp_key, &(new_key.t[4]));
  read_ok &= cmp_read_u32(cmp_key, &(new_key.t[5]));
  read_ok &= cmp_read_u32(cmp_key, &(new_key.t[6]));
  read_ok &= cmp_read_u32(cmp_key, &(new_key.t[7]));

  if (read_ok) {
    target->value.dhkey = new_key;
  } else {
    if (cmp_key->error == 0 /*ERROR_NONE*/) {
      cmp_key->error = 14; // LENGTH_READING_ERROR;
    }
  }

  return cmp_key->error;
}

void __np_tree_serialize_write_type_dhkey(np_dhkey_t source,
                                          cmp_ctx_t *target) {
  log_trace_msg(LOG_TRACE,
                "start: void __np_tree_serialize_write_type_dhkey(np_dhkey_t "
                "source, cmp_ctx_t* target) {");
  // source->size is not relevant here as the transport size includes marker
  // sizes etc..
  //                        8 * (size of uint32 marker + size of key element)
  uint32_t transport_size = 8 * (sizeof(uint8_t) + sizeof(uint32_t));

  cmp_ctx_t key_ctx;
  char      buffer[transport_size];
  void     *buf_ptr = buffer;
  cmp_init(&key_ctx,
           buf_ptr,
           __np_buffer_reader,
           __np_buffer_skipper,
           __np_buffer_writer);

  bool write_ok = true;
  write_ok &= cmp_write_u32(&key_ctx, source.t[0]);
  write_ok &= cmp_write_u32(&key_ctx, source.t[1]);
  write_ok &= cmp_write_u32(&key_ctx, source.t[2]);
  write_ok &= cmp_write_u32(&key_ctx, source.t[3]);
  write_ok &= cmp_write_u32(&key_ctx, source.t[4]);
  write_ok &= cmp_write_u32(&key_ctx, source.t[5]);
  write_ok &= cmp_write_u32(&key_ctx, source.t[6]);
  write_ok &= cmp_write_u32(&key_ctx, source.t[7]);

  if (key_ctx.error == 0) {
    cmp_write_ext32(target, np_treeval_type_dhkey, transport_size, buf_ptr);
  } else {
    target->error = key_ctx.error;
  }
}

void __np_tree_serialize_write_type(np_state_t  *context,
                                    np_treeval_t val,
                                    cmp_ctx_t   *cmp) {
  log_trace_msg(LOG_TRACE,
                "start: void __np_tree_serialize_write_type(np_treeval_t val, "
                "cmp_ctx_t* cmp){");
  // void* count_buf_start = cmp->buf;
  // log_debug(LOG_DEBUG, NULL, "writing jrb (%p) value: %s", jrb,
  // jrb->key.value.s);
  switch (val.type) {
    // signed numbers
  case np_treeval_type_short:
    cmp_write_s8(cmp, val.value.sh);
    break;
  case np_treeval_type_int:
    cmp_write_s16(cmp, val.value.i);
    break;
  case np_treeval_type_long:
    cmp_write_s32(cmp, val.value.l);
    break;
#ifdef x64
  case np_treeval_type_long_long:
    cmp_write_s64(cmp, val.value.ll);
    break;
#endif
    // characters
  case np_treeval_type_char_ptr:
    // log_debug(LOG_DEBUG, NULL, "string size %u/%lu -> %s", val.size,
    cmp_write_str32(cmp,
                    val.value.s,
                    val.size + sizeof(char) /*include terminator*/);
    break;

  case np_treeval_type_char:
    cmp_write_fixstr(cmp, (const char *)&val.value.c, sizeof(char));
    break;
    //	case np_treeval_type_unsigned_char:
    //	 	cmp_write_str(cmp, (const char*) &val.value.uc, sizeof(unsigned
    // char)); 	 	break;

    // float and double precision
  case np_treeval_type_float:
    cmp_write_float(cmp, val.value.f);
    break;
  case np_treeval_type_double:
    cmp_write_double(cmp, val.value.d);
    break;

    // unsigned numbers
  case np_treeval_type_unsigned_short:
    cmp_write_u8(cmp, val.value.ush);
    break;
  case np_treeval_type_unsigned_int:
    cmp_write_u16(cmp, val.value.ui);
    break;
  case np_treeval_type_unsigned_long:
    cmp_write_u32(cmp, val.value.ul);
    break;
#ifdef x64
  case np_treeval_type_unsigned_long_long:
    cmp_write_u64(cmp, val.value.ull);
    break;
#endif
  case np_treeval_type_uint_array_2:
    cmp_write_fixarray(cmp, 2);
    cmp->write(cmp, &val.value.a2_ui[0], sizeof(uint16_t));
    cmp->write(cmp, &val.value.a2_ui[1], sizeof(uint16_t));
    break;

  case np_treeval_type_float_array_2:
  case np_treeval_type_char_array_8:
  case np_treeval_type_unsigned_char_array_8:
    log_msg(LOG_WARNING,
            NULL,
            "please implement serialization for type %" PRIu8,
            val.type);
    break;

  case np_treeval_type_void:
    log_msg(LOG_WARNING,
            NULL,
            "please implement serialization for type %" PRIu8,
            val.type);
    break;
  case np_treeval_type_bin:
    cmp_write_bin32(cmp, val.value.bin, val.size);
    break;
  case np_treeval_type_dhkey:
    __np_tree_serialize_write_type_dhkey(val.value.dhkey, cmp);
    break;
  case np_treeval_type_hash:
    // log_debug(LOG_DEBUG, NULL, "adding hash value %s to serialization",
    // val.value.s);
    cmp_write_ext32(cmp, np_treeval_type_hash, val.size, val.value.bin);
    break;

  case np_treeval_type_cose_signed:
  case np_treeval_type_cose_encrypted:
  case np_treeval_type_cwt:
  case np_treeval_type_jrb_tree: {
    // cmp_ctx_t tree_cmp = {0};
    // size_t buf_size = np_tree_get_byte_size(val.value.tree);
    size_t buf_size = val.value.tree->byte_size;
    // np_serializer_add_map_bytesize(val.value.tree, &buf_size);
    char buffer[buf_size];
    log_debug(LOG_SERIALIZATION | LOG_DEBUG,
              NULL,
              "write: buffer size for subtree %u (%hd %u) %u",
              val.size,
              val.value.tree->size,
              val.value.tree->byte_size,
              buf_size);
    np_serialize_buffer_t tree_serializer = {
        ._tree          = val.value.tree,
        ._target_buffer = buffer,
        ._buffer_size   = buf_size,
        ._error         = 0,
        ._bytes_written = 0,
    };
    np_serializer_write_map(context, &tree_serializer, val.value.tree);
    // write the serialized tree to the upper level buffer
    if (!cmp_write_ext32(cmp, val.type, buf_size, buffer)) {
      log_msg(LOG_WARNING,
              NULL,
              "couldn't write tree data -- ignoring for now");
    }
  } break;
  default:
    log_msg(LOG_WARNING,
            NULL,
            "please implement serialization for type %hhd",
            val.type);
    break;
  }
}

void __np_tree_deserialize_read_type(np_state_t     *context,
                                     np_tree_t      *tree,
                                     cmp_object_t   *obj,
                                     cmp_ctx_t      *cmp,
                                     np_treeval_t   *value,
                                     NP_UNUSED char *key_to_read_for) {
  log_trace_msg(LOG_TRACE,
                "start: void __np_tree_deserialize_read_type(cmp_object_t* "
                "obj, cmp_ctx_t* cmp, np_treeval_t* value){");
  switch (obj->type) {
  case CMP_TYPE_FIXMAP:
  case CMP_TYPE_MAP16:
  case CMP_TYPE_MAP32:
    log_msg(LOG_WARNING,
            NULL,
            "error de-serializing message to normal form, found map type");
    cmp->error = 13; // INVALID_TYPE_ERROR
    break;

  case CMP_TYPE_FIXARRAY:
    if (2 == obj->as.array_size) {
      cmp->read(cmp, &value->value.a2_ui[0], sizeof(uint16_t));
      cmp->read(cmp, &value->value.a2_ui[1], sizeof(uint16_t));
      value->type = np_treeval_type_uint_array_2;
    }
    break;
  case CMP_TYPE_ARRAY16:
  case CMP_TYPE_ARRAY32:
    log_msg(LOG_WARNING,
            NULL,
            "error de-serializing message to normal form, found array type");
    cmp->error = 13; // INVALID_TYPE_ERROR
    break;

  case CMP_TYPE_FIXSTR:
    if (obj->as.str_size == sizeof(char)) {
      value->type = np_treeval_type_char;
      cmp->read(cmp, &value->value.c, sizeof(char));
      value->size = obj->as.str_size;
      break;
    }
  case CMP_TYPE_STR8:
  case CMP_TYPE_STR16:
  case CMP_TYPE_STR32: {
    value->type = np_treeval_type_char_ptr;
    value->size = obj->as.str_size - 1 /*terminator*/;

    if (tree->attr.in_place == true) {
      value->value.s = cmp->buf;
      cmp->skip(cmp, obj->as.str_size);
    } else {
      value->value.s = (char *)malloc(obj->as.str_size * sizeof(char));
      CHECK_MALLOC(value->value.s);
      cmp->read(cmp, value->value.s, obj->as.str_size);
    }

    // to prevent undefined lengths. but should already have a terminator
    char *term = value->value.s + obj->as.str_size - 1;
    term       = "\0";

    break;
  }
  case CMP_TYPE_BIN8:
  case CMP_TYPE_BIN16:
  case CMP_TYPE_BIN32: {
    value->type = np_treeval_type_bin;
    value->size = obj->as.bin_size;

    if (tree->attr.in_place == true) {
      value->value.bin = cmp->buf;
      cmp->skip(cmp, obj->as.bin_size);
    } else {
      value->value.bin = malloc(value->size);
      CHECK_MALLOC(value->value.bin);

      memset(value->value.bin, 0, value->size);
      cmp->read(cmp, value->value.bin, obj->as.bin_size);
    }
    break;
  }

  case CMP_TYPE_NIL:
    log_msg(LOG_WARNING,
            NULL,
            "unknown de-serialization for given type (cmp NIL) ");
    cmp->error = 13; // INVALID_TYPE_ERROR
    break;

  case CMP_TYPE_BOOLEAN:
    log_msg(LOG_WARNING,
            NULL,
            "unknown de-serialization for given type (cmp boolean) ");
    cmp->error = 13; // INVALID_TYPE_ERROR
    break;

  case CMP_TYPE_EXT8:
  case CMP_TYPE_EXT16:
  case CMP_TYPE_EXT32:
  case CMP_TYPE_FIXEXT1:
  case CMP_TYPE_FIXEXT2:
  case CMP_TYPE_FIXEXT4:
  case CMP_TYPE_FIXEXT8:
  case CMP_TYPE_FIXEXT16: {
    void *buffer        = cmp->buf;
    void *target_buffer = buffer + obj->as.ext.size;

    if (obj->as.ext.type == np_treeval_type_jrb_tree ||
        obj->as.ext.type == np_treeval_type_cose_signed ||
        obj->as.ext.type == np_treeval_type_cose_encrypted ||
        obj->as.ext.type == np_treeval_type_cwt) {
      // tree type
      value->type = obj->as.ext.type;

      np_tree_t *subtree                   = np_tree_create();
      subtree->attr.in_place               = tree->attr.in_place;
      np_deserialize_buffer_t deserializer = {
          ._target_tree = subtree,
          ._buffer      = buffer,
          ._buffer_size = obj->as.ext.size,
          ._error       = 0,
          ._bytes_read  = 0,
      };
      np_serializer_read_map(context, &deserializer, subtree);
      if (deserializer._error != 0) {
        cmp->error = 11; // EXT_TYPE_READING_ERROR
        break;
      }
      cmp->skip(cmp, obj->as.ext.size);

      // if (subtree->rbh_root == NULL) {
      //	 ASSERT(0 == subtree->size, "Size of tree does not match 0 size
      // is: %"PRIu16, subtree->size); 	 ASSERT(5/*the empty byte size (set in
      // tree_create())*/ == obj->as.ext.size, "Bytesize of tree does not match
      // , size is: %"PRIu32, obj->as.ext.size);
      // }else{
      //	 ASSERT(
      //		np_tree_element_get_byte_size(subtree->rbh_root) ==
      // obj->as.ext.size, 		"Bytesize of tree does not match.
      // actual: %"PRIu32" expected: %"PRIu32,
      // np_tree_element_get_byte_size(subtree->rbh_root), obj->as.ext.size
      //	);
      //}
      // TODO: check if the complete buffer was read (byte count match)
      value->value.tree = subtree;
      value->size       = subtree->byte_size;
      log_debug(LOG_SERIALIZATION | LOG_VERBOSE,
                NULL,
                "read:  buffer size for subtree %u (%hd %u)",
                value->size,
                value->value.tree->size,
                subtree->byte_size);
    } else if (obj->as.ext.type == np_treeval_type_dhkey) {
      cmp->error = __np_tree_serialize_read_type_dhkey(cmp, value);
    } else if (obj->as.ext.type == np_treeval_type_hash) {
      value->type = np_treeval_type_hash;
      value->size = obj->as.ext.size;

      if (tree->attr.in_place == true) {

        value->value.bin = buffer;
        cmp->skip(cmp, obj->as.bin_size);
      } else {

        value->value.bin = (char *)malloc(obj->as.ext.size);
        CHECK_MALLOC(value->value.bin);

        memset(value->value.bin, 0, value->size);
        memcpy(value->value.bin, buffer, obj->as.ext.size);
      }
    } else {
      log_debug(LOG_TREE | LOG_SERIALIZATION | LOG_DEBUG,
                NULL,
                "Cannot deserialize ext type %" PRIi8 " (size: %" PRIu32 ")",
                obj->as.ext.type,
                obj->as.ext.size);

      log_msg(LOG_TREE | LOG_SERIALIZATION | LOG_WARNING,
              NULL,
              "Unknown de-serialization for given extension type %" PRIi8,
              obj->as.ext.type);
      cmp->buf = target_buffer;

      cmp->error = 11; // EXT_TYPE_READING_ERROR
    }

    if (cmp->buf != target_buffer) {
      cmp->error = 14; // LENGTH_READING_ERROR
      break;
    }
    // skip forward in case of error ?
  } break;

  case CMP_TYPE_FLOAT:
    value->value.f = 0.0;
    value->value.f = obj->as.flt;
    value->type    = np_treeval_type_float;
    break;

  case CMP_TYPE_DOUBLE:
    value->value.d = 0.0;
    value->value.d = obj->as.dbl;
    value->type    = np_treeval_type_double;
    break;

  case CMP_TYPE_POSITIVE_FIXNUM:
  case CMP_TYPE_UINT8:
    value->value.ush = obj->as.u8;
    value->type      = np_treeval_type_unsigned_short;
    break;
  case CMP_TYPE_UINT16:
    value->value.ui = 0;
    value->value.ui = obj->as.u16;
    value->type     = np_treeval_type_unsigned_int;
    break;
  case CMP_TYPE_UINT32:
    value->value.ul = 0;
    value->value.ul = obj->as.u32;
    value->type     = np_treeval_type_unsigned_long;
    break;
#ifdef x64
  case CMP_TYPE_UINT64:
    value->value.ull = 0;
    value->value.ull = obj->as.u64;
    value->type      = np_treeval_type_unsigned_long_long;
    break;
#endif
  case CMP_TYPE_NEGATIVE_FIXNUM:
  case CMP_TYPE_SINT8:
    value->value.sh = obj->as.s8;
    value->type     = np_treeval_type_short;
    break;

  case CMP_TYPE_SINT16:
    value->value.i = 0;
    value->value.i = obj->as.s16;
    value->type    = np_treeval_type_int;
    break;

  case CMP_TYPE_SINT32:
    value->value.l = obj->as.s32;
    value->type    = np_treeval_type_long;
    break;
#ifdef x64
  case CMP_TYPE_SINT64:
    value->value.ll = 0;
    value->value.ll = obj->as.s64;
    value->type     = np_treeval_type_long_long;
    break;
#endif
  default:
    value->type = np_treeval_type_undefined;
    log_msg(LOG_WARNING, NULL, "unknown deserialization for given type");
    break;
  }
}

void np_serializer_add_map_bytesize(np_tree_t *tree, size_t *byte_size) {
  *byte_size += 5;
}

void np_serializer_write_map(np_state_t            *context,
                             np_serialize_buffer_t *buffer,
                             const np_tree_t       *tree) {
  buffer->_tree = tree;

  cmp_ctx_t cmp_context = {0};
  cmp_init(&cmp_context,
           buffer->_target_buffer,
           NULL, // __np_buffer_reader,
           __np_buffer_skipper,
           __np_buffer_writer);
  uint16_t i = 0;

  // first assume a size based on jrb size
  if (!cmp_write_map32(&cmp_context, buffer->_tree->size * 2)) return;

  // write jrb tree
  if (0 < buffer->_tree->size) {

    np_tree_elem_t *tmp = NULL;

    RB_FOREACH (tmp, np_tree_s, buffer->_tree) {

      if (np_treeval_type_int == tmp->key.type ||
          np_treeval_type_dhkey == tmp->key.type ||
          np_treeval_type_unsigned_long == tmp->key.type ||
          np_treeval_type_double == tmp->key.type ||
          np_treeval_type_char_ptr == tmp->key.type) {
        // log_debug(LOG_DEBUG, NULL, "for (%p; %p!=%p; %p=%p) ",
        // tmp->flink, tmp, msg->header, node, node->flink);
        __np_tree_serialize_write_type(context, tmp->key, &cmp_context);
        i++;
        __np_tree_serialize_write_type(context, tmp->val, &cmp_context);
        i++;
      } else {
        log_msg(LOG_ERROR, NULL, "unknown key type for serialization");
      }
    }
  }

  buffer->_bytes_written = cmp_context.buf - buffer->_target_buffer;
  buffer->_error         = cmp_context.error;

  if (i != buffer->_tree->size * 2)
    log_msg(LOG_ERROR,
            NULL,
            "serialized jrb size map size is %d, but should be %hd",
            buffer->_tree->size * 2,
            i);
}

void np_serializer_read_map(np_state_t              *context,
                            np_deserialize_buffer_t *buffer,
                            np_tree_t               *tree) {
  buffer->_target_tree = tree;
  cmp_ctx_t cmp_context;
  cmp_init(&cmp_context,
           buffer->_buffer,
           __np_buffer_reader,
           __np_buffer_skipper,
           NULL); // __np_buffer_writer);

  ASSERT(buffer->_target_tree != NULL, "Tree do deserialize cannot be NULL");
  bool ret = true;

  cmp_object_t obj_key = {0};
  cmp_object_t obj_val = {0};

  uint32_t size = 0;

  cmp_read_map(&cmp_context, &size);

  if (size == 0) {
    return;

  } else if ((size % 2) != 0) {
    buffer->_error = 1;
    return;
  }

  for (uint32_t i = 0; i < (size / 2); i++) {
    // read key
    np_treeval_t tmp_key = {0};
    tmp_key.type         = np_treeval_type_undefined;
    tmp_key.size         = 0;
    cmp_read_object(&cmp_context, &obj_key);
    __np_tree_deserialize_read_type(context,
                                    buffer->_target_tree,
                                    &obj_key,
                                    &cmp_context,
                                    &tmp_key,
                                    "<<key read>>");

    if (cmp_context.error != 0 || np_treeval_type_undefined == tmp_key.type) {
      log_msg(LOG_INFO,
              NULL,
              "deserialization error: %s",
              cmp_strerror(&cmp_context));
      buffer->_error = cmp_context.error;
      ret            = false;
      break;
    }

    // read value
    np_treeval_t tmp_val = {0};
    tmp_val.type         = np_treeval_type_undefined;
    tmp_val.size         = 0;
    cmp_read_object(&cmp_context, &obj_val);

#ifdef DEBUG
    bool  free_tmp_key_str = false;
    char *tmp_key_str = np_treeval_to_str(tmp_key, NULL, &free_tmp_key_str);
    __np_tree_deserialize_read_type(context,
                                    buffer->_target_tree,
                                    &obj_val,
                                    &cmp_context,
                                    &tmp_val,
                                    tmp_key_str);
    if (free_tmp_key_str) {
      free(tmp_key_str);
    }
#else
    __np_tree_deserialize_read_type(context,
                                    buffer->_target_tree,
                                    &obj_val,
                                    &cmp_context,
                                    &tmp_val,
                                    "<<unknown>>");
#endif

    if (cmp_context.error != 0 || np_treeval_type_undefined == tmp_val.type) {
      log_msg(LOG_INFO,
              NULL,
              "deserialization error: %s",
              cmp_strerror(&cmp_context));
      buffer->_error = cmp_context.error;
      ret            = false;
      break;
    }

    // add key value pair to tree
    switch (tmp_key.type) {
    case np_treeval_type_int:
      np_tree_insert_int(buffer->_target_tree, tmp_key.value.i, tmp_val);
      break;
    case np_treeval_type_dhkey:
      np_tree_insert_dhkey(buffer->_target_tree, tmp_key.value.dhkey, tmp_val);
      break;
    case np_treeval_type_unsigned_long:
      np_tree_insert_ulong(buffer->_target_tree, tmp_key.value.ul, tmp_val);
      break;
    case np_treeval_type_double:
      np_tree_insert_dbl(buffer->_target_tree, tmp_key.value.d, tmp_val);
      break;
    case np_treeval_type_char_ptr:
      np_tree_insert_str(buffer->_target_tree, tmp_key.value.s, tmp_val);
      break;
    default:
      tmp_val.type = np_treeval_type_undefined;
      break;
    }

    _np_tree_cleanup_treeval(buffer->_target_tree, tmp_key);
    if (buffer->_target_tree->attr.in_place == false ||
        tmp_val.type != np_treeval_type_jrb_tree) {
      _np_tree_cleanup_treeval(buffer->_target_tree, tmp_val);
    }
  }

  if (cmp_context.error != 0) {
    log_msg(LOG_INFO,
            NULL,
            "deserialization error: %s",
            cmp_strerror(&cmp_context));
  }

  if (ret == false) {
    log_debug(LOG_SERIALIZATION | LOG_TREE | LOG_WARNING,
              NULL,
              "Deserialization error: unspecified error");
    cmp_context.error = 1;
  } else {
    if (buffer->_target_tree->attr.in_place == true) {
      buffer->_target_tree->attr.immutable = true;
    }
  }

  buffer->_bytes_read = cmp_context.buf - buffer->_buffer;
  buffer->_error      = cmp_context.error;
}

enum np_data_return np_serializer_write_object(np_kv_buffer_t *to_write) {
  uint8_t key_len = strnlen(to_write->key, 255);

  cmp_ctx_t cmp = {0};
  cmp_init(&cmp, to_write->buffer_start, NULL, NULL, __np_buffer_writer);

  if (!cmp_write_str8(&cmp, to_write->key, key_len)) {
    // fprintf(stderr, "__write_object.key");
    return np_could_not_write_key;
  } else if (to_write->data_type == NP_DATA_TYPE_BIN) {
    if (!cmp_write_bin32(&cmp, to_write->data.bin, to_write->data_size)) {
      // fprintf(stderr, "__write_object.data_size");
      return np_could_not_write_bin;
    }
  } else if (to_write->data_type == NP_DATA_TYPE_INT) {
    if (!cmp_write_s32(&cmp, to_write->data.integer)) {
      // fprintf(stderr, "__write_object.data_size");
      return np_could_not_write_int;
    }
  } else if (to_write->data_type == NP_DATA_TYPE_UNSIGNED_INT) {
    if (!cmp_write_u32(&cmp, to_write->data.unsigned_integer)) {
      // fprintf(stderr, "__write_object.data_size");
      return np_could_not_write_uint;
    }
  } else if (to_write->data_type == NP_DATA_TYPE_STR) {
    if (!cmp_write_str32(&cmp, to_write->data.str, to_write->data_size)) {
      // fprintf(stderr, "__write_object.data_size");
      return np_could_not_write_str;
    }
  } // ... other types
  else {
    return np_invalid_arguments;
  }

  to_write->buffer_end = cmp.buf;
  return np_data_ok;
}

enum np_data_return np_serializer_read_object(np_kv_buffer_t *to_read) {
  cmp_ctx_t cmp = {0};
  cmp_init(&cmp, to_read->buffer_start, __np_buffer_reader, NULL, NULL);

  uint32_t key_size = 255;
  if (!cmp_read_str(&cmp, to_read->key, &key_size)) // key
  {
    return np_could_not_read_key;
  } else {
    cmp_object_t type;
    to_read->key[key_size] = '\0';
    if (!cmp_read_object(&cmp, &type)) {
      return np_could_not_read_object;
    } else if (type.type == CMP_TYPE_BIN32) {
      to_read->data_type = NP_DATA_TYPE_BIN;
      to_read->data_size = type.as.bin_size;
      to_read->data.bin  = cmp.buf;
      cmp.buf += to_read->data_size;
    } else if (type.type == CMP_TYPE_FIXSTR || type.type == CMP_TYPE_STR8 ||
               type.type == CMP_TYPE_STR16 || type.type == CMP_TYPE_STR32) {
      to_read->data_type = NP_DATA_TYPE_STR;
      to_read->data_size = type.as.str_size;
      to_read->data.str  = cmp.buf;
      cmp.buf += to_read->data_size;
    } else if (type.type == CMP_TYPE_SINT32) {
      to_read->data_type    = NP_DATA_TYPE_INT;
      to_read->data_size    = sizeof(type.as.s32);
      to_read->data.integer = type.as.s32;

    } else if (type.type == CMP_TYPE_UINT32) {
      to_read->data_type             = NP_DATA_TYPE_UNSIGNED_INT;
      to_read->data_size             = sizeof(type.as.u32);
      to_read->data.unsigned_integer = type.as.u32;
    } // ... other types
    else {
      return np_invalid_arguments;
    }
  }
  to_read->buffer_end = cmp.buf;

  return np_data_ok;
}

unsigned char *np_skip_datablock_header(np_datablock_header_t *block) {
  uint32_t overhead = sizeof(uint8_t) /*marker+value*/ + // fixarray
                      3 * (sizeof(uint8_t) /*marker*/ + sizeof(uint32_t)) +
                      /*value:->see right*/ // magic_no + total_length
                                            // + used_length
                      sizeof(uint8_t) +     /* marker */
                      sizeof(uint32_t) /* value:object_count */ // map32
      ;                                                         // 21 byte

  return &block->_inner_blob[overhead];
}

enum np_data_return np_serializer_search_object(np_datablock_header_t *block,
                                                char                  *key,
                                                np_kv_buffer_t        *kv_pair,
                                                uint32_t data_magic_no) {
  np_serializer_read_datablock_header(block, data_magic_no);
  // np_serializer_skip_datablock_header(block);

  enum np_data_return ret          = np_key_not_found;
  uint16_t            objects_read = 0;

  kv_pair->buffer_start = np_skip_datablock_header(block);

  while (objects_read < block->object_count) {
    if (np_data_ok == np_serializer_read_object(kv_pair)) {
      if (strncmp(kv_pair->key, key, strnlen(key, 255)) == 0 &&
          strnlen(kv_pair->key, 255) == strnlen(key, 255)) {
        ret = np_data_ok;
        break;
      }
      objects_read++;
      kv_pair->buffer_start = kv_pair->buffer_end;
    } else {
      ret = np_invalid_structure;
      break;
    }
  }
  return ret;
}

enum np_data_return
np_serializer_read_datablock_header(np_datablock_header_t *block,
                                    uint32_t               data_magic_no) {
  uint32_t array_size = 0;
  uint32_t magic_no   = 0;

  cmp_ctx_t cmp = {0};
  cmp_init(&cmp, block->_inner_blob, __np_buffer_reader, NULL, NULL);

  if (!cmp_read_array(&cmp, &array_size) && array_size == 4) {
    return np_invalid_arguments;

  } else if (!cmp_read_u32(&cmp, &magic_no) &&
             magic_no == data_magic_no) // magic_no
  {
    return np_could_not_read_magicno;

  } else if (!cmp_read_u32(&cmp, &block->total_length)) // total_length
  {
    return np_could_not_read_total_length;

  } else if (!cmp_read_u32(&cmp, &block->used_length)) // used_length
  {
    return np_could_not_read_used_length;

  } else if (!cmp_read_map(&cmp, &block->object_count)) // object_count
  {
    return np_could_not_read_object_count;
  }
  return np_data_ok;
}

enum np_data_return
np_serializer_write_datablock_header(np_datablock_header_t *block,
                                     uint32_t               data_magic_no) {
  uint32_t overhead = sizeof(uint8_t) /*marker+value*/ + // fixarray
                      3 * (sizeof(uint8_t) /*marker*/ + sizeof(uint32_t)) +
                      /*value:->see right*/ // magic_no + total_length
                                            // + used_length
                      sizeof(uint8_t) +     /* marker */
                      sizeof(uint32_t) /* value:object_count */ // map32
      ;                                                         // 21 byte

  if (block->used_length <= overhead) {
    block->used_length = overhead;
    memset(block->_inner_blob, 0, block->total_length);
  }
  // uint32_t initial_object_count = 0;
  // block->total_length = size;
  // block->used_length = overhead;
  // block->object_count = initial_object_count;

  cmp_ctx_t cmp = {0};
  cmp_init(&cmp, block->_inner_blob, NULL, NULL, __np_buffer_writer);
  // fprintf(stderr, "overhead:%" PRIu32 "\n", overhead);

  if (!cmp_write_fixarray(&cmp, 4)) {
    return np_invalid_structure;

  } else if (!cmp_write_u32(&cmp, data_magic_no)) // magic_no
  {
    return np_could_not_write_magicno;

  } else if (!cmp_write_u32(&cmp, block->total_length)) // total_length
  {
    return np_could_not_write_total_length;

  } else if (!cmp_write_u32(&cmp, block->used_length)) // used_length
  {
    return np_could_not_write_used_length;

  } else if (!cmp_write_map32(&cmp, block->object_count)) // object count
  {
    return np_could_not_write_object_count;
  }
  return np_data_ok;
}

enum np_data_return np_serializer_calculate_object_size(np_kv_buffer_t kv_pair,
                                                        size_t *object_size) {
  // check for space in block
  *object_size = sizeof(uint8_t) /*Marker*/ + sizeof(uint8_t) /*str size*/ +
                 strnlen(kv_pair.key, 255) /*Key*/ /*NULL byte*/;

  if (kv_pair.data_type == NP_DATA_TYPE_BIN) {
    *object_size += sizeof(uint8_t) /*Marker*/ + sizeof(uint32_t) /*DataSize*/ +
                    kv_pair.data_size /*Data*/;
  } else if (kv_pair.data_type == NP_DATA_TYPE_INT) {
    kv_pair.data_size = sizeof(int32_t);
    *object_size += sizeof(uint8_t) /*Marker*/ + sizeof(int32_t);
  } else if (kv_pair.data_type == NP_DATA_TYPE_UNSIGNED_INT) {
    kv_pair.data_size = sizeof(uint32_t);
    *object_size += sizeof(uint8_t) /*Marker*/ + sizeof(uint32_t);
  } else if (kv_pair.data_type == NP_DATA_TYPE_STR) {
    *object_size += sizeof(uint8_t) /*Marker*/ + sizeof(uint32_t) /*size*/ +
                    kv_pair.data_size /*Data*/;
  } // other data types
  else {
    ASSERT(false,
           "missing implementation for type %" PRIu32,
           (uint32_t)kv_pair.data_type);
    return np_invalid_arguments;
  }
  return np_data_ok;
}
