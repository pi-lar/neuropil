//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "qcbor/qcbor.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_spiffy_decode.h"

#include "util/np_serialization.h"

#include "np_aaatoken.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_util.h"

static void AppendCBORHeadWithSize(QCBOREncodeContext *me,
                                   uint8_t             uMajorType,
                                   uint64_t            uArgument,
                                   uint8_t             uMinLen) {
  /* A stack buffer large enough for a CBOR head */
  UsefulBuf_MAKE_STACK_UB(pBufferForEncodedHead, QCBOR_HEAD_BUFFER_SIZE);

  UsefulBufC EncodedHead = QCBOREncode_EncodeHead(pBufferForEncodedHead,
                                                  uMajorType,
                                                  uMinLen,
                                                  uArgument);

  /* No check for EncodedHead == NULLUsefulBufC is performed here to
   * save object code. It is very clear that pBufferForEncodedHead is
   * the correct size. If EncodedHead == NULLUsefulBufC then
   * UsefulOutBuf_AppendUsefulBuf() will do nothing so there is no
   * security hole introduced.
   */

  UsefulOutBuf_AppendUsefulBuf(&(me->OutBuf), EncodedHead);
}

static inline int QCBOR_Int64ToUInt16(int64_t src, uint16_t *dest) {
  if (src > UINT16_MAX || src < 0) {
    return -1;
  } else {
    *dest = (uint16_t)src;
  }
  return 0;
}

uint8_t __np_tree_serialize_read_type_dhkey(QCBORDecodeContext *qcbor_ctx,
                                            np_treeval_t       *target) {
  log_trace_msg(LOG_TRACE,
                "start: uint8_t __np_tree_serialize_read_type_dhkey(void* "
                "buffer_ptr, np_treeval_t* target) {");

  target->type = np_treeval_type_dhkey;
  target->size = sizeof(np_dhkey_t);

  QCBORItem item = {0};
  QCBORDecode_VGetNext(qcbor_ctx, &item);
  QCBOR_Int64ToUInt32(item.val.uint64, &target->value.dhkey.t[0]);
  QCBORDecode_VGetNext(qcbor_ctx, &item);
  QCBOR_Int64ToUInt32(item.val.uint64, &target->value.dhkey.t[1]);
  QCBORDecode_VGetNext(qcbor_ctx, &item);
  QCBOR_Int64ToUInt32(item.val.uint64, &target->value.dhkey.t[2]);
  QCBORDecode_VGetNext(qcbor_ctx, &item);
  QCBOR_Int64ToUInt32(item.val.uint64, &target->value.dhkey.t[3]);
  QCBORDecode_VGetNext(qcbor_ctx, &item);
  QCBOR_Int64ToUInt32(item.val.uint64, &target->value.dhkey.t[4]);
  QCBORDecode_VGetNext(qcbor_ctx, &item);
  QCBOR_Int64ToUInt32(item.val.uint64, &target->value.dhkey.t[5]);
  QCBORDecode_VGetNext(qcbor_ctx, &item);
  QCBOR_Int64ToUInt32(item.val.uint64, &target->value.dhkey.t[6]);
  QCBORDecode_VGetNext(qcbor_ctx, &item);
  QCBOR_Int64ToUInt32(item.val.uint64, &target->value.dhkey.t[7]);

  return qcbor_ctx->uLastError;
}

void __np_tree_serialize_write_type_dhkey(np_dhkey_t          source,
                                          QCBOREncodeContext *qcbor_ctx) {
  log_trace_msg(LOG_TRACE,
                "start: void __np_tree_serialize_write_type_dhkey(np_dhkey_t "
                "source, cmp_ctx_t* target) {");
  QCBOREncode_AddTag(qcbor_ctx,
                     NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_dhkey);
  QCBOREncode_OpenArray(qcbor_ctx);
  AppendCBORHeadWithSize(qcbor_ctx,
                         CBOR_MAJOR_TYPE_POSITIVE_INT,
                         source.t[0],
                         4);
  qcbor_ctx->nesting.pCurrentNesting->uCount++;
  AppendCBORHeadWithSize(qcbor_ctx,
                         CBOR_MAJOR_TYPE_POSITIVE_INT,
                         source.t[1],
                         4);
  qcbor_ctx->nesting.pCurrentNesting->uCount++;
  AppendCBORHeadWithSize(qcbor_ctx,
                         CBOR_MAJOR_TYPE_POSITIVE_INT,
                         source.t[2],
                         4);
  qcbor_ctx->nesting.pCurrentNesting->uCount++;
  AppendCBORHeadWithSize(qcbor_ctx,
                         CBOR_MAJOR_TYPE_POSITIVE_INT,
                         source.t[3],
                         4);
  qcbor_ctx->nesting.pCurrentNesting->uCount++;
  AppendCBORHeadWithSize(qcbor_ctx,
                         CBOR_MAJOR_TYPE_POSITIVE_INT,
                         source.t[4],
                         4);
  qcbor_ctx->nesting.pCurrentNesting->uCount++;
  AppendCBORHeadWithSize(qcbor_ctx,
                         CBOR_MAJOR_TYPE_POSITIVE_INT,
                         source.t[5],
                         4);
  qcbor_ctx->nesting.pCurrentNesting->uCount++;
  AppendCBORHeadWithSize(qcbor_ctx,
                         CBOR_MAJOR_TYPE_POSITIVE_INT,
                         source.t[6],
                         4);
  qcbor_ctx->nesting.pCurrentNesting->uCount++;
  AppendCBORHeadWithSize(qcbor_ctx,
                         CBOR_MAJOR_TYPE_POSITIVE_INT,
                         source.t[7],
                         4);
  qcbor_ctx->nesting.pCurrentNesting->uCount++;
  QCBOREncode_CloseArray(qcbor_ctx);
}

void __np_tree_deserialize_read_type(np_state_t         *context,
                                     np_tree_t          *tree,
                                     QCBORDecodeContext *qcbor_ctx,
                                     np_treeval_t       *value,
                                     NP_UNUSED char     *key_to_read_for) {
  log_trace_msg(LOG_TRACE,
                "start: void __np_tree_deserialize_read_type(cmp_object_t* "
                "obj, cmp_ctx_t* cmp, np_treeval_t* value){");

  QCBORItem _item = {0};

  QCBORDecode_VGetNext(qcbor_ctx, &_item);
  switch (_item.uDataType) {

  case QCBOR_TYPE_MAP:
  case QCBOR_TYPE_MAP_AS_ARRAY: {
    if (_item.uTags[0] ==
        (NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_jrb_tree)) {

      for (int32_t i = _item.val.uCount; i > 0; i--) {
        np_treeval_t tmp_key   = {0};
        np_tree_t   *subtree   = np_tree_create();
        subtree->attr.in_place = tree->attr.in_place;
        __np_tree_deserialize_read_type(context,
                                        subtree, // key can't be a tree
                                        qcbor_ctx,
                                        &tmp_key,
                                        "");
        np_tree_clear(subtree); // key value cannot be a tree
        np_treeval_t tmp_val = {0};
        __np_tree_deserialize_read_type(context,
                                        subtree,
                                        qcbor_ctx,
                                        &tmp_val,
                                        "");
        i--;
        // add key value pair to tree
        switch (tmp_key.type) {
        case np_treeval_type_int:
          np_tree_insert_int(tree, tmp_key.value.i, tmp_val);
          break;
        case np_treeval_type_dhkey:
          np_tree_insert_dhkey(tree, tmp_key.value.dhkey, tmp_val);
          break;
        case np_treeval_type_unsigned_long:
          np_tree_insert_ulong(tree, tmp_key.value.ul, tmp_val);
          break;
        case np_treeval_type_double:
          np_tree_insert_dbl(tree, tmp_key.value.d, tmp_val);
          break;
        case np_treeval_type_char_ptr:
          np_tree_insert_str(tree, tmp_key.value.s, tmp_val);
          break;
        default:
          log_msg(LOG_WARNING | LOG_SERIALIZATION,
                  "undefined key type cannot be added to tree structure");
          tmp_val.type = np_treeval_type_undefined;
          break;
        }
        np_tree_free(subtree);
      }
      //        QCBORDecode_ExitMap(qcbor_ctx);
      if (_item.uTags[1] == CBOR_TAG_CWT) {
        value->type = np_treeval_type_cwt;
      } else if (_item.uTags[1] == CBOR_TAG_COSE_ENCRYPT) {
        value->type = np_treeval_type_cose_encrypted;
      } else if (_item.uTags[1] == CBOR_TAG_COSE_SIGN) {
        value->type = np_treeval_type_cose_signed;
      } else {
        value->type = np_treeval_type_jrb_tree;
      }
      value->value.tree = tree;
      value->size       = tree->size;
      log_debug_msg(LOG_SERIALIZATION | LOG_VERBOSE,
                    "read:  buffer size for subtree %u (%hd %u)",
                    value->size,
                    value->value.tree->size,
                    tree->byte_size);
    }
  } break;

  case QCBOR_TYPE_ARRAY: {
    if (_item.uTags[0] ==
        (NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_uint_array_2)) {
      QCBORDecode_VGetNext(qcbor_ctx, &_item);
      QCBOR_Int64ToUInt16(_item.val.int64, &value->value.a2_ui[0]);
      QCBORDecode_VGetNext(qcbor_ctx, &_item);
      QCBOR_Int64ToUInt16(_item.val.int64, &value->value.a2_ui[1]);
      value->type = np_treeval_type_uint_array_2;
    } else if (_item.uTags[0] ==
               (NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_dhkey)) {
      __np_tree_serialize_read_type_dhkey(qcbor_ctx, value);
    } else {
      log_msg(LOG_WARNING,
              "error de-serializing message to normal form, found array type");
      qcbor_ctx->uLastError = 13; // INVALID_TYPE_ERROR
    }
  } break;

  case QCBOR_TYPE_TEXT_STRING: {
    value->size = _item.val.string.len;
    if (_item.val.string.len == 1) {
      value->type    = np_treeval_type_char;
      value->value.c = *((char *)_item.val.string.ptr);
    } else {
      value->type = np_treeval_type_char_ptr;
      if (tree->attr.in_place == true) {
        value->value.s = (char *)_item.val.string.ptr;
      } else {
        value->value.s = strndup(_item.val.string.ptr, _item.val.string.len);
      }
    }
  } break;

  case QCBOR_TYPE_BYTE_STRING: {

    if (_item.uTags[0] == (NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_hash)) {
      value->type = np_treeval_type_hash;
      value->size = _item.val.string.len;
      if (tree->attr.in_place == true) {
        value->value.bin = (char *)_item.val.string.ptr;
      } else {
        value->value.bin = malloc(_item.val.string.len);
        CHECK_MALLOC(value->value.bin);
        memcpy(value->value.bin, _item.val.string.ptr, _item.val.string.len);
      }
    } else {
      value->type = np_treeval_type_bin;
      value->size = _item.val.string.len;
      if (tree->attr.in_place == true) {
        value->value.bin = (char *)_item.val.string.ptr;
      } else {
        value->value.bin = malloc(value->size);
        CHECK_MALLOC(value->value.bin);
        memcpy(value->value.bin, _item.val.string.ptr, value->size);
      }
    }
  } break;

  case QCBOR_TYPE_NULL:
    log_msg(LOG_WARNING, "unknown de-serialization for given type (cmp NIL) ");
    qcbor_ctx->uLastError = 13; // INVALID_TYPE_ERROR
    break;

  case QCBOR_TYPE_FALSE:
  case QCBOR_TYPE_TRUE:
    log_msg(LOG_WARNING,
            "unknown de-serialization for given type (cmp boolean) ");
    qcbor_ctx->uLastError = 13; // INVALID_TYPE_ERROR
    break;

  case QCBOR_TYPE_FLOAT:
    value->value.f = _item.val.fnum;
    value->type    = np_treeval_type_float;
    break;

  case QCBOR_TYPE_DOUBLE:
    value->value.d = _item.val.dfnum;
    value->type    = np_treeval_type_double;
    break;

  case QCBOR_TYPE_UINT64:
  case QCBOR_TYPE_INT64: {
    switch (_item.uTags[0]) {
    case (NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_unsigned_short):
      QCBOR_Int64ToUInt8(_item.val.int64, &value->value.ush);
      value->type = np_treeval_type_unsigned_short;
      break;
    case (NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_unsigned_int):
      QCBOR_Int64ToUInt16(_item.val.int64, &value->value.ui);
      value->type = np_treeval_type_unsigned_int;
      break;
    case (NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_unsigned_long):
      QCBOR_Int64ToUInt32(_item.val.int64, &value->value.ul);
      value->type = np_treeval_type_unsigned_long;
      break;
#ifdef x64
    case (NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_unsigned_long_long):
      QCBOR_Int64ToUInt64(_item.val.int64, &value->value.ull);
      value->type = np_treeval_type_unsigned_long_long;
      break;
#endif
    case (NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_short):
      QCBOR_Int64ToInt8(_item.val.int64, &value->value.sh);
      value->type = np_treeval_type_short;
      break;
    case (NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_int):
      QCBOR_Int64ToInt16(_item.val.int64, &value->value.i);
      value->type = np_treeval_type_int;
      break;
    case (NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_long):
      QCBOR_Int64ToInt32(_item.val.int64, &value->value.l);
      value->type = np_treeval_type_long;
      break;
#ifdef x64
    case (NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_long_long):
      value->value.ll = _item.val.int64;
      value->type     = np_treeval_type_long_long;
      break;
#endif
    default:
      value->type = np_treeval_type_undefined;
      log_msg(LOG_WARNING, "unknown deserialization for given int type");
      break;
    }
  } break;

  default:
    value->type = np_treeval_type_undefined;
    log_msg(LOG_WARNING,
            "unknown deserialization for given type %" PRId8 " / %" PRId16
            " / %" PRId16,
            _item.uDataType,
            _item.uTags[0],
            _item.uTags[1]);
    break;
  }
}

void __np_tree_serialize_write_type(np_state_t         *context,
                                    np_treeval_t        val,
                                    QCBOREncodeContext *qcbor_ctx) {
  log_trace_msg(LOG_TRACE,
                "start: void __np_tree_serialize_write_type(np_treeval_t val, "
                "cmp_ctx_t* cmp){");
  // void* count_buf_start = cmp->buf;
  // log_debug_msg(LOG_DEBUG, "writing jrb (%p) value: %s", jrb,
  // jrb->key.value.s);
  switch (val.type) {
    // signed numbers
  case np_treeval_type_short:
    QCBOREncode_AddTag(qcbor_ctx,
                       NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_short);
    QCBOREncode_AddInt64(qcbor_ctx, val.value.sh);
    break;
  case np_treeval_type_int:
    QCBOREncode_AddTag(qcbor_ctx,
                       NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_int);
    QCBOREncode_AddInt64(qcbor_ctx, val.value.i);
    break;
  case np_treeval_type_long:
    QCBOREncode_AddTag(qcbor_ctx,
                       NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_long);
    QCBOREncode_AddInt64(qcbor_ctx, val.value.l);
    break;
#ifdef x64
  case np_treeval_type_long_long:
    QCBOREncode_AddTag(qcbor_ctx,
                       NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_long_long);
    QCBOREncode_AddInt64(qcbor_ctx, val.value.ll);
    break;
#endif
    // characters
  case np_treeval_type_char_ptr:
    QCBOREncode_AddText(qcbor_ctx,
                        (UsefulBufC){.ptr = val.value.s, .len = val.size});
    break;
  case np_treeval_type_char:
    QCBOREncode_AddText(qcbor_ctx,
                        (UsefulBufC){.ptr = &val.value.c, .len = sizeof(char)});
    break;
    //	case np_treeval_type_unsigned_char:
    //	 	cmp_write_str(cmp, (const char*) &val.value.uc,
    // sizeof(unsigned
    // char)); 	 	break;

    // float and double precision
  case np_treeval_type_float:
    QCBOREncode_AddFloat(qcbor_ctx, val.value.f);
    break;
  case np_treeval_type_double:
    QCBOREncode_AddDouble(qcbor_ctx, val.value.d);
    break;

    // unsigned numbers
  case np_treeval_type_unsigned_short:
    QCBOREncode_AddTag(qcbor_ctx,
                       NP_CBOR_REGISTRY_ENTRIES +
                           np_treeval_type_unsigned_short);
    QCBOREncode_AddUInt64(qcbor_ctx, val.value.ush);
    break;
  case np_treeval_type_unsigned_int:
    QCBOREncode_AddTag(qcbor_ctx,
                       NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_unsigned_int);
    QCBOREncode_AddUInt64(qcbor_ctx, val.value.ui);
    break;
  case np_treeval_type_unsigned_long:
    QCBOREncode_AddTag(qcbor_ctx,
                       NP_CBOR_REGISTRY_ENTRIES +
                           np_treeval_type_unsigned_long);
    QCBOREncode_AddUInt64(qcbor_ctx, val.value.ul);
    break;
#ifdef x64
  case np_treeval_type_unsigned_long_long:
    QCBOREncode_AddTag(qcbor_ctx,
                       NP_CBOR_REGISTRY_ENTRIES +
                           np_treeval_type_unsigned_long_long);
    QCBOREncode_AddUInt64(qcbor_ctx, val.value.ull);
    break;
#endif

  case np_treeval_type_uint_array_2:
    QCBOREncode_AddTag(qcbor_ctx,
                       NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_uint_array_2);
    QCBOREncode_OpenArray(qcbor_ctx);
    QCBOREncode_AddInt64(qcbor_ctx, val.value.a2_ui[0]);
    QCBOREncode_AddInt64(qcbor_ctx, val.value.a2_ui[1]);
    QCBOREncode_CloseArray(qcbor_ctx);
    break;

  case np_treeval_type_float_array_2:
  case np_treeval_type_char_array_8:
  case np_treeval_type_unsigned_char_array_8:
    log_msg(LOG_WARNING,
            "please implement serialization for type %" PRIu8,
            val.type);
    break;

  case np_treeval_type_void:
    log_msg(LOG_WARNING,
            "please implement serialization for type %" PRIu8,
            val.type);
    break;

  case np_treeval_type_bin:
    QCBOREncode_AddBytes(qcbor_ctx,
                         (UsefulBufC){.ptr = val.value.bin, .len = val.size});
    break;

  case np_treeval_type_dhkey:
    // QCBOREncode_AddTag(qcbor_ctx, NP_CBOR_REGISTRY_ENTRIES +
    // np_treeval_type_dhkey);
    __np_tree_serialize_write_type_dhkey(val.value.dhkey, qcbor_ctx);
    break;

  case np_treeval_type_hash:
    // log_debug_msg(LOG_DEBUG, "adding hash value %s to serialization",
    // val.value.s);
    QCBOREncode_AddTag(qcbor_ctx,
                       NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_hash);
    QCBOREncode_AddBytes(qcbor_ctx,
                         (UsefulBufC){.ptr = val.value.bin, .len = val.size});
    break;

  case np_treeval_type_cose_encrypted:
    QCBOREncode_AddTag(qcbor_ctx, CBOR_TAG_COSE_ENCRYPT);
    np_treeval_t tmp_encrypt = np_treeval_new_tree(val.value.tree);
    __np_tree_serialize_write_type(context, tmp_encrypt, qcbor_ctx);
    break;

  case np_treeval_type_cose_signed:
    QCBOREncode_AddTag(qcbor_ctx, CBOR_TAG_COSE_SIGN);
    np_treeval_t tmp_sign = np_treeval_new_tree(val.value.tree);
    __np_tree_serialize_write_type(context, tmp_sign, qcbor_ctx);
    break;

  case np_treeval_type_cwt:
    QCBOREncode_AddTag(qcbor_ctx, CBOR_TAG_CWT);
    np_treeval_t tmp_cwt = np_treeval_new_tree(val.value.tree);
    __np_tree_serialize_write_type(context, tmp_cwt, qcbor_ctx);
    break;

  case np_treeval_type_jrb_tree: {
    size_t buf_size = np_tree_get_byte_size(val.value.tree);
    log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG,
                  "write: buffer size for subtree %d (%hd %hd) %hd",
                  val.size,
                  val.value.tree->size,
                  val.value.tree->byte_size,
                  buf_size);
    QCBOREncode_AddTag(qcbor_ctx,
                       (NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_jrb_tree));
    QCBOREncode_OpenMap(qcbor_ctx);

    np_tree_elem_t *tmp = NULL;
    RB_FOREACH (tmp, np_tree_s, val.value.tree) {

      if (np_treeval_type_int == tmp->key.type ||
          np_treeval_type_dhkey == tmp->key.type ||
          np_treeval_type_unsigned_long == tmp->key.type ||
          np_treeval_type_double == tmp->key.type ||
          np_treeval_type_char_ptr == tmp->key.type) {

        __np_tree_serialize_write_type(context, tmp->key, qcbor_ctx);
        __np_tree_serialize_write_type(context, tmp->val, qcbor_ctx);

        log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG,
                      "known key type for serialization %hd / %hd",
                      qcbor_ctx->OutBuf.data_len,
                      qcbor_ctx->nesting.pCurrentNesting->uCount);
      } else {
        log_msg(LOG_ERROR, "unknown key type for serialization");
      }
    }

    QCBOREncode_CloseMap(qcbor_ctx);

  } break;

  default:
    log_msg(LOG_WARNING,
            "please implement serialization for type %hhd",
            val.type);
    break;
  }
}

void np_serializer_read_map(np_state_t              *context,
                            np_deserialize_buffer_t *buffer,
                            np_tree_t               *tree) {
  bool ret             = true;
  buffer->_target_tree = tree;

  struct q_useful_buf_c qmp       = {.ptr = buffer->_buffer,
                                     .len = buffer->_buffer_size};
  QCBORDecodeContext    qcbor_ctx = {0};
  QCBORDecode_Init(&qcbor_ctx, qmp, QCBOR_DECODE_MODE_MAP_AS_ARRAY);

  np_treeval_t val = {0};
  __np_tree_deserialize_read_type(context,
                                  buffer->_target_tree,
                                  &qcbor_ctx,
                                  &val,
                                  "");

  log_debug_msg(LOG_INFO | LOG_SERIALIZATION,
                " deserialization work  %" PRId32 " %" PRId16
                " items (%d / %d)",
                buffer->_target_tree->size,
                np_tree_get_byte_size(buffer->_target_tree),
                qcbor_ctx.nesting.pCurrent->u.ma.uCountTotal,
                qcbor_ctx.nesting.pCurrent->u.ma.uCountCursor);

  QCBORError qcbor_ret = QCBORDecode_Finish(&qcbor_ctx);
  if (qcbor_ret == QCBOR_SUCCESS || qcbor_ret == QCBOR_ERR_EXTRA_BYTES) {
    log_debug_msg(LOG_INFO | LOG_SERIALIZATION,
                  "deserialization successful: %s",
                  qcbor_err_to_str(qcbor_ret));
    ret = true;
  } else {
    ret = false;
  }

  if (ret == false) {
    log_debug_msg(LOG_SERIALIZATION | LOG_WARNING,
                  "Deserialization error: unspecified error: %s",
                  qcbor_err_to_str(qcbor_ret));
    buffer->_error = 1;
    return;

  } else {
    if (buffer->_target_tree->attr.in_place == true) {
      buffer->_target_tree->attr.immutable = true;
    }
  }

  buffer->_bytes_read = qcbor_ctx.InBuf.cursor;
  buffer->_error      = qcbor_ctx.uLastError;
}

void np_serializer_add_map_bytesize(np_tree_t *tree, size_t *byte_size) {
  *byte_size += sizeof(uint8_t);
  if (tree->byte_size > UINT8_MAX) *byte_size += sizeof(uint16_t);
  else if (tree->byte_size >= 24) *byte_size += sizeof(uint8_t);
}

void np_serializer_write_map(np_state_t            *context,
                             np_serialize_buffer_t *buffer,
                             const np_tree_t       *tree) {
  np_treeval_t tmp_val = {.size       = tree->size,
                          .type       = np_treeval_type_jrb_tree,
                          .value.tree = tree};
  buffer->_tree        = tree;

  struct q_useful_buf qmp       = {.ptr = buffer->_target_buffer,
                                   .len = buffer->_buffer_size};
  QCBOREncodeContext  qcbor_ctx = {0};
  QCBOREncode_Init(&qcbor_ctx, qmp);

  __np_tree_serialize_write_type(context, tmp_val, &qcbor_ctx);

  struct q_useful_buf_c out_cmp  = {0};
  QCBORError            cbor_err = QCBOREncode_Finish(&qcbor_ctx, &out_cmp);

  if (cbor_err == QCBOR_SUCCESS) {
    buffer->_bytes_written = qcbor_ctx.OutBuf.data_len;
    buffer->_error         = qcbor_ctx.uError;
  } else {
    buffer->_bytes_written = buffer->_bytes_written;
    buffer->_error         = 1;
  }
}

enum np_data_return np_serializer_write_object(np_kv_buffer_t *to_write) {
  size_t write_len = to_write->buffer_end - to_write->buffer_start;

  struct q_useful_buf qmp = {.ptr = to_write->buffer_start, .len = write_len};
  QCBOREncodeContext  qcbor_ctx = {0};
  QCBOREncode_Init(&qcbor_ctx, qmp);

  QCBOREncode_AddText(
      &qcbor_ctx,
      (UsefulBufC){.ptr = to_write->key, .len = strnlen(to_write->key, 255)});

  if (to_write->data_type == NP_DATA_TYPE_BIN) {
    QCBOREncode_AddBytes(
        &qcbor_ctx,
        (UsefulBufC){.ptr = to_write->data.bin, .len = to_write->data_size});
  } else if (to_write->data_type == NP_DATA_TYPE_STR) {
    QCBOREncode_AddText(
        &qcbor_ctx,
        (UsefulBufC){.ptr = to_write->data.str, .len = to_write->data_size});
  } else if (to_write->data_type == NP_DATA_TYPE_INT) {
    QCBOREncode_AddTag(&qcbor_ctx,
                       NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_long);
    QCBOREncode_AddInt64(&qcbor_ctx, to_write->data.integer);
  } else if (to_write->data_type == NP_DATA_TYPE_UNSIGNED_INT) {
    QCBOREncode_AddTag(&qcbor_ctx,
                       NP_CBOR_REGISTRY_ENTRIES +
                           np_treeval_type_unsigned_long);
    QCBOREncode_AddUInt64(&qcbor_ctx, to_write->data.unsigned_integer);
  }

  struct q_useful_buf_c qmp_res = {0};
  if (0 == QCBOREncode_Finish(&qcbor_ctx, &qmp_res)) {
    to_write->buffer_end = to_write->buffer_start + qmp_res.len;
    return np_data_ok;
  } else {
    return np_could_not_write_total_length;
  }
}

enum np_data_return np_serializer_read_object(np_kv_buffer_t *to_read) {
  size_t read_len = to_read->buffer_end - to_read->buffer_start;

  struct q_useful_buf_c qmp = {.ptr = to_read->buffer_start, .len = read_len};
  QCBORDecodeContext    qcbor_ctx = {0};
  QCBORDecode_Init(&qcbor_ctx, qmp, QCBOR_DECODE_MODE_NORMAL);
  QCBORItem item = {0};

  QCBORDecode_VGetNext(&qcbor_ctx, &item);
  if (item.uDataType == QCBOR_TYPE_NONE) {
    QCBORDecode_Finish(&qcbor_ctx);
    return np_could_not_read_key;
  }
  strncpy(to_read->key, item.val.string.ptr, item.val.string.len);
  to_read->key[item.val.string.len] = '\0';

  QCBORDecode_VGetNext(&qcbor_ctx, &item);
  if (item.uDataType == QCBOR_TYPE_NONE) {
    QCBORDecode_Finish(&qcbor_ctx);
    return np_could_not_read_object;
  }

  if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
    to_read->data_type = NP_DATA_TYPE_BIN;
    to_read->data_size = item.val.string.len;
    to_read->data.bin  = (unsigned char *)item.val.string.ptr;
  } else if (item.uDataType == QCBOR_TYPE_TEXT_STRING) {
    to_read->data_type = NP_DATA_TYPE_STR;
    to_read->data_size = item.val.string.len;
    to_read->data.bin  = (unsigned char *)item.val.string.ptr;
  } else if (item.uDataType == QCBOR_TYPE_INT64) {
    if (item.uTags[0] == NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_long) {
      to_read->data_type = NP_DATA_TYPE_INT;
      to_read->data_size = sizeof(int32_t);
      QCBOR_Int64ToInt32(item.val.int64, &to_read->data.integer);
    } else if (item.uTags[0] ==
               NP_CBOR_REGISTRY_ENTRIES + np_treeval_type_unsigned_long) {
      to_read->data_type = NP_DATA_TYPE_UNSIGNED_INT;
      to_read->data_size = sizeof(uint32_t);
      QCBOR_Int64ToUInt32(item.val.uint64, &to_read->data.unsigned_integer);
    } else {
      return np_invalid_arguments;
    }
  } else if (item.uDataType == QCBOR_TYPE_UINT64) {
    return np_invalid_arguments;
  }
  // ... other types
  else {
    return np_invalid_arguments;
  }

  QCBORError ret = QCBORDecode_Finish(&qcbor_ctx);
  if (QCBOR_SUCCESS == ret || ret == QCBOR_ERR_EXTRA_BYTES) {
    to_read->buffer_end = to_read->buffer_start + qcbor_ctx.InBuf.cursor;
    return np_data_ok;
  } else {
    return np_invalid_structure;
  }
}

enum np_data_return np_serializer_search_object(np_datablock_header_t *block,
                                                char                  *key,
                                                np_kv_buffer_t        *kv_pair,
                                                uint32_t data_magic_no) {
  np_serializer_read_datablock_header(block, data_magic_no);
  //  np_serializer_skip_datablock_header(block);

  enum np_data_return ret          = np_key_not_found;
  uint16_t            objects_read = 0;

  kv_pair->buffer_start = np_skip_datablock_header(block);
  kv_pair->buffer_end   = block->_inner_blob + block->used_length;

  while (objects_read < block->object_count) {
    if (np_data_ok == np_serializer_read_object(kv_pair)) {
      if (strncmp(kv_pair->key, key, strnlen(key, 255)) == 0 &&
          strnlen(kv_pair->key, 255) == strnlen(key, 255)) {
        ret = np_data_ok;
        break;
      }
      objects_read++;
      kv_pair->buffer_start = kv_pair->buffer_end;
      kv_pair->buffer_end   = block->_inner_blob + block->used_length;
    }
  }
  return ret;
}

unsigned char *np_skip_datablock_header(np_datablock_header_t *block) {
  static const uint32_t overhead =
      sizeof(uint8_t) + /* major type 4 + array size (always 4 items) */
      // magic_no + total_length + used_length + object count
      4 * (sizeof(uint8_t) /* major type 0 */ + sizeof(uint32_t))
      // sizeof(uint8_t) +  /* major type 5 (map)  */
      // sizeof(uint16_t)   /* number of objects in map */
      ;

  return &block->_inner_blob[overhead];
}

enum np_data_return
np_serializer_read_datablock_header(np_datablock_header_t *block,
                                    uint32_t               data_magic_no) {
  uint32_t magic_no = 0;
  uint32_t overhead = sizeof(uint8_t) /*marker+value*/ + // fixarray
                      4 * (sizeof(uint8_t) /*marker*/ + sizeof(uint32_t))
      /*value:->see right*/ // magic_no + total_length
                            // + used_length
      ;                     // 21 byte

  struct q_useful_buf_c qmp = {.ptr = block->_inner_blob, .len = overhead};
  QCBORDecodeContext    qcbor_ctx = {0};
  QCBORDecode_Init(&qcbor_ctx, qmp, QCBOR_DECODE_MODE_NORMAL);
  QCBORItem item = {0};

  QCBORDecode_VGetNext(&qcbor_ctx, &item);
  if (!(item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 4)) {
    return np_invalid_arguments;
  }

  QCBORDecode_VGetNext(&qcbor_ctx, &item);
  if (!(item.uDataType == QCBOR_TYPE_INT64 &&
        (0 == QCBOR_Int64ToUInt32(item.val.int64, &magic_no)) &&
        magic_no == data_magic_no)) // magic_no
  {
    return np_could_not_read_magicno;
  }

  QCBORDecode_VGetNext(&qcbor_ctx, &item);
  if (!(item.uDataType == QCBOR_TYPE_INT64 &&
        0 == QCBOR_Int64ToUInt32(
                 item.val.int64,
                 (uint32_t *)&block->total_length))) // total_length
  {
    return np_could_not_read_total_length;
  }

  QCBORDecode_VGetNext(&qcbor_ctx, &item);
  if (!(item.uDataType == QCBOR_TYPE_INT64 &&
        0 == QCBOR_Int64ToUInt32(
                 item.val.int64,
                 (uint32_t *)&block->used_length))) // used_length
  {
    return np_could_not_read_used_length;
  }

  QCBORDecode_VGetNext(&qcbor_ctx, &item);
  if (!(item.uDataType == QCBOR_TYPE_INT64 &&
        0 == QCBOR_Int64ToUInt32(item.val.int64,
                                 &block->object_count))) // object_count
  {
    return np_could_not_read_object_count;
  }

  QCBORError ret = QCBORDecode_Finish(&qcbor_ctx);
  if (QCBOR_SUCCESS == ret || ret == QCBOR_ERR_EXTRA_BYTES) {
    return np_data_ok;
  } else {
    return np_invalid_structure;
  }
}

enum np_data_return
np_serializer_write_datablock_header(np_datablock_header_t *block,
                                     uint32_t               data_magic_no) {
  uint32_t overhead = sizeof(uint8_t) /*marker+value*/ + // fixarray
                      4 * (sizeof(uint8_t) /*marker*/ + sizeof(uint32_t))
      /*value:->see right*/ // magic_no + total_length
                            // + used_length
      ;

  if (block->used_length == 0) {
    block->used_length = overhead;
    memset(block->_inner_blob, 0, block->total_length);
  }
  struct q_useful_buf qmp       = {.ptr = block->_inner_blob,
                                   .len = block->total_length};
  QCBOREncodeContext  qcbor_ctx = {0};
  QCBOREncode_Init(&qcbor_ctx, qmp);

  QCBOREncode_OpenArray(&qcbor_ctx);

  QCBOREncode_AddUInt64(&qcbor_ctx, data_magic_no);
  // QCBOREncode_AddUInt64(&qcbor_ctx, block->total_length);
  AppendCBORHeadWithSize(&qcbor_ctx,
                         CBOR_MAJOR_TYPE_POSITIVE_INT,
                         block->total_length,
                         4);
  qcbor_ctx.nesting.pCurrentNesting->uCount++;
  //  QCBOREncode_AddUInt64(&qcbor_ctx, block->used_length);
  AppendCBORHeadWithSize(&qcbor_ctx,
                         CBOR_MAJOR_TYPE_POSITIVE_INT,
                         block->used_length,
                         4);
  qcbor_ctx.nesting.pCurrentNesting->uCount++;
  //    IncrementMapOrArrayCount(&qcbor_ctx);
  //  QCBOREncode_AddUInt64(&qcbor_ctx, block->object_count);
  AppendCBORHeadWithSize(&qcbor_ctx,
                         CBOR_MAJOR_TYPE_POSITIVE_INT,
                         block->object_count,
                         4);
  qcbor_ctx.nesting.pCurrentNesting->uCount++;
  //    IncrementMapOrArrayCount(&qcbor_ctx);

  //   QCBOREncode_OpenMap(&qcbor_ctx);
  //   QCBOREncode_CloseMap()

  QCBOREncode_CloseArray(&qcbor_ctx);
  struct q_useful_buf_c qmp_res = {0};

  if (0 == QCBOREncode_Finish(&qcbor_ctx, &qmp_res)) {
    //    block->used_length = qcbor_ctx.OutBuf.data_len;
    return np_data_ok;
  } else {
    return np_invalid_structure;
  }
}

enum np_data_return np_serializer_calculate_object_size(np_kv_buffer_t kv_pair,
                                                        size_t *object_size) {
  // check for space in block
  uint8_t key_size = strnlen(kv_pair.key, 255);
  *object_size =
      sizeof(uint8_t) /* major type 3 */ + key_size /*Key*/ /*NULL byte*/;
  if (key_size > CBOR_TWENTY_FOUR) (*object_size)++;

  if (kv_pair.data_type == NP_DATA_TYPE_BIN) {
    if (kv_pair.data_size > UINT8_MAX) *object_size += sizeof(uint16_t);
    else if (kv_pair.data_size > CBOR_TWENTY_FOUR)
      *object_size += sizeof(uint8_t);
    *object_size +=
        sizeof(uint8_t) /* major type 2 tag */ + kv_pair.data_size /* data */;

  } else if (kv_pair.data_type == NP_DATA_TYPE_STR) {
    // kv_pair.data_size = strnlen(kv_pair.data.str, 512);
    if (kv_pair.data_size > UINT8_MAX) *object_size += sizeof(uint16_t);
    else if (kv_pair.data_size > CBOR_TWENTY_FOUR)
      *object_size += sizeof(uint8_t);
    *object_size += sizeof(uint8_t) /* major type 3 tag */ +
                    kv_pair.data_size /* the string itself */;

  } else if (kv_pair.data_type == NP_DATA_TYPE_INT) {
    *object_size += sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t);
    int32_t data_abs_value =
        kv_pair.data.integer > 0 ? kv_pair.data.integer : -kv_pair.data.integer;
    if (data_abs_value > UINT16_MAX) *object_size += sizeof(uint32_t);
    else if (data_abs_value > UINT8_MAX) *object_size += sizeof(uint16_t);
    else if (data_abs_value > CBOR_TWENTY_FOUR) *object_size += sizeof(uint8_t);

  } else if (kv_pair.data_type == NP_DATA_TYPE_UNSIGNED_INT) {
    *object_size += sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t);
    if (kv_pair.data.unsigned_integer > UINT16_MAX)
      *object_size += sizeof(uint32_t);
    else if (kv_pair.data.unsigned_integer > UINT8_MAX)
      *object_size += sizeof(uint16_t);
    else if (kv_pair.data.unsigned_integer > CBOR_TWENTY_FOUR)
      *object_size += sizeof(uint8_t);
  } else {
    // other data types
    ASSERT(false,
           "missing implementation for type %" PRIu32,
           (uint32_t)kv_pair.data_type);
    return np_invalid_arguments;
  }
  return np_data_ok;
}

/*
    cose header

    Headers = (
        protected : empty_or_serialized_map,
        unprotected : header_map
    )

    header_map = {
        Generic_Headers,
        * label => values
    }

    empty_or_serialized_map = bstr .cbor header_map / bstr .size 0

    Generic_Headers = (
        ? 1 => int / tstr,  ; algorithm identifier
        ? 2 => [+label],    ; criticality
        ? 3 => tstr / int,  ; content type
        ? 4 => bstr,        ; key identifier
        ? 5 => bstr,        ; IV
        ? 6 => bstr,        ; Partial IV
        ? 7 => COSE_Signature / [+COSE_Signature] ; Counter signature
    )

    cose signed payload (multiple signatures)

    COSE_Sign = [
        Headers,
        payload : bstr / nil,
        signatures : [+ COSE_Signature]
    ]

    cose signature

    COSE_Signature =  [
        Headers,
        signature : bstr
    ]

    Sig_structure = [
        context : "Signature" / "Signature1" / "CounterSignature",
        body_protected : empty_or_serialized_map,
        ? sign_protected : empty_or_serialized_map,
        external_aad : bstr,
        payload : bstr
    ]

    cose encrypted object

    COSE_Encrypt = [
        Headers,
        ciphertext : bstr / nil,
        recipients : [+COSE_recipient]
    ]

    COSE_recipient = [
        Headers,
        ciphertext : bstr / nil,
        ? recipients : [+COSE_recipient]
    ]

    cose aead encryption

    Enc_structure = [
        context : "Encrypt" / "Encrypt0" / "Enc_Recipient" /
            "Mac_Recipient" / "Rec_Recipient",
        protected : empty_or_serialized_map,
        external_aad : bstr
    ]

    4.  Summary of the Claim Names, Keys, and Value Types

    +------+-----+----------------------------------+
    | Name | Key | Value Type                       |
    +------+-----+----------------------------------+
    | iss  | 1   | text string                      |
    | sub  | 2   | text string                      |
    | aud  | 3   | text string                      |
    | exp  | 4   | integer or floating-point number |
    | nbf  | 5   | integer or floating-point number |
    | iat  | 6   | integer or floating-point number |
    | cti  | 7   | byte string                      |
    +------+-----+----------------------------------+
*/

bool np_serializer_write_nptoken(const struct np_token *token,
                                 void                  *buffer,
                                 size_t                *buffer_length) {
  log_trace_msg(LOG_TRACE | LOG_AAATOKEN,
                "start: void np_serializer_write_nptoken(np_tree_t* data, "
                "np_aaatoken_t* token){");

  size_t used_bytes = 0;
  // np_state_t* context = np_ctx_by_memory(token);
  // if(trace) _np_aaatoken_trace_info("encode", token);
  // included into np_token_handshake
  struct q_useful_buf cose_sign_buffer = {.ptr = buffer, .len = *buffer_length};
  QCBOREncodeContext  encoder          = {0};
  QCBOREncode_Init(&encoder, cose_sign_buffer);

  QCBOREncode_AddTag(&encoder, CBOR_TAG_COSE_SIGN);
  QCBOREncode_OpenMap(&encoder);

  char null_block[NP_FINGERPRINT_BYTES] = {0};

  if (memcmp(token->issuer, null_block, NP_FINGERPRINT_BYTES) != 0)
    QCBOREncode_AddBytesToMapN(
        &encoder,
        1,
        (struct q_useful_buf_c){.ptr = token->issuer,
                                .len = NP_FINGERPRINT_BYTES});
  QCBOREncode_AddTextToMapN(
      &encoder,
      2,
      (struct q_useful_buf_c){.ptr = token->subject,
                              .len = strnlen(token->subject, 255)});

  if (memcmp(token->audience, null_block, NP_FINGERPRINT_BYTES) != 0)
    QCBOREncode_AddBytesToMapN(
        &encoder,
        3,
        (struct q_useful_buf_c){.ptr = token->audience,
                                .len = NP_FINGERPRINT_BYTES});

  QCBOREncode_AddDoubleToMapN(&encoder, 4, token->expires_at);
  QCBOREncode_AddDoubleToMapN(&encoder, 5, token->not_before);
  QCBOREncode_AddDoubleToMapN(&encoder, 6, token->issued_at);

  QCBOREncode_AddTextToMapN(
      &encoder,
      7,
      (struct q_useful_buf_c){.ptr = token->uuid, .len = NP_UUID_BYTES});

  size_t attributes_size;
  np_get_data_size(token->attributes, &attributes_size);

  // QCBOREncode_AddUInt64ToMap(&encoder, "np:type", token->type);
  if (memcmp(token->realm, null_block, NP_FINGERPRINT_BYTES) != 0)
    QCBOREncode_AddBytesToMap(
        &encoder,
        "np:realm",
        (struct q_useful_buf_c){.ptr = token->realm,
                                .len = NP_FINGERPRINT_BYTES});
  QCBOREncode_AddBytesToMap(&encoder,
                            "np:attr",
                            (struct q_useful_buf_c){.ptr = token->attributes,
                                                    .len = attributes_size});
  // TODO: next line actually needs to be in the cbor key format
  QCBOREncode_AddBytesToMap(
      &encoder,
      "np:pk",
      (struct q_useful_buf_c){.ptr = token->public_key,
                              .len = NP_PUBLIC_KEY_BYTES});
  QCBOREncode_CloseMap(&encoder);

  struct q_useful_buf_c cbor_token = {0};
  QCBOREncode_Finish(&encoder, &cbor_token);
  if (encoder.uError != QCBOR_ERR_EXTRA_BYTES &&
      encoder.uError != QCBOR_SUCCESS)
    // we need extra bytes in the buffer for the signatures at this point
    return false;

  used_bytes += cbor_token.len;

  struct q_useful_buf cose_signature_buffer = {
      .ptr = buffer + cbor_token.len,
      .len = (*buffer_length - cbor_token.len)};

  // QCBOREncodeContext encoder = {0};
  QCBOREncode_Init(&encoder, cose_signature_buffer);

  QCBOREncode_OpenMap(&encoder);

  QCBOREncode_AddBytesToMapN(
      &encoder,
      1,
      (struct q_useful_buf_c){.ptr = token->signature,
                              .len = NP_SIGNATURE_BYTES});
  QCBOREncode_AddBytesToMapN(
      &encoder,
      2,
      (struct q_useful_buf_c){.ptr = token->attributes_signature,
                              .len = NP_SIGNATURE_BYTES});

  QCBOREncode_CloseMap(&encoder);
  QCBOREncode_Finish(&encoder, &cbor_token);
  if (encoder.uError == QCBOR_ERR_EXTRA_BYTES ||
      encoder.uError == QCBOR_SUCCESS) {
    used_bytes += cbor_token.len;
    *buffer_length = used_bytes;
    return true;
  }
  return false;
}

bool np_serializer_read_nptoken(const void      *buffer,
                                size_t          *buffer_length,
                                struct np_token *token) {
  assert(NULL != buffer);
  assert(NULL != token);

  size_t read_bytes = 0;

  uint8_t               qcbor_error = QCBOR_SUCCESS;
  struct q_useful_buf_c cbor_decode = {.ptr = buffer, .len = *buffer_length};

  QCBORDecodeContext decoder = {};
  QCBORDecode_Init(&decoder, cbor_decode, QCBOR_DECODE_MODE_NORMAL);
  QCBORItem item = {0};

  QCBORDecode_PeekNext(&decoder, &item);
  if (!(item.uDataType == QCBOR_TYPE_MAP &&
        item.uTags[0] == CBOR_TAG_COSE_SIGN)) {
    return false;
  }
  QCBORDecode_EnterMap(&decoder, &item);

  struct q_useful_buf_c token_element = {0};

  QCBORDecode_GetByteStringInMapN(&decoder, 1, &token_element);
  qcbor_error = QCBORDecode_GetAndResetError(&decoder);
  if (qcbor_error == QCBOR_ERR_LABEL_NOT_FOUND) {
    // empty, add checks for more errors
  } else {
    if (qcbor_error == QCBOR_SUCCESS ||
        item.uDataType == QCBOR_TYPE_BYTE_STRING)
      memmove(token->issuer, token_element.ptr, NP_FINGERPRINT_BYTES);
  }

  QCBORDecode_GetTextStringInMapN(&decoder, 2, &token_element);
  if (decoder.uLastError != QCBOR_SUCCESS) {
    return false;
  }
  memmove(token->subject, token_element.ptr, MIN(token_element.len, 255));

  QCBORDecode_GetByteStringInMapN(&decoder, 3, &token_element);
  qcbor_error = QCBORDecode_GetAndResetError(&decoder);
  if (qcbor_error == QCBOR_ERR_LABEL_NOT_FOUND) {
    // empty, add checks for more errors
  } else {
    if (qcbor_error == QCBOR_SUCCESS ||
        item.uDataType == QCBOR_TYPE_BYTE_STRING)
      memmove(token->audience, token_element.ptr, NP_FINGERPRINT_BYTES);
  }
  double temp_value = 0.0;
  QCBORDecode_GetDoubleInMapN(&decoder, 4, &temp_value);
  if (decoder.uLastError == QCBOR_SUCCESS) token->expires_at = temp_value;
  QCBORDecode_GetDoubleInMapN(&decoder, 5, &temp_value);
  if (decoder.uLastError == QCBOR_SUCCESS) token->not_before = temp_value;
  QCBORDecode_GetDoubleInMapN(&decoder, 6, &temp_value);
  if (decoder.uLastError == QCBOR_SUCCESS) token->issued_at = temp_value;

  QCBORDecode_GetTextStringInMapN(&decoder, 7, &token_element);
  if (decoder.uLastError != QCBOR_SUCCESS) {
    return false;
  }
  memcpy(token->uuid, token_element.ptr, NP_UUID_BYTES);

  // QCBORDecode_GetUInt64InMapSZ(&decoder, "np:type", &token->type);

  QCBORDecode_GetByteStringInMapSZ(&decoder, "np:realm", &token_element);
  qcbor_error = QCBORDecode_GetAndResetError(&decoder);
  if (qcbor_error == QCBOR_ERR_LABEL_NOT_FOUND) {
    // empty, add checks for more errors
  } else {
    if (qcbor_error == QCBOR_SUCCESS ||
        item.uDataType == QCBOR_TYPE_BYTE_STRING)
      memmove(token->realm, token_element.ptr, NP_FINGERPRINT_BYTES);
  }

  QCBORDecode_GetByteStringInMapSZ(&decoder, "np:attr", &token_element);
  if (decoder.uLastError != QCBOR_SUCCESS) {
    return false;
  }
  memmove(token->attributes, token_element.ptr, token_element.len);

  // TODO: next line actually needs to be in the cbor key format
  QCBORDecode_GetByteStringInMapSZ(&decoder, "np:pk", &token_element);
  if (decoder.uLastError != QCBOR_SUCCESS ||
      token_element.len != NP_PUBLIC_KEY_BYTES) {
    return false;
  }
  memmove(token->public_key, token_element.ptr, NP_PUBLIC_KEY_BYTES);
  // token->crypto.ed25519_public_key_is_set = true;
  // token->private_key_is_set               = false;

  QCBORDecode_ExitMap(&decoder);
  QCBORDecode_Finish(&decoder);

  if (!(decoder.uLastError == QCBOR_ERR_EXTRA_BYTES ||
        decoder.uLastError == QCBOR_SUCCESS))
    return false;
  read_bytes += decoder.InBuf.cursor;
  cbor_decode.ptr = buffer + decoder.InBuf.cursor;
  cbor_decode.len = *buffer_length - decoder.InBuf.cursor;

  QCBORDecode_Init(&decoder, cbor_decode, QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterMap(&decoder, &item);

  QCBORDecode_GetByteStringInMapN(&decoder, 1, &token_element);
  if (decoder.uLastError != QCBOR_SUCCESS ||
      token_element.len != NP_SIGNATURE_BYTES) {
    return false;
  }
  memcpy(token->signature, token_element.ptr, NP_SIGNATURE_BYTES);
  // token->is_signature_verified = false;

  QCBORDecode_GetByteStringInMapN(&decoder, 2, &token_element);
  if (decoder.uLastError != QCBOR_SUCCESS ||
      token_element.len != NP_SIGNATURE_BYTES) {
    return false;
  }
  memcpy(token->attributes_signature, token_element.ptr, NP_SIGNATURE_BYTES);
  // token->is_signature_verified = false;

  QCBORDecode_ExitMap(&decoder);
  QCBORDecode_Finish(&decoder);

  if (decoder.uLastError == QCBOR_ERR_EXTRA_BYTES ||
      decoder.uLastError == QCBOR_SUCCESS)
    return true;
  read_bytes += decoder.InBuf.cursor;
  *buffer_length = read_bytes;
  return false;
}

/*
COSE_Key = {
    1 => tstr / int,          ; kty - identification of type
    ? 2 => bstr,              ; kid - identification of key
    ? 3 => tstr / int,        ; alg - usage restriction
    ? 4 => [+ (tstr / int) ], ; key_ops - permissible operations
    ? 5 => bstr,              ; Base IV - initializatioon vector
    * label => values
}
*/
bool np_serializer_write_ed25519(
    const unsigned char *sk_value[NP_SECRET_KEY_BYTES],
    const unsigned char *pk_value[NP_PUBLIC_KEY_BYTES],
    bool                 include_secret_key,
    np_id               *identifier,
    void                *buffer,
    size_t              *buffer_length) {
  ASSERT(pk_value != NULL || sk_value != NULL,
         "need to have at least one type of key material");
  ASSERT(identifier != NULL, "need to have an identifier for the key");

  struct q_useful_buf cose_sign_buffer = {.ptr = buffer, .len = *buffer_length};
  QCBOREncodeContext  encoder          = {0};
  QCBOREncode_Init(&encoder, cose_sign_buffer);
  QCBOREncode_OpenMap(&encoder);

  // 1 - 1 OKP . Octect Key Pair
  QCBOREncode_AddInt64ToMapN(&encoder, 1, 1);

  // 2 - np hash value
  if (!_np_dhkey_equal(identifier, &dhkey_zero)) {
    QCBOREncode_AddBytesToMapN(
        &encoder,
        2,
        (struct q_useful_buf_c){.ptr = identifier,
                                .len = NP_FINGERPRINT_BYTES});
  }
  // 3 - used algorithm (do not use for now)

  // 4 - [ 1(sign), 2(verify), 7(derive key) ]
  QCBOREncode_OpenArrayInMapN(&encoder, 4);
  QCBOREncode_AddUInt64(&encoder, 1); // sign
  QCBOREncode_AddUInt64(&encoder, 2); // verify
  QCBOREncode_AddUInt64(&encoder, 7); // derive key
  QCBOREncode_CloseArray(&encoder);

  // 5 - iv (do not use for now)

  // crv  1 -1  int / tstr 	Ed25519 / OKP / 6 / Ed25519 for use w/ EdDSA
  // only x 	  1 -2  bstr 	X Coordinate (pk) d 	  1 -4  bstr
  // Private key (sk)
  QCBOREncode_AddInt64ToMapN(&encoder, -1, 6);
  char null_block[NP_SECRET_KEY_BYTES] = {0};
  if (memcmp(pk_value, &null_block, NP_PUBLIC_KEY_BYTES) != 0)
    QCBOREncode_AddBytesToMapN(
        &encoder,
        -2,
        (struct q_useful_buf_c){.ptr = pk_value, .len = NP_PUBLIC_KEY_BYTES});
  if (include_secret_key &&
      memcmp(sk_value, &null_block, NP_SECRET_KEY_BYTES) != 0)
    QCBOREncode_AddBytesToMapN(
        &encoder,
        -4,
        (struct q_useful_buf_c){.ptr = sk_value, .len = NP_SECRET_KEY_BYTES});

  QCBOREncode_CloseMap(&encoder);

  struct q_useful_buf_c cbor_token = {0};
  QCBOREncode_Finish(&encoder, &cbor_token);
  if (encoder.uError != QCBOR_ERR_EXTRA_BYTES &&
      encoder.uError != QCBOR_SUCCESS)
    // we need extra bytes in the buffer for the signatures at this point
    return false;

  *buffer_length = encoder.OutBuf.data_len;

  return true;
}

bool np_serializer_read_ed25519(const void    *buffer,
                                size_t        *buffer_length,
                                np_id         *identifier,
                                unsigned char *sk_value[NP_SECRET_KEY_BYTES],
                                unsigned char *pk_value[NP_PUBLIC_KEY_BYTES]) {
  assert(NULL != buffer);
  assert(NULL != sk_value);
  assert(NULL != pk_value);

  uint8_t               qcbor_error = QCBOR_SUCCESS;
  struct q_useful_buf_c cbor_decode = {.ptr = buffer, .len = *buffer_length};

  QCBORDecodeContext decoder = {};
  QCBORDecode_Init(&decoder, cbor_decode, QCBOR_DECODE_MODE_NORMAL);
  QCBORItem item = {0};

  QCBORDecode_PeekNext(&decoder, &item);
  if (!(item.uDataType == QCBOR_TYPE_MAP)) {
    return false;
  }
  QCBORDecode_EnterMap(&decoder, &item);

  struct q_useful_buf_c key_element = {0};
  int64_t               value;

  // 1 - 1 OKP . Octect Key Pair

  QCBORDecode_GetInt64InMapN(&decoder, 1, &value);
  if (decoder.uLastError != QCBOR_SUCCESS || value != 1) return false;

  // 2 - np hash value
  QCBORDecode_GetByteStringInMapN(&decoder, 2, &key_element);
  qcbor_error = QCBORDecode_GetAndResetError(&decoder);
  if (qcbor_error == QCBOR_ERR_LABEL_NOT_FOUND) {
    // could be empty, add checks for more errors
  } else if (qcbor_error == QCBOR_SUCCESS) {
    memmove(*identifier, key_element.ptr, NP_FINGERPRINT_BYTES);
  }
  // 3 - used algorithm (do not use for now)

  // 4 - [ 1(sign), 2(verify), 7(derive key) ]
  QCBORDecode_EnterArrayFromMapN(&decoder, 4);
  QCBORDecode_GetInt64(&decoder, &value);
  if (value != 1) return false;
  QCBORDecode_GetInt64(&decoder, &value);
  if (value != 2) return false;
  QCBORDecode_GetInt64(&decoder, &value);
  if (value != 7) return false;
  QCBORDecode_ExitArray(&decoder);

  // 5 - iv (do not use for now)

  // crv  1 -1  int / tstr 	Ed25519 / OKP / 6 / Ed25519 for use w/ EdDSA
  // x 	  1 -2  bstr 	X Coordinate (pk)
  // d    1 -4  bstr privatekey (sk)
  QCBORDecode_GetInt64(&decoder, &value);
  if (value != 6) return false;

  bool private_or_public_key_set = false;
  QCBORDecode_GetByteStringInMapN(&decoder, -2, &key_element);
  qcbor_error = QCBORDecode_GetAndResetError(&decoder);
  if (qcbor_error == QCBOR_ERR_LABEL_NOT_FOUND) {
    // empty, add checks for more errors
  } else {
    if (qcbor_error == QCBOR_SUCCESS ||
        item.uDataType == QCBOR_TYPE_BYTE_STRING)
      memmove(pk_value, key_element.ptr, NP_PUBLIC_KEY_BYTES);
    private_or_public_key_set = true;
  }

  QCBORDecode_GetByteStringInMapN(&decoder, -4, &key_element);
  qcbor_error = QCBORDecode_GetAndResetError(&decoder);
  if (qcbor_error == QCBOR_ERR_LABEL_NOT_FOUND) {
    // empty, add checks for more errors
  } else {
    if (qcbor_error == QCBOR_SUCCESS ||
        item.uDataType == QCBOR_TYPE_BYTE_STRING)
      memmove(sk_value, key_element.ptr, NP_SECRET_KEY_BYTES);
    private_or_public_key_set = true;
  }

  if (private_or_public_key_set == false) return false;

  QCBORDecode_ExitMap(&decoder);
  QCBORDecode_Finish(&decoder);

  if (!(decoder.uLastError == QCBOR_ERR_EXTRA_BYTES ||
        decoder.uLastError == QCBOR_SUCCESS))
    return false;

  *buffer_length = decoder.InBuf.cursor;

  return true;
}

bool np_serializer_write_encrypted(void                *crypted_buffer,
                                   size_t              *cb_length,
                                   const unsigned char *nonce,
                                   const unsigned char *m,
                                   const size_t         m_len) {
  assert(NULL != crypted_buffer);
  assert(NULL != nonce);
  assert(*cb_length > m_len);

  struct q_useful_buf cose_encrypt0_buffer = {.ptr = crypted_buffer,
                                              .len = *cb_length};
  QCBOREncodeContext  encoder              = {0};
  QCBOREncode_Init(&encoder, cose_encrypt0_buffer);

  QCBOREncode_AddTag(&encoder, CBOR_TAG_COSE_ENCRYPT0);
  QCBOREncode_OpenArray(&encoder);
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddBytesToMapN(
      &encoder,
      6, // Partial IV for encrpyted content (nonce)
      (struct q_useful_buf_c){.ptr = nonce, .len = crypto_box_NONCEBYTES});
  QCBOREncode_CloseMap(&encoder);
  QCBOREncode_AddBytes(&encoder,
                       (struct q_useful_buf_c){.ptr = m, .len = m_len});
  QCBOREncode_CloseArray(&encoder);

  struct q_useful_buf_c cbor_token = {0};
  QCBOREncode_Finish(&encoder, &cbor_token);
  if (encoder.uError != QCBOR_ERR_EXTRA_BYTES &&
      encoder.uError != QCBOR_SUCCESS)
    return false;

  *cb_length = encoder.OutBuf.data_len;

  return true;
}

bool np_serializer_read_encrypted(const void    *input_buffer,
                                  size_t        *ib_length,
                                  unsigned char *nonce,
                                  unsigned char *crypted_buffer,
                                  size_t        *cb_len) {
  assert(NULL != input_buffer);
  assert(NULL != nonce);
  assert(*ib_length >= *cb_len);

  struct q_useful_buf_c cbor_decode = {.ptr = input_buffer, .len = *ib_length};

  QCBORDecodeContext decoder = {};
  QCBORDecode_Init(&decoder, cbor_decode, QCBOR_DECODE_MODE_NORMAL);
  QCBORItem item = {0};

  QCBORDecode_PeekNext(&decoder, &item);
  if (!(item.uDataType == QCBOR_TYPE_ARRAY &&
        item.uTags[0] == CBOR_TAG_COSE_ENCRYPT0)) {
    return false;
  }

  QCBORDecode_EnterArray(&decoder, &item);

  QCBORDecode_EnterMap(&decoder, &item);
  struct q_useful_buf_c crypt_element = {0};
  QCBORDecode_GetByteStringInMapN(&decoder, 6, &crypt_element);
  if (decoder.uLastError == QCBOR_SUCCESS &&
      crypt_element.len == crypto_box_NONCEBYTES) {
    memmove(nonce, crypt_element.ptr, crypto_box_NONCEBYTES);
  } else {
    return false;
  }
  QCBORDecode_ExitMap(&decoder);

  QCBORDecode_GetByteString(&decoder, &crypt_element);
  if (decoder.uLastError == QCBOR_SUCCESS && crypt_element.len <= *cb_len) {
    memmove(crypted_buffer, crypt_element.ptr, crypt_element.len);
    *cb_len = crypt_element.len;
  } else {
    return false;
  }
  QCBORDecode_Finish(&decoder);

  if (!(decoder.uLastError == QCBOR_ERR_EXTRA_BYTES ||
        decoder.uLastError == QCBOR_SUCCESS))
    return false;

  *ib_length = decoder.InBuf.cursor;

  return true;
}
