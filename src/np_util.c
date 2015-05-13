/*
 *
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "np_util.h"

#include "jval.h"
#include "log.h"

void del_callback(void* data) {
	log_msg(LOG_ERROR, "del_callback should never be called !!!");
}
void new_callback(void* data) {
	log_msg(LOG_ERROR, "new_callback should never be called !!!");
}

np_bool buffer_reader(cmp_ctx_t *ctx, void *data, size_t count) {
	memcpy(data, ctx->buf, count);
	ctx->buf += count;
	return 1;
}

size_t buffer_writer(cmp_ctx_t *ctx, const void *data, size_t count) {
	// log_msg(LOG_DEBUG, "-- writing cmp->buf: %p size: %d", ctx->buf, count);
	memcpy(ctx->buf, data, count);
	ctx->buf += count;
	return count;
}

int write_type(np_jval_t val, cmp_ctx_t* cmp) {

	// void* count_buf_start = cmp->buf;
	// log_msg(LOG_DEBUG, "writing jrb (%p) value: %s", jrb, jrb->key.value.s);
	switch (val.type) {
	// signed numbers
//	case short_type:
//		cmp_write_s8(cmp, val.value.sh);
//		break;
	case int_type:
		cmp_write_s16(cmp, val.value.i);
		break;
	case long_type:
		cmp_write_s32(cmp, val.value.l);
		break;
	case long_long_type:
		cmp_write_s64(cmp, val.value.ll);
		break;
		// characters
	case char_ptr_type:
		cmp_write_str32(cmp, val.value.s,
				strlen(val.value.s));
		break;
	case char_type:
		cmp_write_fixstr(cmp, (const char*) &val.value.c,
				sizeof(char));
		break;
	// case unsigned_char_type:
	// 	cmp_write_str(cmp, (const char*) &val.value.uc,
	// 			sizeof(unsigned char));
	// 	break;
// float and double precision
	case float_type:
		cmp_write_float(cmp, val.value.f);
		break;
	case double_type:
		cmp_write_double(cmp, val.value.d);
		break;
// unsigned numbers
//	case unsigned_short_type:
//		cmp_write_u8(cmp, val.value.ush);
//		break;
	case unsigned_int_type:
		cmp_write_u16(cmp, val.value.ui);
		break;
	case unsigned_long_type:
		cmp_write_u32(cmp, val.value.ul);
		break;
	case unsigned_long_long_type:
		cmp_write_u64(cmp, val.value.ull);
		break;
	case int_array_2_type:
	case float_array_2_type:
	case char_array_8_type:
	case unsigned_char_array_8_type:
		log_msg(LOG_WARN, "please implement serialization for type %d",
				val.type);
		break;

	case void_type:
		// cmp_write_bin(cmp, val.value.v, sizeof(val.value.v));
		break;

	case bin_type:
		cmp_write_bin(cmp, val.value.bin, val.size);
		break;

	case jrb_tree_type:
		{
			cmp_ctx_t tree_cmp;
			char buffer[val.size];
			// log_msg(LOG_DEBUG, "buffer size for subtree %d %ll", val.value.tree->size, val.value.tree->byte_size);
			// log_msg(LOG_DEBUG, "buffer size for subtree %d", val.size);
			void* buf_ptr = buffer;
			cmp_init(&tree_cmp, buf_ptr, buffer_reader, buffer_writer);
			serialize_jrb_node_t(val.value.tree, &tree_cmp);
			int buf_size = tree_cmp.buf - buf_ptr;

			// log_msg(LOG_DEBUG, "now writing tree cmp extension type %d size %d", jrb_tree_type, buf_size);
			// write the serialized tree to the upper level buffer
			if (!cmp_write_ext(cmp, jrb_tree_type, buf_size, buf_ptr)) {
				log_msg(LOG_WARN, "couldn't write tree data -- ignoring for now");
			}
			// buffer_writer(cmp, buf_ptr, buf_size);
			// cmp_write_bin(cmp, buffer, buf_size);
			// log_msg(LOG_DEBUG, "assumed size %ul, real size %ul",
			// 		val.value.tree->byte_size + 20, buf_size);
		}
		break;
	default:
		log_msg(LOG_WARN, "unknown serialization to binary form for type %d -- ignoring for now", val.type);
		break;
	}
	// void* count_buf_end = cmp->buf;
	// log_msg(LOG_DEBUG, "wrote %d bytes ", (count_buf_end - count_buf_start));
	return 1;
}

void serialize_jrb_node_t(np_jrb_t* jrb, cmp_ctx_t* cmp)
{
	if (!cmp_write_map(cmp, jrb->size*2 )) return;
	// log_msg(LOG_WARN, cmp_strerror(cmp));
	if (jrb->size) {
		np_jrb_t* tmp = NULL;
		jrb_traverse(tmp, jrb)
		{
			// log_msg(LOG_DEBUG, "%p: key: %d, value: %d (%d/%d)", tmp, tmp->key.type, tmp->val.type, tmp->size, tmp->byte_size );
			// log_msg(LOG_DEBUG, "for (%p; %p!=%p; %p=%p) ", tmp->flink, tmp, msg->header, node, node->flink);
			write_type(tmp->key, cmp);
			write_type(tmp->val, cmp);
		}
	}

//	switch (jrb->key.type) {
//	case int_type:
//		log_msg(LOG_DEBUG, "wrote int key (%d)", jrb->key.value.i);
//		break;
//	case unsigned_long_type:
//		log_msg(LOG_DEBUG, "wrote uint key (%ul)", jrb->key.value.ul);
//		break;
//	case double_type:
//		log_msg(LOG_DEBUG, "wrote double key (%f)", jrb->key.value.d);
//		break;
//	case char_ptr_type:
//		log_msg(LOG_DEBUG, "wrote str key (%s)", jrb->key.value.s);
//		break;
//	}
}

void read_type(cmp_object_t* obj, cmp_ctx_t* cmp, np_jval_t* value) {

	switch (obj->type) {

	case CMP_TYPE_FIXMAP:
	case CMP_TYPE_MAP16:
	case CMP_TYPE_MAP32:
		log_msg(LOG_WARN,
				"error de-serializing message to normal form, found map type");
		break;
	case CMP_TYPE_FIXARRAY:
	case CMP_TYPE_ARRAY16:
	case CMP_TYPE_ARRAY32:
		log_msg(LOG_WARN,
				"error de-serializing message to normal form, found array type");
		break;

	case CMP_TYPE_FIXSTR:
		cmp->read(cmp, &value->value.c, sizeof(char));
		value->type = char_type;
		value->size = 1;
		break;

	case CMP_TYPE_STR8:
	case CMP_TYPE_STR16:
	case CMP_TYPE_STR32:
		{
			value->value.s = (char*) malloc(obj->as.str_size+1);
			cmp->read(cmp, value->value.s, obj->as.str_size * sizeof(char));
			value->type = char_ptr_type;
			value->size = obj->as.str_size;
			value->value.s[obj->as.str_size] = '\0';
			// log_msg(LOG_WARN, "string size %d/%d -> %s", value->size, strlen(value->value.s), value->value.s);
			break;
		}
	case CMP_TYPE_BIN8:
	case CMP_TYPE_BIN16:
	case CMP_TYPE_BIN32:
		{
			value->value.bin = malloc(obj->as.bin_size);
			value->type = bin_type;
			value->size = obj->as.bin_size;
			memset(value->value.bin, 0, value->size);
			cmp->read(cmp, value->value.bin, obj->as.bin_size);
			break;
		}
	case CMP_TYPE_NIL:
		log_msg(LOG_WARN, "unknown de-serialization for given type (cmp NIL) ");
		break;
	case CMP_TYPE_BOOLEAN:
		log_msg(LOG_WARN,
				"unknown de-serialization for given type (cmp boolean) ");
		break;
	case CMP_TYPE_EXT8:
	case CMP_TYPE_EXT16:
	case CMP_TYPE_EXT32:
	case CMP_TYPE_FIXEXT1:
	case CMP_TYPE_FIXEXT2:
	case CMP_TYPE_FIXEXT4:
	case CMP_TYPE_FIXEXT8:
	case CMP_TYPE_FIXEXT16:
		{
			// required for tree de-serialization
			// log_msg(LOG_DEBUG, "now reading cmp-extension type %d size %d", obj->as.ext.type, obj->as.ext.size);
			char buffer[obj->as.ext.size];
			void* buf_ptr = buffer;
			buffer_reader(cmp, buf_ptr, obj->as.ext.size);

			if (obj->as.ext.type == jrb_tree_type) {
				// tree type
				np_jrb_t* subtree = make_jrb();
				cmp_ctx_t tree_cmp;
				cmp_init(&tree_cmp, buf_ptr, buffer_reader, buffer_writer);
				deserialize_jrb_node_t(subtree, &tree_cmp);

				value->value.tree = subtree;
				value->type = jrb_tree_type;
				value->size = subtree->byte_size;
			} else {
				log_msg(LOG_WARN,
						"unknown de-serialization for given extension type %d", obj->as.ext.type);
			}
		}
		break;
	case CMP_TYPE_FLOAT:
		value->value.f = obj->as.flt;
		value->type = float_type;
		break;
	case CMP_TYPE_DOUBLE:
		value->value.d = obj->as.dbl;
		value->type = double_type;
		break;

	case CMP_TYPE_POSITIVE_FIXNUM:
	case CMP_TYPE_UINT8:
//		value->value.ush = obj->as.u8;
//		value->type = unsigned_short_type;
		break;
	case CMP_TYPE_UINT16:
		value->value.ui = obj->as.u16;
		value->type = unsigned_int_type;
		break;
	case CMP_TYPE_UINT32:
		value->value.ul = obj->as.u32;
		value->type = unsigned_long_type;
		break;
	case CMP_TYPE_UINT64:
		value->value.ull = obj->as.u64;
		value->type = unsigned_long_long_type;
		break;
	case CMP_TYPE_NEGATIVE_FIXNUM:
	case CMP_TYPE_SINT8:
//		value->value.sh = obj->as.s8;
//		value->type = short_type;
		break;
	case CMP_TYPE_SINT16:
		value->value.i = obj->as.s16;
		value->type = int_type;
		break;
	case CMP_TYPE_SINT32:
		value->value.l = obj->as.s32;
		value->type = long_type;
		break;
	case CMP_TYPE_SINT64:
		value->value.ll = obj->as.s64;
		value->type = long_long_type;
		break;
	default:
		log_msg(LOG_WARN, "unknown deserialization for given type");
		break;
	}
}

void deserialize_jrb_node_t(np_jrb_t* jrb, cmp_ctx_t* cmp) {

	cmp_object_t obj;
	unsigned int size = 0;

	if (!cmp_read_map(cmp, &size)) return;

	for (int i = 0; i < (size/2); i++) {
		// log_msg(LOG_DEBUG, "reading key (%d) from message part %p", i, jrb);
		// read key
		np_jval_t tmp_key;
		cmp_read_object(cmp, &obj);
		read_type(&obj, cmp, &tmp_key);

		// log_msg(LOG_DEBUG, "reading value (%d) from message part %p", i, jrb);
		// read value
		np_jval_t tmp_val;
		cmp_read_object(cmp, &obj);
		read_type(&obj, cmp, &tmp_val);

		switch (tmp_key.type) {
		case int_type:
			// log_msg(LOG_DEBUG, "read int key (%d)", tmp_key.value.i);
			jrb_insert_int(jrb, tmp_key.value.i, tmp_val);
			break;
		case unsigned_long_type:
			// log_msg(LOG_DEBUG, "read uint key (%ul)", tmp_key.value.ul);
			jrb_insert_ulong(jrb, tmp_key.value.ul, tmp_val);
			break;
		case double_type:
			// log_msg(LOG_DEBUG, "read double key (%f)", tmp_key.value.d);
			jrb_insert_dbl(jrb, tmp_key.value.d, tmp_val);
			break;
		case char_ptr_type:
			// log_msg(LOG_DEBUG, "read str key (%s)", tmp_key.value.s);
			jrb_insert_str(jrb, tmp_key.value.s, tmp_val);
			break;
		}
	}
	// log_msg(LOG_DEBUG, "read all key/value pairs from message part %p", jrb);
}
