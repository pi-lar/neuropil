#ifndef	_NP_UTIL_H_
#define	_NP_UTIL_H_

#include "cmp.h"

#include "jrb.h"

//typedef void (*f_destructor)(void *, void *);
//
//enum np_e_pointer {
//    UNIQUE,
//    SHARED,
//    ARRAY = 1 << 8
//};
//
//struct np_malloc_meta_s {
//    int sentinel_;
//    enum np_e_pointer type;
//    f_destructor dtor;
//    void **ref_ptr;
//    struct {
//        const void *data;
//        size_t size;
//    } meta;
//};
//
//#define new(__ptr_e_type, __type__) ( \
//	meta = malloc(sizeof(struct np_malloc_meta_s)) \
//	meta.type = ptr_e_type \
//	meta.qref_ptr = malloc(sizeof(__type__)) \
//	return (__type__*) meta)
//
//#define delete(__obj__)  free(__obj__)
//
//#define smart_ptr(ptr_e_type, __type__, __args__) ()
//
//#define shared_ptr(__type__, __args__) smart_ptr(SHARED, __type__, __args__)
//#define unique_ptr(__type__, __args__) smart_ptr(UNIQUE, __type__, __args__)
//
//#define ref(__type__, __obj__) (__type__*) return __obj__.*ptr

np_bool buffer_reader(cmp_ctx_t *ctx, void *data, size_t count);
size_t buffer_writer(cmp_ctx_t *ctx, const void *data, size_t count);

void serialize_jrb_node_t(np_jrb_t* jrb, cmp_ctx_t* cmp);
void deserialize_jrb_node_t(np_jrb_t* jrb, cmp_ctx_t* cmp);

#endif // _NP_UTIL_H_
