//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "util/np_serialization.h"

#ifdef NP_USE_CMP

#include "s11n_impl/np_serialize_cmp.c"
// dummy implementation for msgpack serialization
inline bool np_serializer_write_nptoken(void                  *data_buffer,
                                        const struct np_token *token) {}
inline bool np_serializer_read_nptoken(const void      *data_buffer,
                                       struct np_token *token) {}

inline bool
np_serializer_write_ed25519(const unsigned char *sk_value[NP_SECRET_KEY_BYTES],
                            const unsigned char *pk_value[NP_PUBLIC_KEY_BYTES],
                            bool                 include_secret_key,
                            const np_id         *identifier,
                            void                *buffer,
                            size_t              *buffer_length) {}

inline bool
np_serializer_read_ed25519(const void    *buffer,
                           const size_t   buffer_length,
                           np_id         *identifier,
                           unsigned char *sk_value[NP_SECRET_KEY_BYTES],
                           unsigned char *pk_value[NP_PUBLIC_KEY_BYTES]) {}

bool np_serializer_write_encrypted(void                *crypted_buffer,
                                   size_t              *cb_length,
                                   const unsigned char *nonce,
                                   const unsigned char *m,
                                   const size_t         m_len) {}

bool np_serializer_read_encrypted(void                *crypted_buffer,
                                  size_t              *cb_length,
                                  unsigned char       *nonce,
                                  unsigned const char *m,
                                  size_t               m_len) {}

#endif

#ifdef NP_USE_QCBOR

#include "s11n_impl/np_serialize_qcbor.c"

#endif
