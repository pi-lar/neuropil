//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "np_crypto.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

#include "sodium.h"

#include "neuropil_log.h"

#include "util/np_serialization.h"
#include "util/np_tree.h"

#include "np_constants.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_types.h"
#include "np_util.h"

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(
    np_crypto_encrypted_intermediate_key_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_crypto_encrypted_intermediate_key_ptr);

void _np_crypto_t_new(NP_UNUSED np_state_t *context,
                      NP_UNUSED uint8_t     type,
                      NP_UNUSED size_t      size,
                      void                 *data) {
  np_crypto_init((np_crypto_t *)data);
}

void np_crypto_init(np_crypto_t *self) {
  self->ed25519_public_key_is_set    = false;
  self->ed25519_secret_key_is_set    = false;
  self->derived_kx_public_key_is_set = false;
  self->derived_kx_secret_key_is_set = false;
}

void _np_crypto_t_del(NP_UNUSED np_state_t *context,
                      NP_UNUSED uint8_t     type,
                      NP_UNUSED size_t      size,
                      NP_UNUSED void       *data) {
  // np_crypto_t* obj = (np_crypto_t*)data;
}

void _np_crypto_session_t_new(NP_UNUSED np_state_t *context,
                              NP_UNUSED uint8_t     type,
                              NP_UNUSED size_t      size,
                              void                 *data) {
  np_crypto_session_t *session         = (np_crypto_session_t *)data;
  session->session_type                = crypto_session_none;
  session->session_key_to_read_is_set  = false;
  session->session_key_to_write_is_set = false;
  memset(session->session_key_to_read, 0, crypto_kx_SESSIONKEYBYTES);
  memset(session->session_key_to_write, 0, crypto_kx_SESSIONKEYBYTES);
}

void _np_crypto_session_t_del(NP_UNUSED np_state_t *context,
                              NP_UNUSED uint8_t     type,
                              NP_UNUSED size_t      size,
                              NP_UNUSED void       *data) {
  np_crypto_session_t *session         = (np_crypto_session_t *)data;
  session->session_key_to_read_is_set  = false;
  session->session_key_to_write_is_set = false;
  memset(session->session_key_to_read, 0, crypto_kx_SESSIONKEYBYTES);
  memset(session->session_key_to_write, 0, crypto_kx_SESSIONKEYBYTES);
}

// generates new keypairs, buffer may be NULL
np_crypto_t *np_cryptofactory_new(np_context *context, np_crypto_t *buffer) {
  np_crypto_t *ret = buffer;
  if (ret == NULL) {
    np_new_obj(np_crypto_t, ret, FUNC);
  }

  if (ret != NULL) {
    if (0 != crypto_sign_ed25519_keypair(ret->ed25519_public_key,
                                         ret->ed25519_secret_key)) {
      log_msg(LOG_ERROR, NULL, "Could not create ed25519 keypair!");
      if (buffer == NULL) np_unref_obj(np_crypto_t, ret, FUNC);
      ret = NULL;
    } else {
      ret->ed25519_public_key_is_set = true;
      ret->ed25519_secret_key_is_set = true;
    }
  }

  if (ret != NULL) {
    if (0 != crypto_sign_ed25519_sk_to_curve25519(ret->derived_kx_secret_key,
                                                  ret->ed25519_secret_key)) {
      log_msg(LOG_ERROR,
              NULL,
              "Could not convert ed25519 secret key to session secret key!");
      if (buffer == NULL) np_unref_obj(np_crypto_t, ret, FUNC);
      ret = NULL;
    } else {
      ret->derived_kx_secret_key_is_set = true;
    }
  }
  if (ret != NULL) {
    if (0 != crypto_sign_ed25519_pk_to_curve25519(ret->derived_kx_public_key,
                                                  ret->ed25519_public_key)) {
      log_msg(LOG_ERROR,
              NULL,
              "Could not convert ed25519 public key to session public key!");
      if (buffer == NULL) np_unref_obj(np_crypto_t, ret, FUNC);
      ret = NULL;
    } else {
      ret->derived_kx_public_key_is_set = true;
    }
  }
  return ret;
}

np_crypto_t *np_cryptofactory_by_secret(
    np_context   *context,
    np_crypto_t  *buffer,
    unsigned char ed25519_secret_key[crypto_sign_ed25519_SECRETKEYBYTES]) {
  np_crypto_t *ret = buffer;
  if (ret == NULL) {
    np_new_obj(np_crypto_t, ret, FUNC);
  }

  if (ret != NULL) {
    memcpy(ret->ed25519_secret_key,
           ed25519_secret_key,
           crypto_sign_ed25519_SECRETKEYBYTES);
    ret->ed25519_secret_key_is_set = true;

    if (0 != crypto_sign_ed25519_sk_to_pk(ret->ed25519_public_key,
                                          ret->ed25519_secret_key)) {
      log_msg(LOG_ERROR,
              NULL,
              "Cannot convert ed25519 public key from given secret key");
      if (buffer == NULL) np_unref_obj(np_crypto_t, ret, FUNC);
      ret = NULL;
    } else {
      ret->ed25519_public_key_is_set = true;
    }
  }
  if (ret != NULL) {
    if (0 != crypto_sign_ed25519_sk_to_curve25519(ret->derived_kx_secret_key,
                                                  ret->ed25519_secret_key)) {
      log_msg(LOG_ERROR,
              NULL,
              "Could not convert ed25519 secret key to curve25519 secret key!");
      if (buffer == NULL) np_unref_obj(np_crypto_t, ret, FUNC);
      ret = NULL;
    } else {
      ret->derived_kx_secret_key_is_set = true;
    }
  }
  if (ret != NULL) {
    if (0 != crypto_sign_ed25519_pk_to_curve25519(ret->derived_kx_public_key,
                                                  ret->ed25519_public_key)) {
      log_msg(LOG_ERROR,
              NULL,
              "Could not convert ed25519 public key to curve25519 public key!");
      if (buffer == NULL) np_unref_obj(np_crypto_t, ret, FUNC);
      ret = NULL;
    } else {
      ret->derived_kx_public_key_is_set = true;
    }
  }
  return ret;
}

np_crypto_t *np_cryptofactory_by_public(
    np_context   *context,
    np_crypto_t  *buffer,
    unsigned char ed25519_public_key[crypto_sign_ed25519_PUBLICKEYBYTES]) {
  np_crypto_t *ret = buffer;
  if (ret == NULL) {
    np_new_obj(np_crypto_t, ret, FUNC);
  }

  if (ret != NULL) {
    memcpy(ret->ed25519_public_key,
           ed25519_public_key,
           crypto_sign_ed25519_PUBLICKEYBYTES);
    ret->ed25519_public_key_is_set = true;
  }
  if (ret != NULL && ret->ed25519_public_key_is_set) {
    if (0 != crypto_sign_ed25519_pk_to_curve25519(ret->derived_kx_public_key,
                                                  ret->ed25519_public_key)) {
      log_msg(LOG_ERROR,
              NULL,
              "Could not convert ed25519 public key to session public key!");
      if (buffer == NULL) np_unref_obj(np_crypto_t, ret, FUNC);
      return NULL;
    } else {
      ret->derived_kx_public_key_is_set = true;
    }
  }
  ret->ed25519_secret_key_is_set    = false;
  ret->derived_kx_secret_key_is_set = false;
  return ret;
}

int np_crypto_session_encrypt(np_state_t          *context,
                              np_crypto_session_t *session,
                              unsigned char       *ciphertext,
                              unsigned int         ciphertext_length,
                              unsigned char       *mac,
                              unsigned int         mac_length,
                              unsigned char       *data,
                              unsigned int         data_length,
                              unsigned char       *ad_data,
                              unsigned int         ad_data_length,
                              unsigned char       *nonce) {

  ASSERT(ciphertext_length == data_length,
         "array size does not match expected length");
  ASSERT(crypto_aead_chacha20poly1305_IETF_ABYTES == mac_length,
         "MAC length doesn't match");
  // ASSERT(crypto_aead_xchacha20poly1305_IETF_NPUBBYTES ==
  // crypto_box_NONCEBYTES, "nonce bytes length doesn't match");
  // crypto_aead_xchacha20poly1305_NPUBBYTES
  log_debug(LOG_MESSAGE,
            NULL,
            "s %p, c %p (size %d), m %p (size %d), d %p (size %d), a %p "
            "(size %d), n %p",
            session,
            ciphertext,
            ciphertext_length,
            mac,
            mac_length,
            data,
            data_length,
            ad_data,
            ad_data_length,
            nonce);
  unsigned long long mac_l = 0;
  return crypto_aead_chacha20poly1305_ietf_encrypt_detached(
      ciphertext,
      mac,
      &mac_l,
      data,
      data_length,
      ad_data,
      ad_data_length,
      NULL,
      nonce,
      session->session_key_to_write);
}

int np_crypto_session_decrypt(np_state_t          *context,
                              np_crypto_session_t *session,
                              unsigned char       *ciphertext,
                              unsigned int         ciphertext_length,
                              unsigned char       *mac,
                              unsigned int         mac_length,
                              unsigned char       *data,
                              unsigned int         data_length,
                              unsigned char       *ad_data,
                              unsigned int         ad_data_length,
                              unsigned char       *nonce) {
  ASSERT(ciphertext_length == data_length,
         "array size does not match expected length");
  return crypto_aead_chacha20poly1305_ietf_decrypt_detached(
      data,
      NULL,
      ciphertext,
      ciphertext_length,
      mac,
      ad_data,
      ad_data_length,
      nonce,
      session->session_key_to_read);
}

// generates new keypairs, buffer may be NULL
int np_crypto_session(np_state_t          *context,
                      np_crypto_t         *my_container,
                      np_crypto_session_t *session,
                      np_crypto_t         *remote_container,
                      bool                 remote_is_client) {
  assert(context != NULL);
  assert(my_container != NULL);
  assert(session != NULL);
  assert(remote_container != NULL);
  assert(remote_container->derived_kx_public_key_is_set);

  int ret = -2;
  if (my_container->derived_kx_public_key_is_set &&
      my_container->derived_kx_secret_key_is_set) {

    if (remote_is_client) {
      ret = crypto_kx_server_session_keys(
          session->session_key_to_read,
          session->session_key_to_write,
          my_container->derived_kx_public_key,
          my_container->derived_kx_secret_key,
          remote_container->derived_kx_public_key);
    } else {
      ret = crypto_kx_client_session_keys(
          session->session_key_to_read,
          session->session_key_to_write,
          my_container->derived_kx_public_key,
          my_container->derived_kx_secret_key,
          remote_container->derived_kx_public_key);
    }
  }
  if (ret == 0) {
    session->session_key_to_read_is_set  = true;
    session->session_key_to_write_is_set = true;
  }
  return ret;
}

int __np_crypt_encrypt(np_crypto_transport_message_t *tmessage,
                       unsigned char                 *secret_key,
                       void                          *data_to_encrypt,
                       size_t                         data_size) {
  assert(tmessage != NULL);
  assert(secret_key != NULL);
  assert(data_to_encrypt != NULL);
  int ret = -1;
  randombytes_buf(tmessage->nonce, sizeof tmessage->nonce);
  tmessage->data_length    = data_size + crypto_secretbox_MACBYTES;
  tmessage->encrypted_data = calloc(1, tmessage->data_length);
  ret                      = crypto_secretbox_easy(tmessage->encrypted_data,
                              data_to_encrypt,
                              data_size,
                              tmessage->nonce,
                              secret_key);

  return ret;
}
int __np_crypt_decrypt(np_crypto_transport_message_t *tmessage,
                       unsigned char                 *secret_key,
                       void                          *buffer) {
  assert(tmessage != NULL);
  assert(secret_key != NULL);
  assert(buffer != NULL);

  int ret = crypto_secretbox_open_easy(buffer,
                                       tmessage->encrypted_data,
                                       tmessage->data_length,
                                       tmessage->nonce,
                                       secret_key);

  return ret;
}

int np_crypto_generate_signature(np_crypto_t   *self,
                                 unsigned char *signature_buffer,
                                 void          *data_to_sign,
                                 size_t         data_size) {
  assert(self != NULL);
  assert(signature_buffer != NULL);
  assert(data_to_sign != NULL);
  int ret = -2;
  if (self->ed25519_secret_key_is_set) {
    ret = crypto_sign_detached(signature_buffer,
                               NULL,
                               data_to_sign,
                               data_size,
                               self->ed25519_secret_key);
  }
  return ret;
}
int np_crypto_verify_signature(
    np_crypto_t  *self,
    unsigned char signature_buffer[crypto_sign_BYTES],
    void         *data_to_verify,
    size_t        data_size) {
  assert(self != NULL);
  assert(data_to_verify != NULL);
  int ret = -2;
  if (self->ed25519_public_key_is_set) {
    ret = crypto_sign_verify_detached(signature_buffer,
                                      data_to_verify,
                                      data_size,
                                      self->ed25519_public_key);
  }
  return ret;
}

void np_crypt_export(np_crypto_t *self, struct np_token *dest) {
  assert(self != NULL);
  assert(dest != NULL);
  assert(sizeof(dest->public_key) == sizeof(self->ed25519_public_key));
  memcpy(dest->public_key,
         self->ed25519_public_key,
         sizeof(self->ed25519_public_key));
  assert(sizeof(dest->secret_key) == sizeof(self->ed25519_secret_key));
  memcpy(dest->secret_key,
         self->ed25519_secret_key,
         sizeof(self->ed25519_secret_key));
}
