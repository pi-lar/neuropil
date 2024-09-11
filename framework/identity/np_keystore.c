//
// SPDX-FileCopyrightText: 2016-2023 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "identity/np_keystore.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tree/tree.h"

#include "identity/np_identity.h"
#include "util/np_bloom.h"
#include "util/np_serialization.h"
#include "util/np_skiplist.h"
#include "util/np_tree.h"

#include "np_dhkey.h"
#include "np_util.h"

#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

// TODO: use file attributes to store mac // nonce // fingerprints

struct np_keystore {
  np_skiplist_t _denied_identities;
  np_skiplist_t _allowed_identities;
  np_bloom_t   *_denied_identities_filter;
  np_bloom_t   *_allowed_identities_filter;

  bool          is_initialized;
  np_spinlock_t lock;

  char        _dirname[PATH_MAX];
  np_id       keystore_id;
  np_context *context;

  int    _file_descriptor;
  void  *_mmap_region;
  size_t _mmap_size;

  unsigned char _passphrase[NP_KEY_BYTES];

  size_t            identities_size;
  struct np_token **identities;
};
typedef struct np_keystore np_keystore_t;

static double            NP_KEYSTORE_SAVE_INTERVAL = 60.0;
static const char *const _np_hidden_filename       = ".npks";
static const uint8_t     keystore_filename_length =
    8 /* strnlen("np:npks:", 10) */ + 2 * NP_FINGERPRINT_BYTES + 1;
static np_keystore_t __keystore = {0};

static enum np_return __munmap_keystore_file(size_t size) {

  if (__keystore._mmap_region) {
    munlock(__keystore._mmap_region, __keystore._mmap_size);
    munmap(__keystore._mmap_region, __keystore._mmap_size);
    __keystore._mmap_region = NULL;
  }
  if (size > 0) {
    ftruncate(__keystore._file_descriptor, size);
  }
  if (__keystore._file_descriptor) {
    close(__keystore._file_descriptor);
    __keystore._file_descriptor = 0;
  }
  __keystore._mmap_size = 0;

  return np_ok;
}

static enum np_return __mmap_keystore_file(size_t size) {

  char keystore_id_str[2 * NP_FINGERPRINT_BYTES + 1];
  np_id_str(keystore_id_str, __keystore.keystore_id);
  char keystore_filename[keystore_filename_length];
  snprintf(keystore_filename,
           keystore_filename_length,
           "np:npks:%s",
           keystore_id_str);
  bool new_file = false;

  char cwd[PATH_MAX];
  getcwd(cwd, sizeof(cwd));
  chdir(__keystore._dirname);

  size_t page_size = sysconf(_SC_PAGE_SIZE);

  struct stat fileinfo;
  if (0 == stat(_np_hidden_filename, &fileinfo)) {
    __keystore._mmap_size = fileinfo.st_size;
  } else if (errno == ENOENT) { // file does not exists, create it!
                                //    __keystore._mmap_size = page_size;
    new_file = true;
  }

  if (0 == __keystore._file_descriptor) {
    __keystore._file_descriptor =
        open(_np_hidden_filename, O_CREAT | O_RDWR, S_IWUSR | S_IRUSR);
    if (-1 == __keystore._file_descriptor) {
      fprintf(stdout, "unable to open file (%s)\n", strerror(errno));
      close(__keystore._file_descriptor);
      return np_unknown_error;
    }

    if (__keystore._mmap_size == 0) {
      ftruncate(__keystore._file_descriptor, page_size);
      __keystore._mmap_size = page_size;
    }
  }

  if (size > __keystore._mmap_size) {
    // __munmap_keystore_file(0);

    uint8_t sizing_factor = floor((float)size / page_size) + 1;
    __keystore._mmap_size = page_size * sizing_factor;

    ftruncate(__keystore._file_descriptor, __keystore._mmap_size);
  }

  if (__keystore._mmap_region == NULL) {
    __keystore._mmap_region = mmap(NULL,
                                   __keystore._mmap_size,
                                   PROT_READ | PROT_WRITE,
                                   MAP_SHARED | MAP_NORESERVE,
                                   __keystore._file_descriptor,
                                   0); // MAP_32BIT |
    if (__keystore._mmap_region == MAP_FAILED) {
      fprintf(stdout, "unable to mmap file (%s)\n", strerror(errno));
      close(__keystore._file_descriptor);
      return np_unknown_error;
    }
    mlock(__keystore._mmap_region, __keystore._mmap_size);

    if (new_file) {
      memset(__keystore._mmap_region, 0, __keystore._mmap_size);
    }
  }
  chdir(cwd);

  return np_ok;
}

static int8_t __compare_nptoken_by_fingerprint(const void *t1, const void *t2) {
  np_id fp_1, fp_2;
  np_token_fingerprint(__keystore.context,
                       *(struct np_token *)t1,
                       false,
                       &fp_1);
  np_token_fingerprint(__keystore.context,
                       *(struct np_token *)t2,
                       false,
                       &fp_2);
  return memcmp(fp_1, fp_2, NP_FINGERPRINT_BYTES);
}

static int8_t __cmp_nptoken_by_fingerprint(np_map_reduce_t *mr_args,
                                           const void      *t2) {
  np_id fp_2 = {0};
  np_token_fingerprint(__keystore.context,
                       *(struct np_token *)t2,
                       false,
                       &fp_2);
  return memcmp(mr_args->map_args.io, fp_2, NP_FINGERPRINT_BYTES);
}

static int8_t __all_nptoken_by_fingerprint(NP_UNUSED np_map_reduce_t *mr_args,
                                           NP_UNUSED const void      *t2) {
  return -1;
}

static bool __map_nptoken_by_fingerprint(np_map_reduce_t *mr_args,
                                         const void      *t2) {
  if (t2 == NULL) return true;

  np_dhkey_t fp_2 = {0};
  np_token_fingerprint(__keystore.context,
                       *(struct np_token *)t2,
                       false,
                       (np_id *)&fp_2);
  if (0 == memcmp(mr_args->map_args.io, &fp_2, NP_FINGERPRINT_BYTES)) {
    if (np_tree_find_dhkey(mr_args->reduce_result, fp_2) == NULL) {
      np_tree_insert_dhkey(mr_args->reduce_result,
                           (np_dhkey_t)fp_2,
                           np_treeval_new_v((void *)t2));
      return false;
    }
    return true;
  }
  return false;
}

static bool __store_nptoken_fingerprint(np_map_reduce_t *mr_args,
                                        const void      *t2) {
  if (t2 == NULL) return false;
  np_dhkey_t fp_2 = {0};
  np_token_fingerprint(__keystore.context,
                       *(struct np_token *)t2,
                       false,
                       (np_id *)&fp_2);
  size_t *write_pos = (size_t *)mr_args->map_args.io;
  memcpy(__keystore._mmap_region + *write_pos, &fp_2, NP_FINGERPRINT_BYTES);
  *write_pos = *write_pos + NP_FINGERPRINT_BYTES;

  // sll_append(void_ptr, mr_args->map_result, (void *)t2);
  return true;
}

bool __np_keystore_save(NP_UNUSED np_state_t     *context,
                        NP_UNUSED np_util_event_t args) {
  bool ret = false;

  np_spinlock_lock(&__keystore.lock);
  if (np_skiplist_size(&__keystore._allowed_identities) == 0) {
    ret = true;
    goto __np_finally;
  }

  // calculate size of np_id array and mmap file with new size
  size_t data_size =
      np_skiplist_size(&__keystore._allowed_identities) * NP_FINGERPRINT_BYTES;
  size_t cbor_size = 8 + crypto_box_NONCEBYTES;
  size_t full_size = data_size + cbor_size + crypto_secretbox_MACBYTES;

  if (np_ok != __mmap_keystore_file(full_size)) {
    goto __np_catch;
  }

  size_t          write_pos = cbor_size;
  np_map_reduce_t mr        = {0};
  mr.cmp                    = __all_nptoken_by_fingerprint;
  mr.map                    = __store_nptoken_fingerprint;
  mr.map_args.io            = &write_pos;
  // mr.map_result               = sll_init_part(void_ptr);
  // mr.reduce                   = __encrypt_keystore_fingerprints;
  // mr.reduce_args.io           = __keystore.keystore_id;
  // mr.reduce_result            = np_tree_create();

  np_skiplist_map(&__keystore._allowed_identities, &mr);
  // np_skiplist_reduce(&mr);

  uint64_t subkey_id = 0;
  memcpy(&subkey_id, __keystore.keystore_id, sizeof(uint64_t));

  unsigned char _nonce[crypto_box_NONCEBYTES];
  randombytes_buf(_nonce, crypto_box_NONCEBYTES);

  unsigned char subkey[NP_FINGERPRINT_BYTES];
  crypto_kdf_derive_from_key(subkey,
                             (size_t)NP_FINGERPRINT_BYTES,
                             subkey_id,
                             (char *)__keystore.keystore_id,
                             __keystore._passphrase);
  // in place encryption of skiplist fingerprint items
  if (0 != crypto_secretbox_easy(__keystore._mmap_region + cbor_size,
                                 __keystore._mmap_region + cbor_size,
                                 data_size,
                                 _nonce,
                                 subkey)) {
    log_msg(LOG_ERROR, NULL, "encryption of np_keystore failed, exiting");
    goto __np_catch;
  }

  if (!np_serializer_write_encrypted(__keystore._mmap_region,
                                     &full_size,
                                     _nonce,
                                     __keystore._mmap_region + cbor_size,
                                     data_size + crypto_secretbox_MACBYTES)) {
    log_msg(LOG_ERROR,
            NULL,
            "writing of encrypted np_keystore failed, exiting");
    goto __np_catch;
  }

  __munmap_keystore_file(full_size);
  ret = true;
  goto __np_finally;
  // np_spinlock_unlock(&__keystore.lock);
  // sll_free(void_ptr, mr.map_result);
  // np_tree_free(mr.reduce_result);

__np_catch:
  __munmap_keystore_file(0);
__np_finally:
  np_spinlock_unlock(&__keystore.lock);

  return ret;
}

void __shutdown_keystore(np_context *context) {
  np_keystore_destroy(context, __keystore.keystore_id);
}

enum np_return np_keystore_init(np_context   *context,
                                np_id         keystore_id,
                                const char   *dirname,
                                unsigned char passphrase[NP_KEY_BYTES]) {
  if (!__keystore.is_initialized) {
    np_spinlock_init(&__keystore.lock, PTHREAD_PROCESS_PRIVATE);

    np_spinlock_lock(&__keystore.lock);
    __keystore.context          = context;
    __keystore._file_descriptor = 0;
    __keystore._mmap_region     = NULL;
    __keystore._mmap_size       = 0;
    realpath(dirname, __keystore._dirname);

    memcpy(__keystore.keystore_id, keystore_id, NP_FINGERPRINT_BYTES);
    memcpy(__keystore._passphrase, passphrase, NP_KEY_BYTES);

    // TODO: create for each keystore_id
    np_skiplist_init(&__keystore._allowed_identities,
                     __compare_nptoken_by_fingerprint,
                     NULL);
    __keystore._allowed_identities_filter =
        _np_neuropil_bloom_create(); // 512 identities
    __keystore._denied_identities_filter =
        _np_neuropil_bloom_create(); // 512 identities

    __keystore.is_initialized = true;

    np_spinlock_unlock(&__keystore.lock);

    np_jobqueue_submit_event_periodic(context,
                                      PRIORITY_MOD_USER_DEFAULT,
                                      NP_KEYSTORE_SAVE_INTERVAL,
                                      NP_KEYSTORE_SAVE_INTERVAL,
                                      __np_keystore_save,
                                      "__np_keystore_save");
    np_add_shutdown_cb(context, __shutdown_keystore);
  }
  return np_ok;
}

enum np_return np_keystore_destroy(NP_UNUSED np_context *context,
                                   NP_UNUSED np_id       keystore_id) {

  __munmap_keystore_file(0);

  np_spinlock_destroy(&__keystore.lock);

  np_skiplist_destroy(&__keystore._allowed_identities);
  _np_bloom_free(__keystore._denied_identities_filter);
  _np_bloom_free(__keystore._allowed_identities_filter);

  for (uint16_t x = 0; x < __keystore.identities_size; x++)
    free(__keystore.identities[x]);

  if (__keystore.identities != NULL) free(__keystore.identities);

  __keystore.is_initialized = false;
  return np_ok;
}

enum np_return np_keystore_check_identity(np_context      *context,
                                          np_id            keystore_id,
                                          struct np_token *identity) {
  enum np_return ret = np_unknown_error;

  np_id      identity_fp    = {0};
  np_dhkey_t identity_dhkey = {0};

  if (np_ok != np_token_fingerprint(context, *identity, false, &identity_fp))
    return np_invalid_argument;

  memcpy(&identity_dhkey, identity_fp, NP_FINGERPRINT_BYTES);

  np_spinlock_lock(&__keystore.lock);
  bool in_allow_list =
      _np_neuropil_bloom_check(__keystore._allowed_identities_filter,
                               identity_dhkey);
  bool in_denied_list =
      _np_neuropil_bloom_check(__keystore._denied_identities_filter,
                               identity_dhkey);
  if (in_allow_list && !in_denied_list) {
    np_map_reduce_t mr = {0};
    mr.cmp             = __cmp_nptoken_by_fingerprint;
    mr.map             = __map_nptoken_by_fingerprint;
    mr.map_args.io     = identity_fp;
    mr.reduce          = NULL;
    mr.reduce_result   = np_tree_create();

    np_skiplist_map(&__keystore._allowed_identities, &mr);
    if (mr.reduce_result->size == 1) {
      struct np_token *stored_token =
          np_tree_find_dhkey(mr.reduce_result, identity_dhkey)->val.value.v;
      if (0 == memcmp(stored_token->public_key,
                      identity->public_key,
                      NP_PUBLIC_KEY_BYTES))
        ret = np_ok;
    }
    np_tree_free(mr.reduce_result);
  }
  np_spinlock_unlock(&__keystore.lock);

  return ret;
}

enum np_return np_keystore_load_identity(np_context      *context,
                                         np_id            keystore_id,
                                         np_id            fingerprint,
                                         struct np_token *identity) {
  enum np_return ret = np_invalid_operation;

  // __np_try: // noop line, syntactic sugar

  np_spinlock_lock(&__keystore.lock);
  if (np_ok != __mmap_keystore_file(0)) {
    goto __np_catch;
  }

  // calculate size of np_id array and mmap file with new size
  size_t full_size = __keystore._mmap_size;
  size_t cbor_size = 8 + crypto_box_NONCEBYTES;
  size_t data_size = full_size - cbor_size;

  if (full_size == 0) {
    goto __np_catch;
  }

  unsigned char _nonce[crypto_box_NONCEBYTES];
  if (false == np_serializer_read_encrypted(__keystore._mmap_region,
                                            &full_size,
                                            _nonce,
                                            __keystore._mmap_region + cbor_size,
                                            &data_size)) {
    log_msg(LOG_WARNING, NULL, "could not read/decrypt keystore file");
    goto __np_catch;
  }

  uint64_t subkey_id = 0;
  memcpy(&subkey_id, __keystore.keystore_id, sizeof(uint64_t));

  unsigned char subkey[NP_FINGERPRINT_BYTES];
  crypto_kdf_derive_from_key(subkey,
                             (size_t)NP_FINGERPRINT_BYTES,
                             subkey_id,
                             (char *)__keystore.keystore_id,
                             __keystore._passphrase);

  if (0 != crypto_secretbox_open_easy(__keystore._mmap_region + cbor_size +
                                          crypto_box_MACBYTES,
                                      __keystore._mmap_region + cbor_size,
                                      data_size,
                                      _nonce,
                                      subkey)) {
    log_msg(LOG_ERROR, NULL, "decryption of np_keystore failed, exiting");
    goto __np_catch;
  }

  void *current_pos = __keystore._mmap_region + cbor_size + crypto_box_MACBYTES;
  void *end_pos     = __keystore._mmap_region + full_size;

  // lookup fingerprint in the identity array
  while (current_pos < end_pos) {
    np_dhkey_t keystore_member = {0};
    memcpy(&keystore_member, current_pos, NP_FINGERPRINT_BYTES);

    if (0 == memcmp(&keystore_member, &fingerprint, NP_FINGERPRINT_BYTES)) {
      // found the fingeprint, open its file and load the token into the core
      // library
      memcpy(&subkey_id, &keystore_member, sizeof(uint64_t));
      crypto_kdf_derive_from_key(subkey,
                                 (size_t)NP_FINGERPRINT_BYTES,
                                 subkey_id,
                                 (char *)__keystore.keystore_id,
                                 __keystore._passphrase);

      ret = np_identity_load_token(context,
                                   __keystore._dirname,
                                   *(np_id *)&keystore_member,
                                   subkey,
                                   identity);
      break;
    }

    current_pos += NP_FINGERPRINT_BYTES;
  }

__np_catch:
  __munmap_keystore_file(0);

__np_finally: // noop line, syntactic sugar
  np_spinlock_unlock(&__keystore.lock);

  return ret;
}

enum np_return np_keystore_load_identities(np_context *context,
                                           np_id       keystore_id) {
  assert(context != NULL);

  enum np_return ret = np_invalid_operation;

  // __np_try: // noop line, syntactic sugar

  np_spinlock_lock(&__keystore.lock);
  if (np_ok != __mmap_keystore_file(0)) {
    goto __np_catch;
  }

  // calculate size of np_id array and mmap file with new size
  size_t full_size = __keystore._mmap_size;
  size_t cbor_size = 8 + crypto_box_NONCEBYTES;
  size_t data_size = full_size - cbor_size;

  if (full_size == 0) {
    goto __np_catch;
  }

  unsigned char _nonce[crypto_box_NONCEBYTES];
  if (false == np_serializer_read_encrypted(__keystore._mmap_region,
                                            &full_size,
                                            _nonce,
                                            __keystore._mmap_region + cbor_size,
                                            &data_size)) {
    log_msg(LOG_WARNING, NULL, "could not read/decrypt keystore file");
    goto __np_catch;
  }

  uint64_t subkey_id = 0;
  memcpy(&subkey_id, __keystore.keystore_id, sizeof(uint64_t));

  unsigned char subkey[NP_FINGERPRINT_BYTES];
  crypto_kdf_derive_from_key(subkey,
                             (size_t)NP_FINGERPRINT_BYTES,
                             subkey_id,
                             (char *)__keystore.keystore_id,
                             __keystore._passphrase);

  if (0 != crypto_secretbox_open_easy(__keystore._mmap_region + cbor_size +
                                          crypto_box_MACBYTES,
                                      __keystore._mmap_region + cbor_size,
                                      data_size,
                                      _nonce,
                                      subkey)) {
    log_msg(LOG_ERROR, NULL, "decryption of np_keystore failed, exiting");
    goto __np_catch;
  }

  // delete old content if present
  if (np_skiplist_size(&__keystore._allowed_identities) > 0) {
    _np_neuropil_bloom_clear(__keystore._allowed_identities_filter);
    np_skiplist_destroy(&__keystore._allowed_identities);
    for (uint16_t x = 0; x < __keystore.identities_size; x++)
      free(__keystore.identities[x]);
    free(__keystore.identities);
    __keystore.identities_size = 0;
  }

  np_skiplist_init(&__keystore._allowed_identities,
                   __compare_nptoken_by_fingerprint,
                   NULL);

  void *current_pos = __keystore._mmap_region + cbor_size + crypto_box_MACBYTES;
  void *end_pos     = __keystore._mmap_region + full_size;

  // rebuild the identity array
  while (current_pos < end_pos) {
    np_dhkey_t keystore_member = {0};
    memcpy(&keystore_member, current_pos, NP_FINGERPRINT_BYTES);

    uint16_t pos = __keystore.identities_size;
    __keystore.identities_size++;
    __keystore.identities =
        realloc(__keystore.identities,
                __keystore.identities_size * sizeof(struct np_token *));
    CHECK_MALLOC(__keystore.identities);

    __keystore.identities[pos] = calloc(1, sizeof(struct np_token));
    CHECK_MALLOC(__keystore.identities[pos]);

    memcpy(&subkey_id, &keystore_member, sizeof(uint64_t));
    crypto_kdf_derive_from_key(subkey,
                               (size_t)NP_FINGERPRINT_BYTES,
                               subkey_id,
                               (char *)__keystore.keystore_id,
                               __keystore._passphrase);
    if (np_ok == np_identity_load_token(context,
                                        __keystore._dirname,
                                        *(np_id *)&keystore_member,
                                        subkey,
                                        __keystore.identities[pos])) {
      np_skiplist_add(&__keystore._allowed_identities,
                      __keystore.identities[pos]);
      _np_neuropil_bloom_add(__keystore._allowed_identities_filter,
                             keystore_member);
    }
    current_pos += NP_FINGERPRINT_BYTES;
  }

__np_catch:
  __munmap_keystore_file(0);

__np_finally: // noop line, syntactic sugar
  np_spinlock_unlock(&__keystore.lock);

  return ret;
}

enum np_return np_keystore_store_identity(np_context      *context,
                                          np_id            keystore_id,
                                          struct np_token *identity) {
  assert(context != NULL);

  enum np_return ret         = np_invalid_operation;
  np_id          identity_fp = {0};

  if (np_ok != np_token_fingerprint(context, *identity, false, &identity_fp))
    // cannot create fingerprint
    return np_invalid_argument;

  if (np_ok == np_keystore_check_identity(context, keystore_id, identity))
    // already in the list
    return np_ok;

  // store identity in file
  uint64_t subkey_id = 0;
  memcpy(&subkey_id, &identity_fp, sizeof(uint64_t));
  unsigned char subkey[NP_FINGERPRINT_BYTES];
  crypto_kdf_derive_from_key(subkey,
                             (size_t)NP_FINGERPRINT_BYTES,
                             subkey_id,
                             (char *)__keystore.keystore_id,
                             __keystore._passphrase);

  // __np_try: // noop line, syntactic sugar

  np_spinlock_lock(&__keystore.lock);
  if (np_ok != np_identity_save_token(__keystore.context,
                                      __keystore._dirname,
                                      subkey,
                                      identity)) {
    // token already stored?
    struct np_token tmp_token = {0};
    if (np_ok != np_identity_load_token(__keystore.context,
                                        __keystore._dirname,
                                        identity_fp,
                                        subkey,
                                        &tmp_token)) {
      // could not store token in file
      log_msg(LOG_WARNING,
              NULL,
              "identity token already present while storing token in "
              "keystore, abort");
      ret = np_invalid_operation;
      goto __np_catch;
    }
    // check wether already existing token is the same
    np_id tmp_token_fingerprint = {0};
    np_token_fingerprint(__keystore.context,
                         tmp_token,
                         false,
                         &tmp_token_fingerprint);
    if (0 != memcmp(tmp_token_fingerprint, identity_fp, NP_FINGERPRINT_BYTES)) {
      // could not store token in file
      log_msg(LOG_WARNING,
              NULL,
              "identity token already present while storing token in "
              "keystore, abort");
      ret = np_invalid_operation;
      goto __np_catch;
    }
  }

  uint16_t pos = __keystore.identities_size;
  __keystore.identities_size++;
  __keystore.identities =
      realloc(__keystore.identities,
              __keystore.identities_size * sizeof(struct np_token *));
  CHECK_MALLOC(__keystore.identities);

  __keystore.identities[pos] = calloc(1, sizeof(struct np_token));
  CHECK_MALLOC(__keystore.identities[pos]);

  memcpy(__keystore.identities[pos], identity, sizeof(struct np_token));
  if (np_skiplist_add(&__keystore._allowed_identities,
                      __keystore.identities[pos])) {
    _np_neuropil_bloom_add(__keystore._allowed_identities_filter,
                           *(np_dhkey_t *)identity_fp);
    ret = np_ok;
    goto __np_finally;
  }

__np_catch:
  log_msg(LOG_WARNING, NULL, "error while storing token in keystore");

__np_finally: // noop line, syntactic sugar
  np_spinlock_unlock(&__keystore.lock);

  return ret;
}
