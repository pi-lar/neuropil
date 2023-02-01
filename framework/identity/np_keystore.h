//
// SPDX-FileCopyrightText: 2016-2023 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef NP_FWK_KEYSTORE_H_
#define NP_FWK_KEYSTORE_H_

#include "neuropil.h"

#include "identity/np_identity.h"
#include "util/np_mapreduce.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A keystore holds one or more identities (np_token), that are known to the
 * issuing party. There can be more than one keystore, e.g. you could have one
 * keystore for bootstrap nodes, one for family members and one for business
 * contacts. A keystore is stored in a cbor encrypted file, the filename is
 * prefixed with "np:npks:<hash value>", where hash value is actually the
 * fingerprint of the signature over all known identities. The contents of the
 * file are loaded into memory. When identities are added to the keystore, the
 * file is written directly back to the disk.
 */

// initialize the npks module with the filename to store/load identities from
// identites will be loaded into memory, and the actual file will be closed.
enum np_return np_keystore_init(np_context   *context,
                                np_id         keystore_id,
                                const char   *dirname,
                                unsigned char passphrase[NP_KEY_BYTES]);
// load all identities of the npks file into the neuropil context
enum np_return np_keystore_load_identities(np_context *context,
                                           np_id       keystore_id);
// load one identity of the npks file into the neuropil context
enum np_return np_keystore_load_identity(np_context      *context,
                                         np_id            keystore_id,
                                         np_id            fingerprint_id,
                                         struct np_token *identity);
// add and save an identity to the store (without private key)
// the operation will change the keystore id to the new value
// if a new keystore should be created, then the keystore id should be
// initialized with zeros
enum np_return np_keystore_store_identity(np_context      *context,
                                          np_id            keystore_id,
                                          struct np_token *token);
// check whether an identity is contained in the npks store
enum np_return np_keystore_check_identity(np_context      *context,
                                          np_id            keystore_id,
                                          struct np_token *token);
// destroy the npks module, does not delete file contents
enum np_return np_keystore_destroy(np_context *context, np_id keystore_id);

// FUTURE IDEAS
// wrap the callback functions to store the intermediate result
// in this way a denied identity will not need to re-evaluated again by the
// user space function, but the keystore can handle the result directly
// enum np_return wrap_authetication_cb(np_context     *context,
//                                      np_subject      subject,
//                                      np_aaa_callback func);
// enum np_return wrap_authorization_cb(np_context     *context,
//                                      np_subject      subject,
//                                      np_aaa_callback func);
// enum np_return wrap_accounting_cb(np_context     *context,
//                                   np_subject      subject,
//                                   np_aaa_callback func);
// expose the keystore to the neuropil network, so that it can be queried from
// other nodes as well. if the keystore_id is not available locally, this will
// start a client that connects to the remote keystore enum np_return
// np_keystore_expose(np_context      *context,
//                                   np_id            keystore_id,
//                                   struct np_token *token);
// enable map reduce functionality on the keystore for other modules
// enum np_return np_keystore_mapreduce(np_context      *context,
//                                      np_id            keystore_id,
//                                      np_map_reduce_t *mr_struct);

#ifdef __cplusplus
}
#endif

#endif // NP_FWK_KEYSTORE_H_
