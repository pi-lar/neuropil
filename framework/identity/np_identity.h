//
// SPDX-FileCopyrightText: 2016-2023 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef NP_FWK_IDENTITY_H_
#define NP_FWK_IDENTITY_H_

#include "sodium.h"

#include "neuropil.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NP_KEY_BYTES crypto_secretbox_KEYBYTES

// create a new digital identity (aka private key) and store it into the
// filename. passphrase will be used together with a random nonce to encrypt the
// private key (if not NULL). The file content will be a cose encrypted buffer
// with an empty recipient list
enum np_return
np_identity_create_secretkey(np_context         *context,
                             const char         *directory,
                             const unsigned char passphrase[NP_KEY_BYTES]);

// save an private key to a file and add the identifier to the
// structure. Should be used to store private key and public token in two
// different files. The np_id is the fingerprint of the identity token.
enum np_return
np_identity_save_secretkey(np_context            *context,
                           const char            *directory,
                           const unsigned char    passphrase[NP_KEY_BYTES],
                           const struct np_token *identity);

// loads an private key from a file and adds it to the identity
// passed into the function call. The np_id will contain the fingerprint of the
// token file it is linked with.
enum np_return
np_identity_load_secretkey(np_context         *context,
                           const char         *directory,
                           np_id              *identifier,
                           const unsigned char passphrase[NP_KEY_BYTES],
                           struct np_token    *identity);

// loads a identity token from a file. The filename has to be passed in and
// consists of the prefix "np:npt:" plus the fingerprint of the identity token.
// the functions actually checks whether the filename matches to the fingerprint
// of the token. When loading a secret key, it is possible to retrieve the
// fingerprint for a file in the identifier, the identifier only needs to be
// converted to hex code
enum np_return
np_identity_load_token(np_context         *context,
                       const char         *dirname,
                       np_id               identifier,
                       const unsigned char passphrase[NP_KEY_BYTES],
                       struct np_token    *identity);

// stores an identity token in a file, file name is based on the fingerprint of
// the identity. The secret key is not part of the saved structure and needs to
// be stored separatly (see np_identity_save_secretkey as well).
enum np_return
np_identity_save_token(np_context         *context,
                       const char         *directory,
                       const unsigned char passphrase[NP_KEY_BYTES],
                       struct np_token    *identity);

#ifdef __cplusplus
}
#endif

#endif // NP_FWK_IDENTITY_H_
