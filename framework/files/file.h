//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// neuropil is copyright 2016-2022 by pi-lar GmbH
//
#ifndef NP_FWK_FILE_H_
#define NP_FWK_FILE_H_

#include "neuropil.h"
#include "neuropil_attributes.h"
#include "neuropil_data.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * a module to share files via the neuropil cybersecurity mesh
 *
 * The module will offer at the top level a "files/" subject that lists all
 * opened directories or files. It contains only the hash values of each shared
 * file or directory, but no additional information. A user who would liek to
 * receive a file has to "apply" for sharing and explicitly subscribe to each
 * hash (aka file).
 *
 * TODO: chunk files before sending and enable partial re-delivery of chunks
 * TODO: file receiver storing the file in disk
 */
enum np_file_enum { DATABLOCK_SIZE = 10240 };

struct np_filestorage {
  struct np_token *identity;

  np_id filename;
  char  mimetype[255];

  np_attributes_t attributes;
  np_signature_t  signature;

  np_datablock_t *blocks[];
};

// conveniance function that can be used to initiate the sending of files to a
// peer, e.g. after a authorization was successful. The subject of the token
// identifies the files that should be send to the peer.
void np_files_send_authorized(np_context *ac, struct np_token *token);

// open a directory or file and share it via neuropil. The hash of the file will
// be calculated based on teh filename (currently). "hidden" files will nto be
// shared (files starting with '.'). the seed parameter shoudl be used to
// obfuscate the resulting hash (make it private, prevent collision of files
// with the same name but from a different owner)
// TODO: hash value calculation based on filename and attributes
// TODO: hash value calculation of directories based on directory name and hash
// list of contained files
// TODO: store additional attributes as fiel attributes (see xattr)
void np_files_open(np_context *context,
                   np_id       identifier_seed,
                   const char *dir_or_filename,
                   bool        searchable);

// a callback function that can be passed to the neuropil library
bool np_files_store_cb(np_context *context, struct np_message *msg);

// close files and stop sharing files previsoulsy shared using np_files_open
void np_files_close(np_context *ac, const char *alias);

//
void np_files_list(np_context *ac, const char *alias);

#ifdef __cplusplus
}
#endif

#endif // NP_FWK_FILE_H_
