//
// SPDX-FileCopyrightText: 2016-2023 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "identity/np_identity.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sodium.h"

#include "util/np_bloom.h"
#include "util/np_serialization.h"
#include "util/np_tree.h"

#include "np_util.h"

// TODO: use file attributes to store mac // nonce // fingerprints

static const char *const _np_hidden_filename = ".npid";
static const uint8_t     _filename_length =
    7 /* strnlen("np:npt:", 10) */ + 2 * NP_FINGERPRINT_BYTES + 1;
static char _null_block[NP_SECRET_KEY_BYTES] = {0};

static enum np_return
__check_passphrase(const unsigned char passphrase[NP_KEY_BYTES]) {

  if (0 == memcmp(passphrase, _null_block, NP_KEY_BYTES)) {
    return np_invalid_argument;
  }
  return np_ok;
}

static enum np_return
__create_token_filename(np_context            *context,
                        const struct np_token *identity,
                        char                  *filename[_filename_length]) {
  assert(filename != NULL);
  // check whether filename matches the token fingerprint
  np_id identity_fp         = {0};
  char  identity_fp_str[65] = {0};
  // create the filename
  np_token_fingerprint(context, *identity, false, &identity_fp);
  np_id_str(identity_fp_str, identity_fp);
  snprintf(filename, _filename_length, "np:npt:%s", identity_fp_str);
  return np_ok;
}

static enum np_return __write_encrypted(np_context          *context,
                                        const char          *filename,
                                        const unsigned char *nonce,
                                        const unsigned char *buffer,
                                        size_t               buffer_size) {

  // check for existing files, for .npid file create a backup
  struct stat info;
  stat(filename, &info);
  if (ENOENT == errno) {
    // file already exists
    if (strnlen(filename, 255) == strnlen(_np_hidden_filename, 6) &&
        0 == strncmp(filename, _np_hidden_filename, 6)) {
      char      backup_file_name[26];
      struct tm t;

#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
      localtime_r(&info.st_ctimespec.tv_sec, &t);
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
      localtime_r(&info.st_ctime.tv_sec, &t);
#else
      localtime_r(&info.st_ctim.tv_sec, &t);
#endif

      strftime(backup_file_name, 26, ".npid.%FT%T", &t);
      rename(filename, backup_file_name);
      log_msg(LOG_WARNING,
              NULL,
              "found existing .npid file, created backup %s",
              backup_file_name);
    }
  }
  size_t new_buffer_size = buffer_size + 2 * crypto_box_NONCEBYTES;
  char   file_buffer[new_buffer_size];
  int    fd = open(filename, O_CREAT | O_RDWR, S_IRUSR);
  if (fd > 0 && true == np_serializer_write_encrypted(file_buffer,
                                                      &new_buffer_size,
                                                      nonce,
                                                      buffer,
                                                      buffer_size)) {
    size_t bytes_written = write(fd, file_buffer, new_buffer_size);
    close(fd);
    if (bytes_written == new_buffer_size) return np_ok;
  } else {
    log_msg(
        LOG_ERROR,
        NULL,
        "while writing encrypted identity/token: could not open filename: (%s) "
        "// (%d)",
        strerror(errno),
        errno);
  }
  return np_invalid_operation;
}

static enum np_return __read_encrypted(np_context    *context,
                                       const char    *filename,
                                       unsigned char *nonce,
                                       unsigned char *buffer,
                                       size_t        *buffer_size) {
  struct stat fileinfo;
  if (0 == stat(filename, &fileinfo)) {

    int fd = open(filename, O_RDONLY, S_IRUSR);

    size_t file_buffer_size = fileinfo.st_size;
    char   file_buffer[file_buffer_size];
    char  *file_buffer_ptr = &file_buffer[0];
    file_buffer_size       = read(fd, file_buffer_ptr, file_buffer_size);
    *buffer_size           = file_buffer_size;
    if (fd > 0 && true == np_serializer_read_encrypted(file_buffer,
                                                       &file_buffer_size,
                                                       nonce,
                                                       buffer,
                                                       buffer_size)) {
      close(fd);
      return np_ok;
    }
  }
  return np_invalid_operation;
}

enum np_return
np_identity_load_secretkey(np_context         *context,
                           const char         *directory,
                           np_id              *identifier,
                           const unsigned char passphrase[NP_KEY_BYTES],
                           struct np_token    *identity) {
  assert(identity != NULL);
  assert(directory != NULL);
  assert(passphrase != NULL);
  assert(context != NULL);

  if (np_ok != __check_passphrase(passphrase)) return np_invalid_argument;

  size_t         buffer_size = 512;
  unsigned char  crypted_buffer[buffer_size];
  unsigned char *_crypted_buffer_ptr = &crypted_buffer[0];
  unsigned char  _nonce[crypto_box_NONCEBYTES];

  char cwd[PATH_MAX];
  getcwd(cwd, sizeof(cwd));
  chdir(directory);

  if (np_ok != __read_encrypted(context,
                                _np_hidden_filename,
                                _nonce,
                                crypted_buffer,
                                &buffer_size))
    return np_unknown_error;

  chdir(cwd);

  if (0 != crypto_secretbox_open_easy(_crypted_buffer_ptr,
                                      _crypted_buffer_ptr,
                                      buffer_size,
                                      _nonce,
                                      passphrase)) {

    log_msg(LOG_ERROR, NULL, "decryption of secret key failed");
    return np_unknown_error;
  }

  if (true ==
      np_serializer_read_ed25519(crypted_buffer,
                                 &buffer_size,
                                 identifier,
                                 (unsigned char **)&identity->secret_key,
                                 (unsigned char **)&identity->public_key)) {
    log_msg(LOG_INFO, NULL, "loaded secret key into token, exiting");
  } else {
    fprintf(stdout,
            "load_identity: could not deserialize filename: %s (%d) ",
            strerror(errno),
            errno);
    return np_unknown_error;
  }

  return np_sign_identity(context, identity, true);
}

// create a new secret key and store it in filename, protected with a
// passphrase
enum np_return np_identity_create_secretkey(np_context          *context,
                                            const char          *directory,
                                            const unsigned char *passphrase) {
  if (np_ok != __check_passphrase(passphrase)) return np_invalid_argument;

  struct np_token created_identity = np_new_identity(context, 0.0, NULL);

  size_t               _crypted_buffer_length = 512;
  unsigned char        _crypted_buffer[_crypted_buffer_length];
  unsigned char       *_crypted_buffer_ptr = &_crypted_buffer[0];
  static unsigned char _nonce[crypto_box_NONCEBYTES];
  randombytes_buf(_nonce, crypto_box_NONCEBYTES);
  np_id identifier = {0};

  if (false == np_serializer_write_ed25519(
                   (const unsigned char **)&created_identity.secret_key,
                   (const unsigned char **)&created_identity.public_key,
                   true,
                   &identifier,
                   _crypted_buffer_ptr,
                   &_crypted_buffer_length)) {
    return np_unknown_error;
  }

  if (0 != crypto_secretbox_easy(_crypted_buffer_ptr,
                                 _crypted_buffer_ptr,
                                 _crypted_buffer_length,
                                 _nonce,
                                 passphrase)) {
    log_msg(LOG_ERROR, NULL, "encryption of secret key failed, exiting");
    return np_unknown_error;
  }
  _crypted_buffer_length += crypto_secretbox_MACBYTES;

  char cwd[PATH_MAX];
  getcwd(cwd, sizeof(cwd));

  chdir(directory);
  if (np_ok != __write_encrypted(context,
                                 _np_hidden_filename,
                                 _nonce,
                                 _crypted_buffer,
                                 _crypted_buffer_length)) {
    chdir(cwd);
    return np_unknown_error;
  }
  log_info(LOG_INFO, NULL, "stored new secret key (ed25519) in file, exiting");

  chdir(cwd);
  return np_ok;
}

enum np_return
np_identity_save_secretkey(np_context            *context,
                           const char            *directory,
                           const unsigned char    passphrase[NP_KEY_BYTES],
                           const struct np_token *identity) {
  if (np_ok != __check_passphrase(passphrase)) return np_invalid_argument;

  size_t               _crypted_buffer_length = 512;
  unsigned char        _crypted_buffer[_crypted_buffer_length];
  unsigned char       *_crypted_buffer_ptr = &_crypted_buffer[0];
  static unsigned char _nonce[crypto_box_NONCEBYTES];
  randombytes_buf(_nonce, crypto_box_NONCEBYTES);

  np_id identifier = {};
  np_token_fingerprint(context, *identity, false, &identifier);
  if (false ==
      np_serializer_write_ed25519((const unsigned char **)&identity->secret_key,
                                  (const unsigned char **)&identity->public_key,
                                  true,
                                  &identifier,
                                  _crypted_buffer_ptr,
                                  &_crypted_buffer_length)) {
    return np_unknown_error;
  }

  if (0 != crypto_secretbox_easy(_crypted_buffer_ptr,
                                 _crypted_buffer_ptr,
                                 _crypted_buffer_length,
                                 _nonce,
                                 passphrase)) {
    log_msg(LOG_ERROR, NULL, "encryption of secret key failed, exiting");
    return np_unknown_error;
  }
  _crypted_buffer_length += crypto_secretbox_MACBYTES;

  char cwd[PATH_MAX];
  getcwd(cwd, sizeof(cwd));

  chdir(directory);
  if (np_ok != __write_encrypted(context,
                                 _np_hidden_filename,
                                 _nonce,
                                 _crypted_buffer,
                                 _crypted_buffer_length)) {
    chdir(cwd);
    return np_unknown_error;
  }
  log_info(LOG_INFO, NULL, "stored new secret key (ed25519) in file, exiting");

  chdir(cwd);
  return np_ok;
}

// loads an identity token from a file
enum np_return
np_identity_load_token(np_context         *context,
                       const char         *directory,
                       np_id               fingerprint,
                       const unsigned char passphrase[NP_KEY_BYTES],
                       struct np_token    *identity) {
  assert(identity != NULL);
  assert(context != NULL);
  assert(directory != NULL);

  if (np_ok != __check_passphrase(passphrase)) return np_invalid_argument;

  enum np_return ret         = np_unknown_error;
  size_t         buffer_size = sizeof(struct np_token) + NP_FINGERPRINT_BYTES;
  unsigned char  crypted_buffer[buffer_size];
  unsigned char  _nonce[crypto_box_NONCEBYTES];

  char filename[79];
  char identity_fp_str[65] = {0};
  np_id_str(identity_fp_str, fingerprint);
  snprintf(filename, 75, "np:npt:%s", identity_fp_str);

  char cwd[PATH_MAX];
  getcwd(cwd, sizeof(cwd));
  chdir(directory);
  if (np_ok != __read_encrypted(context,
                                filename,
                                _nonce,
                                crypted_buffer,
                                &buffer_size)) {
    chdir(cwd);
    return np_unknown_error;
  }
  chdir(cwd);

  if (0 != crypto_secretbox_open_easy(crypted_buffer,
                                      crypted_buffer,
                                      buffer_size,
                                      _nonce,
                                      passphrase)) {
    log_msg(LOG_ERROR, NULL, "decryption of secret key failed");
    return np_unknown_error;
  }

  // memset(identity, 0, sizeof(struct np_token));
  if (true ==
      np_serializer_read_nptoken(crypted_buffer, &buffer_size, identity)) {

    // create the filename
    char check_filename[_filename_length];
    __create_token_filename(context, identity, (char **)&check_filename);

    if (0 != strncmp(check_filename, filename, strnlen(check_filename, 79))) {
      ret = np_invalid_argument;
    } else {
      if (0 == memcmp(identity->secret_key, _null_block, NP_SECRET_KEY_BYTES)) {
        np_use_token(context, *identity);
      } else {
        np_use_identity(context, *identity);
      }
      ret = np_ok;
    }
  } else {
    log_msg(LOG_ERROR, NULL, "token identity could not be loaded, exiting");
  }

  return ret;
}

// stores an identity token from a file
enum np_return
np_identity_save_token(np_context         *context,
                       const char         *directory,
                       const unsigned char passphrase[NP_KEY_BYTES],
                       struct np_token    *identity) {
  assert(identity != NULL);
  assert(context != NULL);

  if (np_ok != __check_passphrase(passphrase)) return np_invalid_argument;

  enum np_return ret = np_unknown_error;

  // create the filename
  char filename[_filename_length];
  __create_token_filename(context, identity, (char **)&filename);

  size_t crypted_buffer_size = sizeof(struct np_token) + NP_FINGERPRINT_BYTES;
  unsigned char crypted_buffer[crypted_buffer_size];
  unsigned char nonce[crypto_box_NONCEBYTES];

  // fill in random garbage
  randombytes_buf(crypted_buffer, crypted_buffer_size);
  randombytes_buf(nonce, crypto_box_NONCEBYTES);

  // serialize token on top
  if (false == np_serializer_write_nptoken(identity,
                                           crypted_buffer,
                                           &crypted_buffer_size))
    return np_unknown_error;

  if (0 != crypto_secretbox_easy(crypted_buffer,
                                 crypted_buffer,
                                 crypted_buffer_size,
                                 nonce,
                                 passphrase)) {
    log_msg(LOG_ERROR, NULL, "encryption of np_token failed, exiting");
    return np_unknown_error;
  }
  crypted_buffer_size += crypto_box_MACBYTES;
  char cwd[PATH_MAX];
  getcwd(cwd, sizeof(cwd));

  chdir(directory);
  if (np_ok != __write_encrypted(context,
                                 filename,
                                 nonce,
                                 crypted_buffer,
                                 crypted_buffer_size)) {
    chdir(cwd);
    return np_unknown_error;
  }
  log_info(LOG_INFO,
           NULL,
           "stored new secret token (ed25519) in file, exiting");

  chdir(cwd);
  return np_ok;
}
