//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "neuropil_attributes.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "neuropil.h"
#include "neuropil_data.h"

#include "util/np_bloom.h"
#include "util/np_mapreduce.h"

#include "np_attributes.h"
#include "np_data.h"
#include "np_dhkey.h"
#include "np_legacy.h"

np_module_struct(attributes) {
  np_state_t     *context;
  np_attributes_t attribute_cache[NP_ATTR_MAX];
};

void _np_attributes_destroy(np_state_t *context) {
  // nothing to do
}

bool _np_attributes_init(np_state_t *context) {
  bool ret = true;
  np_module_malloc(attributes);

  for (int i = 0; i < NP_ATTR_MAX; i++) {
    ret = np_ok ==
          np_init_datablock((np_datablock_t *)&_module->attribute_cache[i],
                            sizeof(np_attributes_t));
    if (!ret) break;
  }
  return ret;
}

enum np_data_return np_set_ident_attr_bin(np_context           *ac,
                                          struct np_token      *ident,
                                          enum np_msg_attr_type inheritance,
                                          char                  key[255],
                                          unsigned char        *bin,
                                          size_t                bin_length) {
  np_ctx_cast(ac);
  enum np_data_return ret = np_invalid_arguments;

  struct np_data_conf conf = {0};
  conf.data_size           = bin_length;
  conf.type                = NP_DATA_TYPE_BIN;
  strncpy(conf.key, key, 254);
  if (ident != NULL) {
    ret = np_set_data(ident->attributes, conf, (np_data_value){.bin = bin});
  }

  if (inheritance != NP_ATTR_NONE)
    ret = np_set_data(np_module(attributes)->attribute_cache[inheritance],
                      conf,
                      (np_data_value){.bin = bin});

  return ret;
}

enum np_data_return np_set_mxp_attr_bin(np_context           *ac,
                                        np_subject            subject,
                                        enum np_msg_attr_type inheritance,
                                        char                  key[255],
                                        unsigned char        *bin,
                                        size_t                bin_length) {
  np_ctx_cast(ac);
  enum np_data_return ret = np_invalid_arguments;

  struct np_data_conf conf = {0};
  conf.data_size           = bin_length;
  conf.type                = NP_DATA_TYPE_BIN;
  strncpy(conf.key, key, 254);

  if (0 != memcmp(&dhkey_zero, subject, NP_FINGERPRINT_BYTES)) {
    np_dhkey_t subject_dhkey = {0};
    memcpy(&subject_dhkey, subject, NP_FINGERPRINT_BYTES);
    np_msgproperty_run_t *property =
        _np_msgproperty_run_get(context, INBOUND, subject_dhkey);
    if (property != NULL) {
      ret =
          np_set_data(property->attributes, conf, (np_data_value){.bin = bin});
    }
    property = NULL;
    property = _np_msgproperty_run_get(context, OUTBOUND, subject_dhkey);
    if (property != NULL) {
      ret =
          np_set_data(property->attributes, conf, (np_data_value){.bin = bin});
    }
  }

  if (inheritance != NP_ATTR_NONE)
    ret = np_set_data(np_module(attributes)->attribute_cache[inheritance],
                      conf,
                      (np_data_value){.bin = bin});

  return ret;
}

enum np_data_return np_get_msg_attr_bin(struct np_message    *msg,
                                        char                  key[255],
                                        struct np_data_conf **out_data_config,
                                        unsigned char       **out_data) {
    assert (*out_data != NULL);
  enum np_data_return ret;

  struct np_data_conf *conf = NULL;
  if (out_data_config != NULL) conf = *out_data_config;
  np_data_value val;
  ret = np_get_data(msg->attributes, key, conf, &val);

  if (out_data != NULL) memcpy(*out_data, val.bin, conf->data_size);

  return ret;
}

enum np_data_return np_get_token_attr_bin(struct np_token      *ident,
                                          char                  key[255],
                                          struct np_data_conf **out_data_config,
                                          unsigned char       **out_data) {
  enum np_data_return ret;

  struct np_data_conf *conf = NULL;
  if (out_data_config != NULL) conf = *out_data_config;
  np_data_value val;
  ret = np_get_data(ident->attributes, key, conf, &val);

  if (out_data != NULL) *out_data = val.bin;

  return ret;
}

np_attributes_t *_np_get_attributes_cache(np_state_t           *context,
                                          enum np_msg_attr_type cache) {
  assert(cache != NP_ATTR_NONE);

  return &np_module(attributes)->attribute_cache[cache];
}

enum np_data_return np_set_mxp_attr_policy_bin(np_context    *ac,
                                               np_subject     subject,
                                               char           key[255],
                                               unsigned char *value,
                                               size_t         value_size) {
  np_ctx_cast(ac);

  enum np_data_return ret = np_key_not_found;

  if (subject != NULL) {
    np_dhkey_t subject_dhkey = {0};
    memcpy(&subject_dhkey, subject, NP_FINGERPRINT_BYTES);

    np_msgproperty_run_t *property =
        _np_msgproperty_run_get(context, INBOUND, subject_dhkey);
    if (property != NULL) {
      if (property->required_attributes_policy == NULL)
        property->required_attributes_policy = _np_attribute_bloom();

      if (value == NULL)
        _np_policy_set_key(property->required_attributes_policy, key);
      else
        _np_policy_set_bin(property->required_attributes_policy,
                           key,
                           value,
                           value_size);
      // ret = np_data_ok;
    }
    property = NULL;
    property = _np_msgproperty_run_get(context, OUTBOUND, subject_dhkey);
    if (property != NULL) {
      if (property->required_attributes_policy == NULL)
        property->required_attributes_policy = _np_attribute_bloom();

      if (value == NULL)
        _np_policy_set_key(property->required_attributes_policy, key);
      else
        _np_policy_set_bin(property->required_attributes_policy,
                           key,
                           value,
                           value_size);
      ret = np_data_ok;
    }

    else {
      ret = np_invalid_operation;
    }
  }

  return ret;
}

void _np_policy_set_key(np_bloom_t *bloom, char key[255]) {
  ASSERT(bloom != NULL, "Bloom cannot be null");
  np_dhkey_t _key = np_dhkey_create_from_hostport(key, "required");
  bloom->op.add_cb(bloom, _key);
}

void _np_policy_set_bin(np_bloom_t    *bloom,
                        char           key[255],
                        unsigned char *value,
                        size_t         value_size) {
  ASSERT(bloom != NULL, "Bloom cannot be null");
  _np_policy_set_key(bloom, key);
  np_dhkey_t _key = _np_dhkey_generate_hash(value, value_size);
  bloom->op.add_cb(bloom, _key);
}

np_bloom_t *_np_attribute_bloom() {
  struct np_bloom_optable_s neuropil_operations = {
      .add_cb       = _np_neuropil_bloom_add,
      .check_cb     = _np_neuropil_bloom_check,
      .clear_cb     = _np_neuropil_bloom_clear,
      .union_cb     = _np_neuropil_bloom_union,
      .intersect_cb = _np_neuropil_bloom_intersect_ignore_age,
  };

  np_bloom_t *bloom = _np_neuropil_bloom_create();
  bloom->op         = neuropil_operations;

  return bloom;
}

bool __np_policy_classic_build_attribute_bloom(
    struct np_data_conf *out_data_config,
    np_data_value       *out_data,
    void                *userdata) {
  np_bloom_t *bloom = (np_bloom_t *)userdata;
  _np_policy_set_key(bloom, out_data_config->key);

  switch (out_data_config->type) {
  case NP_DATA_TYPE_BIN:
    _np_policy_set_bin(bloom,
                       out_data_config->key,
                       out_data->bin,
                       out_data_config->data_size);
    break;
  case NP_DATA_TYPE_INT:
    _np_policy_set_bin(bloom,
                       out_data_config->key,
                       &out_data->integer,
                       out_data_config->data_size);
    break;
  case NP_DATA_TYPE_STR:
    _np_policy_set_bin(bloom,
                       out_data_config->key,
                       out_data->str,
                       out_data_config->data_size);
    break;
  case NP_DATA_TYPE_UNSIGNED_INT:
    _np_policy_set_bin(bloom,
                       out_data_config->key,
                       &out_data->unsigned_integer,
                       out_data_config->data_size);
    break;
  default:
    ASSERT(false,
           "missing implementation for type %" PRIu32 " key: %255s",
           out_data_config->type,
           out_data_config->key);
    break;
  }

  return true;
}

bool _np_attribute_build_bloom(np_bloom_t      *target,
                               np_attributes_t *attributes) {
  enum np_data_return r =
      np_iterate_data((np_datablock_t *)attributes,
                      __np_policy_classic_build_attribute_bloom,
                      target);
  return r == np_data_ok;
}

bool _np_policy_check_compliance(np_bloom_t      *policy,
                                 np_attributes_t *attributes) {
  bool        ret                               = false;
  np_bloom_t *all_relevant_hashes_of_attributes = _np_attribute_bloom();

  // test for empty policy
  if (policy == NULL ||
      _np_neuropil_bloom_cmp(all_relevant_hashes_of_attributes, policy) == 0) {
    ret = true;
  } else {
    ret = _np_attribute_build_bloom(all_relevant_hashes_of_attributes,
                                    attributes);

    if (ret) {
      np_bloom_t *policy_relevant_elements_of_attributes =
          _np_attribute_bloom();
      policy_relevant_elements_of_attributes->op.union_cb(
          policy_relevant_elements_of_attributes,
          policy);
      policy_relevant_elements_of_attributes->op.intersect_cb(
          policy_relevant_elements_of_attributes,
          all_relevant_hashes_of_attributes);

      ret = _np_neuropil_bloom_cmp(policy,
                                   policy_relevant_elements_of_attributes) == 0;

      _np_bloom_free(policy_relevant_elements_of_attributes);
    }
  }
  _np_bloom_free(all_relevant_hashes_of_attributes);
  return ret;
}
