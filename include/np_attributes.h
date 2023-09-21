//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project
#ifndef _NP_ATTR_INNER_H_
#define _NP_ATTR_INNER_H_

#include "neuropil_attributes.h"

#include "util/np_bloom.h"

#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif
// neuropil setup functions
NP_API_PROTEC
bool _np_attributes_init(np_state_t *context);
NP_API_PROTEC
void _np_attributes_destroy(np_state_t *context);
NP_API_PROTEC
np_attributes_t *_np_get_attributes_cache(np_state_t           *context,
                                          enum np_msg_attr_type cache);
NP_API_INTERN
void _np_policy_set_key(np_bloom_t *bloom, char key[255]);
NP_API_INTERN
void _np_policy_set_bin(np_bloom_t    *bloom,
                        char           key[255],
                        unsigned char *value,
                        size_t         value_size);
NP_API_INTERN
bool _np_policy_check_compliance(np_bloom_t      *policy,
                                 np_attributes_t *attributes);
NP_API_INTERN
bool _np_attribute_build_bloom(np_bloom_t *target, np_attributes_t *attributes);
NP_API_INTERN
np_bloom_t *_np_attribute_bloom();

#ifdef __cplusplus
}
#endif
#endif /* _NP_ATTR_INNER_H_ */

/**
--------------
Initialization
--------------

The purpose of this API is to enable the user to create and use arbitrary
attributes on :c:data:`np_token` and message intent level.

Attributes can then be e.g. used to:

  - publish searchable metadata (e.g. the location of a temperature sensor or
the cost of a data sample)

  - create a `SessionID <https://en.wikipedia.org/wiki/Session_ID>`_ based
authentication. (see: :c:data:`NP_ATTR_IDENTITY_AND_USER_MSG`)

  - many more ...

.. c:type:: enum np_msg_attr_type

   This type denotes the set of scope levels relevant for a given attribute.

   Possible values include:

   ================================================
====================================================================== Value
Meaning
   ================================================
======================================================================
   :c:data:`NP_ATTR_USER_MSG`                        The attribute will be
available in every USER message. (end-to-end encrypted)
   :c:data:`NP_ATTR_IDENTITY`                        The attribute will be
appended to the identity :c:data:`np_token` and will then be transfered to every
node receiving a :c:data:`_NP.JOIN.REQUEST`  request. (end-to-end encrypted)
   :c:data:`NP_ATTR_INTENT`                          The attribute will be
appended to every :c:data:`_NP.MESSAGE.DISCOVER.RECEIVER` and
:c:data:`_NP.MESSAGE.DISCOVER.SENDER` message. (transport encrypted)
   :c:data:`NP_ATTR_IDENTITY_AND_USER_MSG`           combine
:c:data:`NP_ATTR_USER_MSG` and :c:data:`NP_ATTR_IDENTITY`
   :c:data:`NP_ATTR_INTENT_AND_USER_MSG`             combine
:c:data:`NP_ATTR_USER_MSG` and :c:data:`NP_ATTR_INTENT`
   :c:data:`NP_ATTR_INTENT_AND_IDENTITY`             combine
:c:data:`NP_ATTR_INTENT`   and :c:data:`NP_ATTR_IDENTITY`
   ================================================
======================================================================

.. c:function:: enum np_return np_set_ident_attr_bin(struct np_token* ident,
enum np_msg_attr_type  inheritance, char key[255], unsigned char * bin, size_t
bin_length)

   Sets an identity level wide attribute

    :param ident:        the :c:type:`struct np_token` to set the attribute for
    :param inheritance:  the :c:type:`enum np_msg_attr_type` inheritance level
for this attribute :param key:          the network wide identifier for this
attribute :param bin:          the attribute value as binary blob :param
bin_length:   the length of the blob :return: :c:data:`np_ok` on success

.. c:function:: enum np_return np_set_mxp_attr_bin(struct np_mx_properties*
prop, enum np_msg_attr_type  inheritance, char key[255], unsigned char * bin,
size_t bin_length)

   Sets an message exchange level wide attribute

    :param prop:         the :c:type:`struct np_mx_properties` to set the
attribute for :param inheritance:  the :c:type:`enum np_msg_attr_type`
inheritance level for this attribute, only non NP_ATTR_IDENTITY... values are
respected. :param key:          the network wide identifier for this attribute
    :param bin:          the attribute value as binary blob
    :param bin_length:   the length of the blob
    :return: :c:data:`np_ok` on success

**/
