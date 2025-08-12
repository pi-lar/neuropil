//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#ifndef NP_ATTR_H_
#define NP_ATTR_H_

#include "neuropil.h"
#include "neuropil_data.h"

#ifdef __cplusplus
extern "C" {
#endif

enum np_msg_attr_type {
  NP_ATTR_NONE = -1,
  NP_ATTR_USER_MSG,
  NP_ATTR_INTENT,
  NP_ATTR_IDENTITY,              // e.g. used when joining a network
  NP_ATTR_IDENTITY_AND_USER_MSG, // e.g. used to secure the bootstapping
                                 // process.
  // Scenario for further documentation:
  // Node "A" wants to connect to node "B"
  // "B" requests attr key "K1" to be given.  ("K1" is not in JOIN msg)
  // Node A registers by realm master "C"
  // "C" answers with a attribute "K1" configured for
  // NP_ATTR_IDENTITY_AND_USER_MSG "A" now saves "K1" in its identity token (so
  // it can be saved) ("K1" is now in every JOIN msg) "A" now preps every user
  // message send with attribute "K1" (for example: SessionID)

  NP_ATTR_INTENT_AND_USER_MSG,
  NP_ATTR_INTENT_AND_IDENTITY,
  NP_ATTR_MAX,

} NP_CONST_ENUM;

NP_API_EXPORT
enum np_data_return np_set_ident_attr_bin(np_context           *ac,
                                          struct np_token      *ident,
                                          enum np_msg_attr_type inheritance,
                                          char                  key[255],
                                          unsigned char        *bin,
                                          size_t                bin_length);
NP_API_EXPORT
enum np_data_return np_set_mxp_attr_bin(np_context           *ac,
                                        np_subject            subject,
                                        enum np_msg_attr_type inheritance,
                                        char                  key[255],
                                        unsigned char        *bin,
                                        size_t                bin_length);

NP_API_EXPORT
enum np_data_return np_get_msg_attr_bin(struct np_message    *msg,
                                        char                  key[255],
                                        struct np_data_conf **out_data_config,
                                        unsigned char       **out_data);
NP_API_EXPORT
enum np_data_return np_get_token_attr_bin(struct np_token      *ident,
                                          char                  key[255],
                                          struct np_data_conf **out_data_config,
                                          unsigned char       **out_data);

// NP_API_EXPORT
// enum np_data_return np_set_mxp_attr_policy_str(np_context *ac, char* subject,
// char key[255], char* value[1024], size_t value_size);
NP_API_EXPORT
enum np_data_return np_set_mxp_attr_policy_bin(np_context    *ac,
                                               np_subject     subject,
                                               char           key[255],
                                               unsigned char *value,
                                               size_t         value_size);

#ifdef __cplusplus
}
#endif
#endif /* NP_ATTR_H_ */

/**

Attribute Initialization
------------------------

The purpose of this API is to enable the user to create and use arbitrary
attributes on :c:data:`np_token` and message intent level.

Attributes can then be e.g. used to:

  - publish searchable metadata (e.g. the location of a temperature sensor or
the cost of a data sample)

  - create a `SessionID <https://en.wikipedia.org/wiki/Session_ID>`_ based
authentication. (see: :c:data:`NP_ATTR_IDENTITY_AND_USER_MSG`)

  - many more ...


.. c:enum:: np_msg_attr_type

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

    :param ident:        the :c:type:`np_token` to set the attribute for
    :param inheritance:  the :c:type:`np_msg_attr_type` inheritance level for
this attribute :param key:          the network wide identifier for this
attribute :param bin:          the attribute value as binary blob :param
bin_length:   the length of the blob :return: :c:data:`np_ok` on success


.. c:function:: enum np_return np_set_mxp_attr_bin(struct np_mx_properties*
prop, enum np_msg_attr_type  inheritance, char key[255], unsigned char * bin,
size_t bin_length)

   Sets an message exchange level wide attribute

    :param prop:         the :c:type:`np_mx_properties` to set the attribute for
    :param inheritance:  the :c:type:`np_msg_attr_type` inheritance level for
this attribute, only non NP_ATTR_IDENTITY... values are respected. :param key:
the network wide identifier for this attribute :param bin:          the
attribute value as binary blob :param bin_length:   the length of the blob
    :return: :c:data:`np_ok` on success

**/
