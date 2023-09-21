//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#ifndef _NP_CONSTANTS_H_
#define _NP_CONSTANTS_H_

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ref_message_bin_static       "ref_message_bin_static"
#define ref_msgpartcache             "ref_msgpartcache"
#define ref_state_nodekey            "ref_state_nodekey"
#define ref_state_identitykey        "ref_state_identitykey"
#define ref_obj_creation             "ref_obj_creation"
#define ref_obj_usage                "ref_obj_usage"
#define ref_keycache                 "ref_keycache"
#define ref_key_recv_property        "ref_key_recv_property"
#define ref_key_send_property        "ref_key_send_property"
#define ref_key_aaa_token            "ref_key_aaa_token"
#define ref_key_node                 "ref_key_node"
#define ref_key_network              "ref_key_network"
#define ref_aaatoken_local_mx_tokens "ref_aaatoken_local_mx_tokens"
#define ref_message_messagepart      "ref_message_messagepart"
#define ref_system_msgproperty       "ref_system_msgproperty"
#define ref_route_routingtable_mykey "ref_route_routingtable_mykey"
#define ref_route_inroute            "ref_route_inroute"
#define ref_route_inleafset          "ref_route_inleafset"
#define ref_msgproperty_msgcache     "ref_msgproperty_msgcache"
#define ref_key_parent               "ref_key_parent"
#define ref_message_msg_property     "ref_message_msg_property"
#define ref_ack_obj                  "ref_ack_obj"
#define ref_ack_msg                  "ref_ack_msg"
#define ref_ack_key                  "ref_ack_key"
#define ref_msgproperty_current_recieve_token                                  \
  "ref_msgproperty_current_recieve_token"
#define ref_msgproperty_current_sender_token                                   \
  "ref_msgproperty_current_sender_token"
#define ref_bootstrap_list "ref_bootstrap_list"

#define NP_SERIALISATION_NODE_KEY          "np.n.k"
#define NP_SERIALISATION_NODE_PROTOCOL     "np.n.pr"
#define NP_SERIALISATION_NODE_DNS_NAME     "np.n.d"
#define NP_SERIALISATION_NODE_PORT         "np.n.p"
#define NP_SERIALISATION_NODE_CREATED_AT   "np.n.c"
#define NP_SERIALISATION_NODE_SUCCESS_AVG  "np.n.sa"
#define NP_SERIALISATION_NODE_LATENCY      "np.n.l"
#define NP_SERIALISATION_NODE_LAST_SUCCESS "np.n.ls"

#define NP_SERIALISATION_USERDATA   "np.userdata"
#define NP_SERIALISATION_ATTRIBUTES "np.attributes"

#define NP_NONCE     "_np.nonce"
#define NP_ENCRYPTED "_np.encrypted"
#define NP_SYMKEY    "_np.symkey"

#define NP_AAATOKEN_MAX_SIZE_EXTENSIONS (1024)

/*
PRIORITY:
0 defines the first job to execute
...
99... defines the last job to execute
*/

#define PRIORITY_MOD_LEVEL_0 (0)

#define PRIORITY_MOD_LEVEL_1 (1)

#define PRIORITY_MOD_LEVEL_2 (2)

#define PRIORITY_MOD_LEVEL_3 (3)

#define PRIORITY_MOD_LEVEL_4 (4)

#define NP_PRIORITY_MAX_QUEUES (PRIORITY_MOD_LEVEL_4)
// C-System (memory, ...)
#define NP_PRIORITY_HIGHEST (MIN(NP_PRIORITY_MAX_QUEUES, PRIORITY_MOD_LEVEL_0))
// Protocol
#define NP_PRIORITY_HIGH (MIN(NP_PRIORITY_MAX_QUEUES, PRIORITY_MOD_LEVEL_1))
// Encrypted messages
#define NP_PRIORITY_MEDIUM (MIN(NP_PRIORITY_MAX_QUEUES, PRIORITY_MOD_LEVEL_2))
// Unencrypted messages
#define NP_PRIORITY_LOW (MIN(NP_PRIORITY_MAX_QUEUES, PRIORITY_MOD_LEVEL_3))
// 3.Party Jobs
#define NP_PRIORITY_LOWEST (MIN(NP_PRIORITY_MAX_QUEUES, PRIORITY_MOD_LEVEL_4))

/*
        Every CHAR_LENGTH_* may contain the final \0 char
*/
#define CHAR_LENGTH_PORT (8)
#define CHAR_LENGTH_IP   (255)

#define _CONCAT(a, b) a##b
#define CONCAT(a, b)  _CONCAT(a, b)

/* Macro for overloading macros
 * Use like this if you want to overload foo(a,b) with foo(a,b,c)
 * #define foo(...) VFUNC(foo, __VA_ARGS__)
 * #define foo2(a, b) foo3(a, b, default_c)
 * #define foo3(a, b, c)  <insert_foo_fn>
 *
 * the number after foo in the function has to match the count of function
 * arguments. It is not possible to overload with the same number of arguments
 *
 */
#define __NARG__(...)  __NARG_I_(__VA_ARGS__, __RSEQ_N())
#define __NARG_I_(...) __ARG_N(__VA_ARGS__)
#define __ARG_N(_1,                                                            \
                _2,                                                            \
                _3,                                                            \
                _4,                                                            \
                _5,                                                            \
                _6,                                                            \
                _7,                                                            \
                _8,                                                            \
                _9,                                                            \
                _10,                                                           \
                _11,                                                           \
                _12,                                                           \
                _13,                                                           \
                _14,                                                           \
                _15,                                                           \
                _16,                                                           \
                _17,                                                           \
                _18,                                                           \
                _19,                                                           \
                _20,                                                           \
                _21,                                                           \
                _22,                                                           \
                _23,                                                           \
                _24,                                                           \
                _25,                                                           \
                _26,                                                           \
                _27,                                                           \
                _28,                                                           \
                _29,                                                           \
                _30,                                                           \
                _31,                                                           \
                _32,                                                           \
                _33,                                                           \
                _34,                                                           \
                _35,                                                           \
                _36,                                                           \
                _37,                                                           \
                _38,                                                           \
                _39,                                                           \
                _40,                                                           \
                _41,                                                           \
                _42,                                                           \
                _43,                                                           \
                _44,                                                           \
                _45,                                                           \
                _46,                                                           \
                _47,                                                           \
                _48,                                                           \
                _49,                                                           \
                _50,                                                           \
                _51,                                                           \
                _52,                                                           \
                _53,                                                           \
                _54,                                                           \
                _55,                                                           \
                _56,                                                           \
                _57,                                                           \
                _58,                                                           \
                _59,                                                           \
                _60,                                                           \
                _61,                                                           \
                _62,                                                           \
                _63,                                                           \
                N,                                                             \
                ...)                                                           \
  N
#define __RSEQ_N()                                                             \
  63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45,  \
      44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27,  \
      26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9,   \
      8, 7, 6, 5, 4, 3, 2, 1, 0

// general definition for any function name
#define VFUNC(func, ...) CONCAT(func, __NARG__(__VA_ARGS__))(__VA_ARGS__)

#define DEPRECATED __attribute__((deprecated))

#define SIZE(ARRAY) (sizeof(ARRAY) / sizeof(ARRAY[0]))

#define FUNC ((char *)__func__)

#ifndef PRIsizet
#define PRIsizet "zu"
#endif
#ifdef __cplusplus
}
#endif

#endif /* NP_CONSTANTS_H_ */
