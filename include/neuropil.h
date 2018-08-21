//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

/* Neuropil API v2 */

#ifndef _NP_INTERFACE_H_
#define _NP_INTERFACE_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
#define NEUROPIL_RELEASE	"neuropil_0.6.0"
#ifndef NEUROPIL_RELEASE_BUILD
#define NEUROPIL_RELEASE_BUILD 0
#endif //NEUROPIL_RELEASE_BUILD

#define NEUROPIL_COPYRIGHT	"copyright (C)  2016-2018 neuropil.org, Cologne, Germany"
#define NEUROPIL_TRADEMARK  "trademark (TM) 2016-2018 pi-lar GmbH, Cologne, Germany"


    /* just in case NULL is not defined */
#ifndef NULL
#define NULL (void*)0
#endif

    //
    // int __attribute__((overloadable)) square(int);

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__linux__)
    #define NP_ENUM
#endif
#if defined(__APPLE__) && defined(__MACH__)
    #define NP_ENUM __attribute__ ((flag_enum))
#endif

#define NP_CONST __attribute__ ((const))
#define NP_PURE  __attribute__ ((pure))

#define NP_PACKED(x)  __attribute__ ((packed(x)))
#define NP_DEPRECATED __attribute__ ((deprecated("!!! DEPRECATED !!!")))



#if defined(TEST_COMPILE) || defined(DEBUG)
#define NP_UNUSED     __attribute__ ((unused))
#define NP_API_HIDDEN __attribute__ ((visibility ("default")))
#define NP_API_PROTEC __attribute__ ((visibility ("default")))
#define NP_API_INTERN __attribute__ ((visibility ("default")))
#else
#ifndef NP_UNUSED
#define NP_UNUSED     __attribute__ ((unused))
#endif
#ifndef NP_API_PROTEC
#define NP_API_PROTEC __attribute__ ((visibility ("default")))
#endif
#ifndef NP_API_HIDDEN
#define NP_API_HIDDEN __attribute__ ((visibility ("default")))
#endif
#ifndef NP_API_INTERN
#define NP_API_INTERN __attribute__ ((visibility ("default")))
#endif
#endif

#ifndef NP_API_EXPORT
#define NP_API_EXPORT __attribute__ ((visibility ("default")))
#endif


    // Protocol constants
    enum {
        NP_SECRET_KEY_BYTES = 32,
        NP_PUBLIC_KEY_BYTES = 32,
        NP_FINGERPRINT_BYTES = 32,
        NP_UUID_BYTES = 37
    } NP_ENUM;

    // Implementation defined limits
    #define NP_EXTENSION_BYTES (10*1024)
    #define NP_EXTENSION_MAX (NP_EXTENSION_BYTES-1)

    enum np_status {
        np_error = 0,
        np_uninitialized,
        np_running,
        np_stopped,
        np_shutdown,		
    } NP_ENUM;

    enum np_error {
        np_ok = 0,
        np_not_implemented,
        np_network_error,
        np_invalid_argument,
        np_invalid_operation,
        np_startup
        // ...
    } NP_ENUM;

    static const char* np_error_str[] = {
        "",
        "operation is not implemented",
        "could not init network",
        "argument is invalid",
        "operation is currently invalid",
        "insufficient memory",
        "startup error. See log for more details"
    };
    
    typedef void np_context;    

	typedef uint8_t np_id[NP_FINGERPRINT_BYTES];
	
    // If length is 0 then string is expected to be null-terminated.
    // char* is the appropriate type because it is the type of a string
    // and can also describe an array of bytes. (sizeof char == 1)
    void np_get_id(np_context * context, np_id* id, char* string, size_t length);

    struct np_token {
        char subject[255]; // todo: has to be np_id
        np_id realm, issuer, audience;
        double issued_at, not_before, expires_at;
        uint8_t extensions[NP_EXTENSION_BYTES];
        size_t extension_length;
        uint8_t public_key[NP_PUBLIC_KEY_BYTES],
            secret_key[NP_SECRET_KEY_BYTES];
    };
    
    struct np_message {
        char uuid[NP_UUID_BYTES];
        np_id from; 
        np_id subject;		
        double received_at;
        uint8_t * data;
        size_t data_length;
    };
        
    struct np_settings {
        uint32_t n_threads;
        char log_file[256];
        uint32_t log_level;
        // ...
    };

    NP_API_EXPORT
    struct np_settings * np_default_settings(struct np_settings *settings);

    NP_API_EXPORT
    np_context* np_new_context(struct np_settings *settings);

    // secret_key is nullable
    NP_API_EXPORT
    struct np_token *np_new_identity(np_context* ac, double expires_at, uint8_t* (secret_key[NP_SECRET_KEY_BYTES]));

    NP_API_EXPORT
    enum np_error np_set_identity(np_context* ac, struct np_token identity);

    NP_API_EXPORT
    enum np_error np_listen(np_context* ac, char* protocol, char* host, uint16_t port);

    // Get “connect string”. Signals error if connect string is unavailable (i.e.,
    // no listening interface is configured.)
    NP_API_EXPORT
    enum np_error np_get_address(np_context* ac, char* address, uint32_t max);

    NP_API_EXPORT
    enum np_error np_join(np_context* ac, char* address);

    NP_API_EXPORT
    enum np_error np_send(np_context* ac, char* subject, uint8_t* message, size_t length);
    
    typedef bool (*np_receive_callback)(np_context* ac, struct np_message* message);

    // There can be more than one receive callback, hence "add".
    NP_API_EXPORT
    enum np_error np_add_receive_cb(np_context* ac, char* subject, np_receive_callback callback);

    typedef bool (*np_aaa_callback)(np_context* ac, struct np_token* aaa_token);
    NP_API_EXPORT
    enum np_error np_set_authenticate_cb(np_context* ac, np_aaa_callback callback);
    NP_API_EXPORT
    enum np_error np_set_authorize_cb(np_context* ac, np_aaa_callback callback);
    NP_API_EXPORT
    enum np_error np_set_accounting_cb(np_context* ac, np_aaa_callback callback);
    

    // duration: 0 => process pending events and return
    //           N => process events for up to N seconds and return
    NP_API_EXPORT
    enum np_error np_run(np_context* ac, double duration);

    //enum np_mx_pattern      { NP_MX_BROADCAST, NP_MX_ANY, NP_MX_ONE_WAY, NP_MX_REQ_REP, /* ... */ } NP_ENUM;
    enum np_mx_cache_policy { NP_MX_FIFO_REJECT, NP_MX_FIFO_PURGE, NP_MX_LIFO_REJECT, NP_MX_LIFO_PURGE } NP_ENUM;
    enum np_mx_ackmode      { NP_MX_ACK_NONE, NP_MX_ACK_DESTINATION, NP_MX_ACK_CLIENT } NP_ENUM;

    struct np_mx_properties {
        char reply_subject[255];
        enum np_mx_ackmode ackmode;
        //enum np_mx_pattern pattern;  will be added later on
        enum np_mx_cache_policy cache_policy;
        uint32_t max_parallel, max_retry;
        double intent_ttl, intent_update_after;
        double message_ttl;
    };

    NP_API_EXPORT
    struct np_mx_properties np_get_mx_properties(np_context* ac, char* subject);
    NP_API_EXPORT
    enum np_error np_set_mx_properties(np_context* ac, char* subject, struct np_mx_properties properties);
    NP_API_EXPORT
    void np_set_userdata(np_context * ac, void* userdata);
    NP_API_EXPORT
    void* np_get_userdata(np_context * ac);
    

    NP_API_EXPORT
        enum np_error np_send_to(np_context* ac, char* subject, uint8_t* message, size_t length, np_id * target);
    NP_API_EXPORT
        bool np_has_joined(np_context * ac);		
    NP_API_EXPORT
        enum np_status np_get_status(np_context* ac);
    NP_API_EXPORT
        bool np_has_receiver_for(np_context*ac, char * subject);	
    NP_API_EXPORT
        void np_id2str(const np_id* k, char* key_string);
    NP_API_EXPORT
        void np_str2id(const char* key_string, np_id* k);


#ifdef __cplusplus
}
#endif

#endif /* _NP_INTERFACE_H_ */
