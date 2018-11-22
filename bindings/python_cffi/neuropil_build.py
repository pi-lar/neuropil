import os
from cffi import FFI

ffibuilder = FFI()

PATH = os.path.dirname(__file__)
np_lib_path = os.path.join(PATH, "../../build/lib")
np_include_path = os.path.join(PATH, "../../include")

# This describes the extension module "_neuropil" to produce.
ffibuilder.set_source(
	"_neuropil",
	r"""
    		#include "neuropil.h"   // the C header of the library
    	""",

    libraries=['neuropil', 'sodium'],   # library name, for the linker
    # extra_objects=[np_lib_path],
    library_dirs=[np_lib_path],
    include_dirs=[np_include_path]
	)
	

# sourcefile = os.path.join('.', 'beta.h')
# source = os.path.join('.', 'beta.c')
# with open(sourcefile) as f:
#     ffibuilder.cdef(f.read())

    
# cdef() expects a string listing the C types, functions and
# globals needed from Python. The string follows the C syntax.
ffibuilder.cdef(
    r"""
	    // Protocol constants
	    typedef enum {
	        NP_PUBLIC_KEY_BYTES = 32,
	        NP_FINGERPRINT_BYTES = 32,
	        NP_UUID_BYTES = 37,
	        NP_SECRET_KEY_BYTES = 64
	    };
	
	    // Implementation defined limits
	    #define NP_EXTENSION_BYTES 10240
	    #define NP_EXTENSION_MAX 10239
    """,
    packed=True)

ffibuilder.cdef(
    r"""
	    struct np_token {
	        char uuid[NP_UUID_BYTES];
	        char subject[255]; // todo: has to be np_id
	        char issuer[65]; // todo: has to be np_id		
	        char realm[255]; // todo: has to be np_id		
	        char audience[255]; // todo: has to be np_id		
	
	        double issued_at, not_before, expires_at;
	        uint8_t extensions[NP_EXTENSION_BYTES];
	        size_t extension_length;
	        uint8_t public_key[NP_PUBLIC_KEY_BYTES],
	                secret_key[NP_SECRET_KEY_BYTES];
	    };
    """,
    packed=True)

ffibuilder.cdef(
    r"""
	    enum np_status {
	        np_error = 0,
	        np_uninitialized,
	        np_running,
	        np_stopped,
	        np_shutdown,		
	    };
	
	    enum np_error {
	        np_ok = 0,
	        np_not_implemented,
	        np_network_error,
	        np_invalid_argument,
	        np_invalid_operation,
	        np_startup
	        // ...
	    } ;
	
	    static const char* np_error_str[] = {
	        "none",
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
	
	    struct np_settings * np_default_settings(struct np_settings *settings);
	    np_context* np_new_context(struct np_settings *settings);
	
	    // secret_key is nullable
	    struct np_token np_new_identity(np_context* ac, double expires_at, uint8_t* secret_key[NP_SECRET_KEY_BYTES]);
	    enum np_error   np_use_identity(np_context* ac, struct np_token identity);
	
	    typedef bool (*np_aaa_callback)(np_context* ac, struct np_token* aaa_token);    
	    enum np_error np_set_authenticate_cb(np_context* ac, np_aaa_callback callback);    
	    enum np_error np_set_authorize_cb(np_context* ac, np_aaa_callback callback);    
	    enum np_error np_set_accounting_cb(np_context* ac, np_aaa_callback callback);
	
	    enum np_error np_listen(np_context* ac, char* protocol, char* host, uint16_t port);
	    // Get “connect string”. Signals error if connect string is unavailable (i.e.,
	    // no listening interface is configured.)
	    enum np_error np_get_address(np_context* ac, char* address, uint32_t max);
	    enum np_error np_join(np_context* ac, char* address);
	
	    typedef bool (*np_receive_callback)(np_context* ac, struct np_message* message);
	    enum np_error np_send   (np_context* ac, char* subject, uint8_t* message, size_t length);
	    enum np_error np_send_to(np_context* ac, char* subject, uint8_t* message, size_t length, np_id * target);    
	    
	    // There can be more than one receive callback, hence "add".
	    enum np_error np_add_receive_cb(np_context* ac, char* subject, np_receive_callback callback);
	    bool np_has_receiver_for(np_context*ac, char * subject);	
	    
	    // duration: 0 => process pending events and return
	    //           N => process events for up to N seconds and return
	    enum np_error np_run(np_context* ac, double duration);
	
	    //enum np_mx_pattern    { NP_MX_BROADCAST, NP_MX_ANY, NP_MX_ONE_WAY, NP_MX_REQ_REP, /* ... */ };
	    typedef enum np_mx_cache_policy { NP_MX_FIFO_REJECT, NP_MX_FIFO_PURGE, NP_MX_LIFO_REJECT, NP_MX_LIFO_PURGE };
	    typedef enum np_mx_ackmode      { NP_MX_ACK_NONE, NP_MX_ACK_DESTINATION, NP_MX_ACK_CLIENT };
	
	    struct np_mx_properties {
	        char reply_subject[255];
	        enum np_mx_ackmode ackmode;
	        //enum np_mx_pattern pattern;  will be added later on
	        enum np_mx_cache_policy cache_policy;
	        uint32_t max_parallel, max_retry;
	        double intent_ttl, intent_update_after;
	        double message_ttl;
	    };
	    
	    struct np_mx_properties np_get_mx_properties(np_context* ac, char* subject);    
	    enum np_error np_set_mx_properties(np_context* ac, char* subject, struct np_mx_properties properties);
	    
	    void np_set_userdata(np_context * ac, void* userdata);
	    void* np_get_userdata(np_context * ac);
	
	    bool np_has_joined(np_context * ac);		
	    enum np_status np_get_status(np_context* ac);
	    
	    void np_id2str(np_id* k, char* key_string);
	    void np_str2id(const char* key_string, np_id* k);
    """)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
