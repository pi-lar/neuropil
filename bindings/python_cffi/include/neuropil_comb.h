    enum np_limits {
        NP_SECRET_KEY_BYTES = 64,
        NP_SIGNATURE_BYTES = 64,
        NP_PUBLIC_KEY_BYTES = 32,
        NP_FINGERPRINT_BYTES = 32,
        NP_UUID_BYTES = 37,
        NP_EXTENSION_BYTES = 10240,
    } ;
    enum np_status {
        np_error = 0,
        np_uninitialized,
        np_running,
        np_stopped,
        np_shutdown,
    } ;
    enum np_return {
        np_ok = 0,
        np_unknown_error,
        np_not_implemented,
        np_network_error,
        np_invalid_argument,
        np_invalid_operation,
        np_startup,
    } ;
    const char *np_error_str(enum np_return e);
    struct version_t {
        uint8_t major;
        uint8_t minor;
        uint8_t patch;
    } ;
    typedef void np_context;
   typedef unsigned char np_id[NP_FINGERPRINT_BYTES];
   typedef unsigned char np_attributes_t[NP_EXTENSION_BYTES];
   typedef unsigned char np_signature_t[NP_SIGNATURE_BYTES];
    void np_get_id(np_id (*id), const char* string, size_t length);
    struct np_token {
        char uuid[NP_UUID_BYTES];
        char subject[255];
        char issuer[65];
        char realm[255];
        char audience[255];
        double issued_at, not_before, expires_at;
        unsigned char public_key[NP_PUBLIC_KEY_BYTES],
                secret_key[NP_SECRET_KEY_BYTES];
        np_signature_t signature;
        np_attributes_t attributes;
        np_signature_t attributes_signature;
    } ;
    struct np_message {
        char uuid[NP_UUID_BYTES];
        np_id from;
        np_id subject;
        double received_at;
        unsigned char * data;
        size_t data_length;
        np_attributes_t attributes;
    } ;
    struct np_settings {
        uint32_t n_threads;
        char log_file[256];
        uint32_t log_level;
    } ;
    struct np_settings * np_default_settings(struct np_settings *settings);
    np_context* np_new_context(struct np_settings *settings);
    struct np_token np_new_identity(np_context* ac, double expires_at, unsigned char (*secret_key)[NP_SECRET_KEY_BYTES]);
    enum np_return np_use_identity(np_context* ac, struct np_token identity);
    enum np_return np_sign_identity(np_context* ac, struct np_token* identity, bool self_sign);
    enum np_return np_token_fingerprint(np_context* ac, struct np_token identity, bool include_attributes, np_id (*id));
    enum np_return np_node_fingerprint(np_context* ac, np_id (*id));
    enum np_return np_listen(np_context* ac, const char* protocol, const char* host, uint16_t port) ;
    enum np_return np_get_address(np_context* ac, char* address, uint32_t max);
    enum np_return np_join(np_context* ac, const char* address);
    enum np_return np_send(np_context* ac, const char* subject, const unsigned char* message, size_t length);
    typedef bool (*np_receive_callback)(np_context* ac, struct np_message* message);
    enum np_return np_add_receive_cb(np_context* ac, const char* subject, np_receive_callback callback);
    typedef bool (*np_aaa_callback)(np_context* ac, struct np_token* aaa_token);
    enum np_return np_set_authenticate_cb(np_context* ac, np_aaa_callback callback);
    enum np_return np_set_authorize_cb(np_context* ac, np_aaa_callback callback);
    enum np_return np_set_accounting_cb(np_context* ac, np_aaa_callback callback);
    enum np_return np_run(np_context* ac, double duration);
    enum np_mx_cache_policy { NP_MX_FIFO_REJECT, NP_MX_FIFO_PURGE, NP_MX_LIFO_REJECT, NP_MX_LIFO_PURGE } ;
    enum np_mx_ackmode { NP_MX_ACK_NONE, NP_MX_ACK_DESTINATION, NP_MX_ACK_CLIENT } ;
    struct np_mx_properties {
        char reply_subject[255] ;
        enum np_mx_ackmode ackmode;
        enum np_mx_cache_policy cache_policy;
        uint16_t cache_size;
        uint8_t max_parallel, max_retry;
        double intent_ttl, intent_update_after;
        double message_ttl;
    } ;
    struct np_mx_properties np_get_mx_properties(np_context* ac, const char* subject);
    enum np_return np_set_mx_properties(np_context* ac, const char* subject, struct np_mx_properties properties);
    void np_set_userdata(np_context * ac, void* userdata);
    void* np_get_userdata(np_context * ac);
        enum np_return np_send_to(np_context* ac, const char* subject, const unsigned char* message, size_t length, np_id (*target));
        bool np_has_joined(np_context * ac);
        enum np_status np_get_status(np_context* ac);
        bool np_has_receiver_for(np_context*ac, const char * subject);
        char * np_id_str(char str[65], const np_id id);
        void np_str_id(np_id (*id), const char str[65]);
        void np_destroy(np_context*ac, bool gracefully);
        bool np_id_equals(np_id first, np_id second);
    enum np_data_return {
        np_data_ok = 0,
        np_key_not_found = 1,
        np_insufficient_memory,
        np_invalid_structure,
        np_invalid_arguments,
        np_could_not_write_magicno,
        np_could_not_write_total_length,
        np_could_not_write_used_length,
        np_could_not_write_object_count,
        np_could_not_write_bin,
        np_could_not_write_str,
        np_could_not_write_int,
        np_could_not_write_uint,
        np_could_not_write_key,
        np_could_not_read_magicno,
        np_could_not_read_total_length,
        np_could_not_read_used_length,
        np_could_not_read_object_count,
        np_could_not_read_object,
        np_could_not_read_key,
    } ;
    enum np_data_type {
        NP_DATA_TYPE_MASK = 0xFFF000,
        NP_DATA_TYPE_BIN = 0x001000,
        NP_DATA_TYPE_INT = 0x002000,
        NP_DATA_TYPE_UNSIGNED_INT = 0x003000,
        NP_DATA_TYPE_STR = 0x004000,
    } ;
    struct np_data_conf {
        char key[255];
        enum np_data_type type;
        uint32_t data_size;
    } ;
    typedef union {
        unsigned char *bin;
        int32_t integer;
        uint32_t unsigned_integer;
        char * str;
    } np_data_value;
    typedef unsigned char np_datablock_t;
    enum np_data_return np_init_datablock(np_datablock_t * block, uint32_t block_length);
    enum np_data_return np_set_data(np_datablock_t * block, struct np_data_conf data_conf, np_data_value data);
    enum np_data_return np_get_data(np_datablock_t * block, char key[255], struct np_data_conf * out_data_config, np_data_value * out_data);
    enum np_data_return np_merge_data(np_datablock_t *dest, np_datablock_t *src);
    enum np_msg_attr_type {
        NP_ATTR_NONE = -1,
        NP_ATTR_USER_MSG,
        NP_ATTR_INTENT,
        NP_ATTR_IDENTITY,
        NP_ATTR_IDENTITY_AND_USER_MSG,
        NP_ATTR_INTENT_AND_USER_MSG,
        NP_ATTR_INTENT_AND_IDENTITY,
        NP_ATTR_MAX,
    } ;
    enum np_data_return np_set_ident_attr_bin(np_context *ac, struct np_token* ident, enum np_msg_attr_type inheritance, char key[255], unsigned char * bin, size_t bin_length);
    enum np_data_return np_set_mxp_attr_bin(np_context *ac, char * subject, enum np_msg_attr_type inheritance, char key[255], unsigned char * bin, size_t bin_length);
    enum np_data_return np_get_msg_attr_bin(struct np_message * msg, char key[255], struct np_data_conf ** out_data_config, unsigned char ** out_data);
    enum np_data_return np_get_token_attr_bin(struct np_token* ident, char key[255], struct np_data_conf ** out_data_config, unsigned char ** out_data);
   enum np_log_e
   {
      LOG_NONE = 0x00000000U,
      LOG_NOMOD = 0x00000000U,
      LOG_ERROR = 0x00000001U,
      LOG_WARN = 0x00000002U,
      LOG_INFO = 0x00000004U,
      LOG_DEBUG = 0x00000008U,
      LOG_TRACE = 0x00000010U,
      LOG_VERBOSE = 0x00000020U,
      LOG_SERIALIZATION = 0x00000100U,
      LOG_MUTEX = 0x00000200U,
      LOG_KEY = 0x00000400U,
      LOG_NETWORK = 0x00000800U,
      LOG_ROUTING = 0x00001000U,
      LOG_MESSAGE = 0x00002000U,
      LOG_SECURE = 0x00004000U,
      LOG_HTTP = 0x00008000U,
      LOG_AAATOKEN = 0x00010000U,
      LOG_MEMORY = 0x00020000U,
      LOG_SYSINFO = 0x00040000U,
      LOG_TREE = 0x00080000U,
      LOG_THREADS = 0x00100000U,
      LOG_MSGPROPERTY = 0x00200000U,
      LOG_JOBS = 0x00400000U,
      LOG_EVENT = 0x00800000U,
      LOG_MISC = 0x01000000U,
      LOG_HANDSHAKE = 0x02000000U,
      LOG_KEYCACHE = 0x04000000U,
      LOG_GLOBAL = 0x80000000U,
   } ;
