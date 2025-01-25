enum np_limits {
  NP_SECRET_KEY_BYTES  = 64U,
  NP_SIGNATURE_BYTES   = 64U,
  NP_PUBLIC_KEY_BYTES  = 32U,
  NP_FINGERPRINT_BYTES = 32U,
  NP_UUID_BYTES        = 16U,
  NP_EXTENSION_BYTES   = 10240U,
};
enum np_status {
  np_error = 0,
  np_uninitialized,
  np_running,
  np_stopped,
  np_shutdown,
};
enum np_return {
  np_ok = 0,
  np_unknown_error,
  np_not_implemented,
  np_network_error,
  np_invalid_argument,
  np_invalid_operation,
  np_startup,
};
const char *np_error_str(enum np_return e);
struct version_t {
  uint8_t major;
  uint8_t minor;
  uint8_t patch;
};
typedef void          np_context;
typedef unsigned char np_id[NP_FINGERPRINT_BYTES];
typedef unsigned char np_attributes_t[NP_EXTENSION_BYTES];
typedef unsigned char np_signature_t[NP_SIGNATURE_BYTES];
typedef np_id         np_subject;
void                  np_get_id(np_id(*id), const char *string, size_t length);
enum np_return        np_generate_subject(np_subject(*subject_id),
                                          const char *subject,
                                          size_t      length);
enum np_return        np_regenerate_subject(np_context      *ac,
                                            char            *subject_buffer,
                                            size_t           buffer_length,
                                            const np_subject subject);
struct np_log_entry {
  char  *string;
  size_t string_length;
  double timestamp;
  char   level[20];
};
typedef void (*np_log_write_callback)(np_context         *ac,
                                      struct np_log_entry entry);
struct np_token {
  char          uuid[NP_UUID_BYTES];
  char          subject[255];
  np_id         issuer;
  np_id         realm;
  np_id         audience;
  double        issued_at, not_before, expires_at;
  unsigned char public_key[NP_PUBLIC_KEY_BYTES],
      secret_key[NP_SECRET_KEY_BYTES];
  np_signature_t  signature;
  np_attributes_t attributes;
  np_signature_t  attributes_signature;
};
struct np_message {
  char            uuid[NP_UUID_BYTES];
  np_id           from;
  np_subject      subject;
  double          received_at;
  unsigned char  *data;
  size_t          data_length;
  np_attributes_t attributes;
};
struct np_settings {
  uint32_t              n_threads;
  char                  log_file[256];
  uint32_t              log_level;
  uint8_t               leafset_size;
  np_log_write_callback log_write_fn;
  uint16_t              jobqueue_size;
  uint16_t              max_msgs_per_sec;
};
struct np_settings *np_default_settings(struct np_settings *settings);
np_context         *np_new_context(struct np_settings *settings);
struct np_token
               np_new_identity(np_context *ac,
                               double      expires_at,
                               unsigned char (*secret_key)[NP_SECRET_KEY_BYTES]);
enum np_return np_use_identity(np_context *ac, struct np_token identity);
enum np_return np_use_token(np_context *ac, struct np_token token);
enum np_return
np_sign_identity(np_context *ac, struct np_token *identity, bool self_sign);
enum np_return np_verify_issuer(np_context     *ac,
                                struct np_token identity,
                                struct np_token issuer);
enum np_return np_token_fingerprint(np_context     *ac,
                                    struct np_token identity,
                                    bool            include_attributes,
                                    np_id(*id));
enum np_return np_listen(np_context *ac,
                         const char *protocol,
                         const char *host,
                         uint16_t    port);
enum np_return np_node_fingerprint(np_context *ac, np_id(*id));
enum np_return np_get_address(np_context *ac, char *address, uint32_t max);
enum np_return np_join(np_context *ac, const char *address);
typedef bool (*np_aaa_callback)(np_context *ac, struct np_token *aaa_token);
enum np_return np_set_authenticate_cb(np_context *ac, np_aaa_callback callback);
enum np_return np_set_authorize_cb(np_context *ac, np_aaa_callback callback);
enum np_return np_set_accounting_cb(np_context *ac, np_aaa_callback callback);
enum np_return np_run(np_context *ac, double duration);
enum np_mx_role { NP_MX_PROVIDER, NP_MX_CONSUMER, NP_MX_PROSUMER };
enum np_mx_cache_policy {
  NP_MX_FIFO_REJECT,
  NP_MX_FIFO_PURGE,
  NP_MX_LIFO_REJECT,
  NP_MX_LIFO_PURGE
};
enum np_mx_ackmode { NP_MX_ACK_NONE, NP_MX_ACK_DESTINATION, NP_MX_ACK_CLIENT };
enum np_mx_audience_type {
  NP_MX_AUD_PUBLIC,
  NP_MX_AUD_VIRTUAL,
  NP_MX_AUD_PROTECTED,
  NP_MX_AUD_PRIVATE
};
struct np_mx_properties {
  enum np_mx_role          role;
  enum np_mx_ackmode       ackmode;
  np_subject               reply_id;
  enum np_mx_audience_type audience_type;
  np_id                    audience_id;
  enum np_mx_cache_policy  cache_policy;
  uint16_t                 cache_size;
  uint8_t                  max_parallel, max_retry;
  double                   intent_ttl, intent_update_after;
  double                   message_ttl;
};
struct np_mx_properties np_get_mx_properties(np_context      *ac,
                                             const np_subject id);
enum np_return          np_set_mx_properties(np_context             *ac,
                                             const np_subject        id,
                                             struct np_mx_properties properties);
enum np_return          np_set_mx_authorize_cb(np_context      *ac,
                                               const np_subject id,
                                               np_aaa_callback  callback);
enum np_return np_mx_properties_enable(np_context *ac, const np_subject id);
enum np_return np_mx_properties_disable(np_context *ac, const np_subject id);
enum np_return np_send(np_context          *ac,
                       np_subject           subject,
                       const unsigned char *message,
                       size_t               length);
enum np_return np_send_to(np_context          *ac,
                          np_subject           subject,
                          const unsigned char *message,
                          size_t               length,
                          np_id(*target));
typedef bool (*np_receive_callback)(np_context *ac, struct np_message *message);
enum np_return np_add_receive_cb(np_context         *ac,
                                 np_subject          subject,
                                 np_receive_callback callback);
void           np_set_userdata(np_context *ac, void *userdata);
void          *np_get_userdata(np_context *ac);
bool           np_has_joined(np_context *ac);
enum np_status np_get_status(np_context *ac);
bool           np_has_receiver_for(np_context *ac, np_subject subject);
char          *np_id_str(char str[65], const np_id id);
void           np_str_id(np_id(*id), const char str[65]);
void           np_destroy(np_context *ac, bool gracefully);
typedef void (*np_callback)(np_context *ac);
enum np_return np_add_shutdown_cb(np_context *ac, np_callback callback);
bool           np_id_equals(np_id first, np_id second);
uint32_t       np_get_route_count(np_context *ac);
enum np_data_return {
  np_data_ok       = 0,
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
};
enum np_data_type {
  NP_DATA_TYPE_BIN,
  NP_DATA_TYPE_INT,
  NP_DATA_TYPE_UNSIGNED_INT,
  NP_DATA_TYPE_STR
};
struct np_data_conf {
  char              key[255];
  enum np_data_type type;
  size_t            data_size;
};
typedef union {
  unsigned char *bin;
  int32_t        integer;
  uint32_t       unsigned_integer;
  char          *str;
} np_data_value;
typedef unsigned char np_datablock_t;
enum np_data_return   np_init_datablock(np_datablock_t *block,
                                        uint32_t        block_length);
enum np_data_return   np_set_data(np_datablock_t     *block,
                                  struct np_data_conf data_conf,
                                  np_data_value       data);
enum np_data_return   np_get_data(np_datablock_t      *block,
                                  char                 key[255],
                                  struct np_data_conf *out_data_config,
                                  np_data_value       *out_data);
enum np_data_return   np_get_data_size(np_datablock_t *block,
                                       size_t         *out_block_size);
enum np_data_return   np_merge_data(np_datablock_t *dest, np_datablock_t *src);
typedef bool (*np_iterate_data_cb)(struct np_data_conf *out_data_config,
                                   np_data_value       *out_data,
                                   void                *userdata);
enum np_data_return np_iterate_data(np_datablock_t    *block,
                                    np_iterate_data_cb callback,
                                    void              *userdata);
enum np_msg_attr_type {
  NP_ATTR_NONE = -1,
  NP_ATTR_USER_MSG,
  NP_ATTR_INTENT,
  NP_ATTR_IDENTITY,
  NP_ATTR_IDENTITY_AND_USER_MSG,
  NP_ATTR_INTENT_AND_USER_MSG,
  NP_ATTR_INTENT_AND_IDENTITY,
  NP_ATTR_MAX,
};
enum np_data_return np_set_ident_attr_bin(np_context           *ac,
                                          struct np_token      *ident,
                                          enum np_msg_attr_type inheritance,
                                          char                  key[255],
                                          unsigned char        *bin,
                                          size_t                bin_length);
enum np_data_return np_set_mxp_attr_bin(np_context           *ac,
                                        np_subject            subject,
                                        enum np_msg_attr_type inheritance,
                                        char                  key[255],
                                        unsigned char        *bin,
                                        size_t                bin_length);
enum np_data_return np_get_msg_attr_bin(struct np_message    *msg,
                                        char                  key[255],
                                        struct np_data_conf **out_data_config,
                                        unsigned char       **out_data);
enum np_data_return np_get_token_attr_bin(struct np_token      *ident,
                                          char                  key[255],
                                          struct np_data_conf **out_data_config,
                                          unsigned char       **out_data);
enum np_data_return np_set_mxp_attr_policy_bin(np_context    *ac,
                                               np_subject     subject,
                                               char           key[255],
                                               unsigned char *value,
                                               size_t         value_size);
enum np_log_e {
  LOG_NONE          = 0x000000000U,
  LOG_NOMOD         = 0x000000000U,
  LOG_ERROR         = 0x000000001U,
  LOG_WARNING       = 0x000000002U,
  LOG_INFO          = 0x000000004U,
  LOG_DEBUG         = 0x000000008U,
  LOG_TRACE         = 0x000000010U,
  LOG_VERBOSE       = 0x000000020U,
  LOG_SERIALIZATION = 0x000000100U,
  LOG_MUTEX         = 0x000000200U,
  LOG_KEY           = 0x000000400U,
  LOG_NETWORK       = 0x000000800U,
  LOG_ROUTING       = 0x000001000U,
  LOG_MESSAGE       = 0x000002000U,
  LOG_SECURE        = 0x000004000U,
  LOG_HTTP          = 0x000008000U,
  LOG_AAATOKEN      = 0x000010000U,
  LOG_MEMORY        = 0x000020000U,
  LOG_SYSINFO       = 0x000040000U,
  LOG_TREE          = 0x000080000U,
  LOG_THREADS       = 0x000100000U,
  LOG_MSGPROPERTY   = 0x000200000U,
  LOG_JOBS          = 0x000400000U,
  LOG_EVENT         = 0x000800000U,
  LOG_MISC          = 0x001000000U,
  LOG_HANDSHAKE     = 0x002000000U,
  LOG_KEYCACHE      = 0x004000000U,
  LOG_EXPERIMENT    = 0x008000000U,
  LOG_PHEROMONE     = 0x010000000U,
  LOG_GLOBAL        = 0x800000000U,
};
enum np_search_analytic_mode { SEARCH_ANALYTICS_OFF = 0, SEARCH_ANALYTICS_ON };
enum np_search_minhash_mode {
  SEARCH_MH_FIX256,
  SEARCH_MH_FIX512,
  SEARCH_MH_DD256
};
enum np_search_shingle_mode {
  SEARCH_1_SHINGLE = 1,
  SEARCH_1_IN_2_SHINGLE,
  SEARCH_4_KMER
};
enum np_search_node_type { SEARCH_NODE_SERVER = 1, SEARCH_NODE_CLIENT };
struct np_search_settings {
  np_subject                   search_space;
  bool                         enable_remote_peers;
  char                         bootstrap_node[255];
  enum np_search_node_type     node_type;
  uint8_t                      local_peer_count;
  uint16_t                     local_table_count;
  enum np_search_analytic_mode analytic_mode;
  enum np_search_minhash_mode  minhash_mode;
  enum np_search_shingle_mode  shingle_mode;
  float                        target_similarity;
};
typedef np_id np_index;
struct np_searchentry {
  np_index        search_index;
  struct np_token intent;
};
struct np_searchquery {
  uint8_t               query_id;
  char                  result_uuid[NP_UUID_BYTES];
  float                 similarity;
  struct np_searchentry query_entry;
};
struct np_searchresult {
  uint8_t               hit_counter;
  char                  label[256];
  float                 level;
  struct np_searchentry result_entry;
};
struct np_search_settings *np_default_searchsettings();
void np_searchnode_init(np_context *ac, struct np_search_settings *settings);
void np_searchnode_destroy(np_context *ac);
bool pysearch_entry(np_context            *ac,
                    struct np_searchentry *entry,
                    const char            *text,
                    np_attributes_t        attributes);
bool pysearch_query(np_context            *ac,
                    float                  search_probability,
                    struct np_searchquery *query,
                    const char            *query_text,
                    np_attributes_t        attributes);
bool pysearch_pullresult(np_context            *context,
                         struct np_searchquery *query,
                         struct np_searchresult py_result[],
                         size_t                 elements_to_fetch);
uint32_t pysearch_pullresult_size(np_context            *context,
                                  struct np_searchquery *query);
