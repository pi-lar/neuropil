#include "util/np_serialization.h"

// #include "qcbor/qcbor.h"

void np_tree_serializer_init(np_serialize_buffer_t *buffer,
                             const np_tree_t       *tree);
void np_tree_deserializer_init(np_deserialize_buffer_t *buffer,
                               const void              *bytes,
                               const size_t             buffer_size);

void np_tree_serializer_run(np_state_t                  *context,
                            const np_serialize_buffer_t *buffer);
void np_deserializer_read_map(np_state_t                    *context,
                              const np_deserialize_buffer_t *tree);
