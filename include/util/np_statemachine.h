//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef _NP_UTIL_STATEMACHINE_H_
#define _NP_UTIL_STATEMACHINE_H_

#include <stdbool.h>
#include <stdint.h>

#include "util/np_event.h"

#ifdef __cplusplus
extern "C" {
#endif

enum np_util_statemachine_error_codes {
  NO_ERROR = 0,
  CONDITION_NOT_MET,
  NO_RULE,
};

typedef struct np_util_statemachine_s np_util_statemachine_t;

typedef bool (*np_util_statemachine_cond)(np_util_statemachine_t *sm,
                                          const np_util_event_t   ev);
typedef void (*np_util_statemachine_func)(np_util_statemachine_t *sm,
                                          const np_util_event_t   ev);

struct np_util_statemachine_transition_s {
  bool                      _active;
  uint8_t                   _source_state, _target_state;
  np_util_statemachine_func f_action;
  np_util_statemachine_cond f_condition;
};
typedef struct np_utile_statemachine_transition_s
    np_utile_statemachine_transition_t;

struct np_util_statemachine_state_s {
  uint8_t                   _state_id;
  char                      _state_name[25];
  np_util_statemachine_func f_error;
  np_util_statemachine_func f_enter;
  np_util_statemachine_func f_exit;

  uint8_t                                   _transitions;
  struct np_util_statemachine_transition_s *_transition_table;
};
typedef struct np_util_statemachine_state_s np_util_statemachine_state_t;

struct np_util_statemachine_s {
  uint8_t _start_state;
  uint8_t _current_state;

  void *_user_data;
  void *_context;

  np_util_statemachine_state_t **_state_table;
};

struct np_util_statemachine_result_s {
  bool    success;
  uint8_t error_code;
};

// np_util_statemachine_t np_util_statemachine_init(struct
// np_util_statemachine_config_s transitions);

uint8_t np_util_statemachine_get_state(np_util_statemachine_t *machine);

void np_util_statemachine_add_state(np_util_statemachine_state_t      **states,
                                    struct np_util_statemachine_state_s state);
void np_util_statemachine_add_transition(
    np_util_statemachine_state_t           **states,
    uint8_t                                  state,
    struct np_util_statemachine_transition_s trans);

bool np_util_statemachine_invoke_auto_transition(
    np_util_statemachine_t *machine, const np_util_event_t event);

/**
 * Calls np_util_statemachine_invoke_auto_transition till no transition is
 * possible anymore
 */
bool np_util_statemachine_invoke_auto_transitions(
    np_util_statemachine_t *machine);

struct np_util_statemachine_result_s
np_util_statemachine_transition(np_util_statemachine_t *machine,
                                uint8_t                 target_state);

#define NP_UTIL_STATEMACHINE_TRANSITION(MACHINE,                               \
                                        SOURCE_STATE,                          \
                                        TARGET_STATE,                          \
                                        ACTION,                                \
                                        CONDITION)                             \
  np_util_statemachine_add_transition(                                         \
      MACHINE,                                                                 \
      SOURCE_STATE,                                                            \
      (struct np_util_statemachine_transition_s){                              \
          ._active       = true,                                               \
          ._source_state = SOURCE_STATE,                                       \
          ._target_state = TARGET_STATE,                                       \
          .f_action      = ACTION,                                             \
          .f_condition   = CONDITION})

#define NP_UTIL_STATEMACHINE_STATE(MACHINE,                                    \
                                   STATE,                                      \
                                   NAME,                                       \
                                   ERROR_FUNC,                                 \
                                   ENTER_FUNC,                                 \
                                   EXIT_FUNC)                                  \
  np_util_statemachine_add_state(                                              \
      MACHINE,                                                                 \
      (struct np_util_statemachine_state_s){._state_id         = STATE,        \
                                            ._state_name       = NAME,         \
                                            ._transitions      = 0,            \
                                            .f_error           = ERROR_FUNC,   \
                                            .f_enter           = ENTER_FUNC,   \
                                            .f_exit            = EXIT_FUNC,    \
                                            ._transition_table = NULL})

#define NP_UTIL_STATEMACHINE_INIT(MACHINE,                                     \
                                  CONTEXT,                                     \
                                  START_STATE,                                 \
                                  STATE_TABLE,                                 \
                                  USERDATA)                                    \
  {                                                                            \
    MACHINE._start_state   = START_STATE;                                      \
    MACHINE._current_state = START_STATE;                                      \
    MACHINE._user_data     = USERDATA;                                         \
    MACHINE._state_table   = STATE_TABLE;                                      \
    MACHINE._context       = CONTEXT;                                          \
  }

#ifdef __cplusplus
}
#endif

#endif // _NP_UTIL_STATEMACHINE_H_
