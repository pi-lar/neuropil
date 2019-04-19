//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
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

typedef bool (*np_util_statemachine_transition_condition)(np_util_statemachine_t *sm, const np_util_event_t ev);
typedef void (*np_util_statemachine_transition_action)   (np_util_statemachine_t *sm, const np_util_event_t ev);

typedef void (*np_util_statemachine_state_error)(np_util_statemachine_t *sm, const np_util_event_t ev);
typedef void (*np_util_statemachine_state_enter)(np_util_statemachine_t *sm, const np_util_event_t ev);
typedef void (*np_util_statemachine_state_exit)(np_util_statemachine_t *sm, const np_util_event_t ev);


struct np_util_statemachine_transition_s {
    bool _active;
    uint8_t _source_state, _target_state;
    np_util_statemachine_transition_action f_action;
    np_util_statemachine_transition_condition f_condition;
};

struct np_util_statemachine_state_s {
    uint8_t _state_id;
    char    _state_name[25];
    np_util_statemachine_state_error f_error;
    np_util_statemachine_state_enter f_enter;
    np_util_statemachine_state_exit  f_exit;

    uint8_t _transitions;
    struct np_util_statemachine_transition_s *_transition_table;
};

struct np_util_statemachine_s {
    uint8_t _start_state;
    uint8_t _current_state;
    void *_user_data;

    uint8_t _states;
    struct np_util_statemachine_state_s *_state_table;
};

struct np_util_statemachine_result_s {
    bool success;
    uint8_t error_code;
}; 

// np_util_statemachine_t np_util_statemachine_init(struct np_util_statemachine_config_s transitions);

uint8_t np_util_statemachine_get_state(np_util_statemachine_t *machine);

void np_util_statemachine_add_state(np_util_statemachine_t *machine, struct np_util_statemachine_state_s state);
void np_util_statemachine_add_transition(np_util_statemachine_t *machine, uint8_t state, struct np_util_statemachine_transition_s trans);

bool np_util_statemachine_invoke_auto_transition(np_util_statemachine_t *machine, const np_util_event_t event);

/**
 * Calls np_util_statemachine_invoke_auto_transition till no transition is possible anymore
 */
bool np_util_statemachine_invoke_auto_transitions(np_util_statemachine_t *machine);

struct np_util_statemachine_result_s np_util_statemachine_transition(np_util_statemachine_t *machine, uint8_t target_state);


#define NP_UTIL_STATEMACHINE_TRANSITION(MACHINE, SOURCE_STATE, TARGET_STATE, ACTION, CONDITION)           \
    np_util_statemachine_add_transition(MACHINE, SOURCE_STATE, (struct np_util_statemachine_transition_s) \
    { ._active=true, ._source_state=SOURCE_STATE, ._target_state=TARGET_STATE, .f_action=ACTION, .f_condition=CONDITION })

#define NP_UTIL_STATEMACHINE_STATE(MACHINE, STATE, NAME, ERROR_FUNC, ENTER_FUNC, EXIT_FUNC) \
    np_util_statemachine_add_state(MACHINE, (struct np_util_statemachine_state_s)           \
    {                                                                                       \
        ._state_id=STATE, ._state_name=NAME, ._transitions=0,                               \
        .f_error=ERROR_FUNC, .f_enter=ENTER_FUNC, .f_exit=EXIT_FUNC,                        \
        ._transition_table = NULL                                                           \
    })

#define NP_UTIL_STATEMACHINE_INIT(MACHINE, START_STATE, USERDATA)              \
    {      														      \
        MACHINE._start_state = START_STATE; MACHINE._current_state = START_STATE;   \
        MACHINE._user_data   = USERDATA;    MACHINE._states=0;                      \
        MACHINE._state_table = NULL;                                          \
    }

#ifdef __cplusplus
}
#endif

#endif // _NP_UTIL_STATEMACHINE_H_
