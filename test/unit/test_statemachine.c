#include <stdbool.h>
#include <inttypes.h>

#include <criterion/criterion.h>

#include "util/np_event.h"
#include "util/np_statemachine.h"


TestSuite(np_util_statemachine_t);

enum NP_TEST_STATEMACHINE_STATES{
    IDLE,
    RUNNING,
    INVALID,
    MAX_STATES
};

int job = 0;

void _noop_state_action(np_util_statemachine_t* statemachine, const np_util_event_t event) {
    // empty by design
}

void action(np_util_statemachine_t* statemachine, const np_util_event_t event) {
    
}

bool has_job(np_util_statemachine_t* statemachine, const np_util_event_t event) {
    return (job > 0);
}

bool invalid_condition(np_util_statemachine_t* statemachine, const np_util_event_t event) {
    return false;
}

Test(np_util_statemachine_t, np_util_statemachine_t, .description = "test the statemachine implementation") {
    
    np_util_statemachine_t sm;

    np_util_statemachine_state_t* states[MAX_STATES];

    NP_UTIL_STATEMACHINE_STATE(states, IDLE, "idle", _noop_state_action, _noop_state_action, _noop_state_action);
        NP_UTIL_STATEMACHINE_TRANSITION(states, IDLE,    RUNNING, action, has_job);
        NP_UTIL_STATEMACHINE_TRANSITION(states, IDLE,    INVALID, action, invalid_condition);

    NP_UTIL_STATEMACHINE_STATE(states, RUNNING, "running", _noop_state_action, _noop_state_action, _noop_state_action);
        NP_UTIL_STATEMACHINE_TRANSITION(states, RUNNING, IDLE,    action, NULL);

    NP_UTIL_STATEMACHINE_STATE(states, INVALID, "invalid", _noop_state_action, _noop_state_action, _noop_state_action);

    NP_UTIL_STATEMACHINE_INIT(sm, IDLE, states, NULL);

    struct np_util_statemachine_result_s result;
    bool auto_transition_result;
    np_util_event_t ev = { .type=internal };

    cr_assert(np_util_statemachine_get_state(&sm) == IDLE, "State of sm needs to be IDLE");
    job = 1;
    
    auto_transition_result = np_util_statemachine_invoke_auto_transition(&sm, ev); // IDLE -> RUNNING (ok as condition is met)
    cr_assert(auto_transition_result == true ,"Do transition as condition is met");
    cr_assert(np_util_statemachine_get_state(&sm) == RUNNING,"State of sm needs to be RUNNING");
    job = 0;
    
    auto_transition_result = np_util_statemachine_invoke_auto_transitions(&sm); // Nothing
    cr_assert(auto_transition_result == true ,"Do nothing as no condition is set");
    cr_assert(np_util_statemachine_get_state(&sm) == IDLE,"State of sm needs to be RUNNING");
    
    result = np_util_statemachine_transition(&sm, RUNNING); // IDLE -> RUNNING (not ok, as per rule)
    cr_assert(result.success == false,"Success attribute has to be true not %"PRIu8,result.success);
    cr_assert(result.error_code == CONDITION_NOT_MET,"Errorcode attribute has to be CONDITION_NOT_MET not %"PRIu16, result.error_code);
    
    result = np_util_statemachine_transition(&sm, IDLE); // IDLE -> IDLE (nok, no rule set)
    cr_assert(result.success ==  false,"Success attribute has to be false not %"PRIu8,result.success);
    cr_assert(result.error_code == NO_RULE,"Errorcode attribute has to be NO_RULE not %"PRIu16, result.error_code);
    
    result = np_util_statemachine_transition(&sm, INVALID); // IDLE -> INVALID (nok, rule condition not ok)
    cr_assert(result.success ==  false,"Success attribute has to be false not %"PRIu8,result.success);
    cr_assert(result.error_code == CONDITION_NOT_MET,"Errorcode attribute has to be CONDITION_NOT_MET not %"PRIu16, result.error_code);
}

enum NP_TEST_STATEMACHINE_TOKEN_STATES{
    INITIAL = 0,
    PRIVATE_IDENTITY,
    PUBLIC_IDENTITY,
    PUBLIC_IDENTITY_AUTHENTICATED,
    MESSAGE_IDENTITY,
    IDENTITY_INVALID,
    INVALID_IDENTITY,
    MAX_TOKEN_STATES
};

Test(np_util_statemachine_t, _np_util_statemachine_token, .description = "test the token statemachine implementation"){
    
    CTX() {
        
    np_aaatoken_t *aaatoken;
    np_new_obj(np_aaatoken_t, aaatoken);

    np_util_statemachine_t sm;
    np_util_statemachine_state_t* states[MAX_TOKEN_STATES];    
    
    NP_UTIL_STATEMACHINE_STATE(states, INITIAL, "INITIAL", _noop_state_action, _noop_state_action, _noop_state_action);
        // NP_UTIL_STATEMACHINE_TRANSITION(states, INITIAL,          PRIVATE_IDENTITY, action, _np_private_key_available);
        // NP_UTIL_STATEMACHINE_TRANSITION(states, INITIAL,          PUBLIC_IDENTITY,  action, _np_aaatoken_is_valid);
        // NP_UTIL_STATEMACHINE_TRANSITION(states, INITIAL,          MESSAGE_IDENTITY, action, _np_is_discovery_message);
    
    NP_UTIL_STATEMACHINE_STATE(states, PRIVATE_IDENTITY, "PRIVATE", _noop_state_action, _noop_state_action, _noop_state_action);
        // NP_UTIL_STATEMACHINE_TRANSITION(states, PRIVATE_IDENTITY, IDENTITY_INVALID, action, _np_aaatoken_is_valid);

    NP_UTIL_STATEMACHINE_STATE(states, PUBLIC_IDENTITY, "PUBLIC", _noop_state_action, _noop_state_action, _noop_state_action);
        // NP_UTIL_STATEMACHINE_TRANSITION(states, PUBLIC_IDENTITY,  IDENTITY_INVALID, action, _np_aaatoken_is_valid);
        // NP_UTIL_STATEMACHINE_TRANSITION(states, PUBLIC_IDENTITY,  PUBLIC_IDENTITY_AUTHENTICATED, action, _is_authenticated);
    
    NP_UTIL_STATEMACHINE_STATE(states, PUBLIC_IDENTITY_AUTHENTICATED, "PUBLIC_AUTHENTICATED", _noop_state_action, _noop_state_action, _noop_state_action);
        // NP_UTIL_STATEMACHINE_TRANSITION(states, PUBLIC_IDENTITY_AUTHENTICATED, PUBLIC_IDENTITY,  action, _is_not_authenticated);
        // NP_UTIL_STATEMACHINE_TRANSITION(states, PUBLIC_IDENTITY_AUTHENTICATED, IDENTITY_INVALID, action, _token_is_not_valid);

    NP_UTIL_STATEMACHINE_STATE(states, IDENTITY_INVALID, "INVALID", _noop_state_action, _noop_state_action, _noop_state_action);
        // NP_UTIL_STATEMACHINE_TRANSITION(states, IDENTITY_INVALID, INITIAL,          action, NULL);

    NP_UTIL_STATEMACHINE_INIT(sm, INITIAL, states, aaatoken);

    np_util_event_t ev = { .type=noop };
    np_util_statemachine_invoke_auto_transition(&sm, ev);

    ev = (struct np_util_event_s) { .type=token };
    np_util_statemachine_invoke_auto_transition(&sm, ev);
    }
};
