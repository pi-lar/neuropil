//
// neuropil is copyright 2016-2021 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdbool.h>
#include <stdbool.h>
#include <inttypes.h>

#include "np_util.h"
#include "util/np_statemachine.h"


// const struct np_util_event_s noop_event = { .type = evt_noop, .user_data=NULL };

const struct np_util_statemachine_result_s ok_result                = { .success = true,  .error_code = NO_ERROR          };
const struct np_util_statemachine_result_s condition_not_met_result = { .success = false, .error_code = CONDITION_NOT_MET };
const struct np_util_statemachine_result_s no_rule_result           = { .success = false, .error_code = NO_RULE           };


bool np_util_statemachine_invoke_auto_transition(np_util_statemachine_t *machine, const np_util_event_t ev)
{
    bool ret = false;
    unsigned int i = 0;

    np_util_statemachine_state_t* current_state = machine->_state_table[machine->_current_state];
    uint16_t old_state = machine->_current_state;

    struct np_util_statemachine_transition_s transition = {0};

    // fprintf(stdout, "cs: %s\n", current_state->_state_name);
    while(i < current_state->_transitions ) {

        transition = current_state->_transition_table[i];

        // fprintf(stdout, " t:   %25s ->   %p / %d -> %d (c: %p / a: %p)\n", 
        //         current_state->_state_name, transition, transition->_source_state, transition->_target_state,
        //         transition->f_condition, transition->f_action);

        if (transition._active && 
            (
                transition.f_condition == NULL || transition.f_condition(machine, ev)
            )
           )
        {
            // fprintf(stdout, "cs: %d.%25s -> transition: %d\n", machine->_current_state, current_state->_state_name, i);
            ret = true;
            
            // first call the action
            transition.f_action(machine, ev);

            bool process_enter_exit_states = (transition._target_state != current_state->_state_id) ? true : false;
            if (process_enter_exit_states) current_state->f_exit(machine, ev);

            if (machine->_current_state == old_state)
            {   // prevent state reset in case of follow up transitions
                machine->_current_state = transition._target_state;            
                current_state = machine->_state_table[machine->_current_state];
            }
            // fprintf(stdout, "cs: %d.%25s -> %p / %p\n", 
            //                 machine->_current_state, current_state->_state_name, current_state, current_state->f_enter);
            if (process_enter_exit_states) current_state->f_enter(machine, ev);
            break; // exit while early after first successful transition

        } else {
            // log_debug(LOG_DEBUG, "cs: %d.%25s -> transition: %d -> not met\n", machine->_current_state, current_state->_state_name, i);
        }
        i++;
    }
    return ret;
}

bool np_util_statemachine_invoke_auto_transitions(np_util_statemachine_t* machine)
{
    bool result = false;
    np_util_event_t noop_event = { .type = evt_noop, .user_data=NULL };
    bool ret = np_util_statemachine_invoke_auto_transition(machine, noop_event);

    // if(ret) {
    // do {
    //      result = _np_util_statemachine_invoke_auto_transition(machine, noop_event);
    // }
    // while(result);
    // }
    return ret;
}

struct np_util_statemachine_result_s np_util_statemachine_transition(np_util_statemachine_t* machine, uint8_t target_state)
{
    struct np_util_statemachine_result_s ret = no_rule_result;
    unsigned int i = 0;

    np_util_statemachine_state_t* current_state = machine->_state_table[machine->_current_state];
    struct np_util_statemachine_transition_s transition = {0};
    
    while(i < current_state->_transitions) {
        
        // fprintf(stdout, "cs: %25s -> %d (%d)\n", current_state->_state_name, i, current_state->_transitions);
        transition = current_state->_transition_table[i]; // + (i*sizeof(struct np_util_statemachine_transition_s));
        
        // fprintf(stdout, " t: %25s -> %p / %p\n", current_state->_state_name, current_state->_transition_table, transition);

        if (!transition._active)  { i++; continue; }

        np_util_event_t noop_event = { .type = evt_noop, .user_data=NULL };

        if (transition._target_state == target_state &&
            (transition.f_condition == NULL ||
             transition.f_condition(machine, noop_event)) )
        {
            // first call the action
            transition.f_action(machine, noop_event);

            fprintf(stdout, "cs: %25s -> transition: %d\n", current_state->_state_name, i);
            bool process_enter_exit_states = (transition._target_state != current_state->_state_id) ? true : false;
            if (process_enter_exit_states) current_state->f_exit(machine, noop_event);

            machine->_current_state = transition._target_state;
            current_state = machine->_state_table[machine->_current_state];
            fprintf(stdout, "cs: %d.%25s -> %p / %p\n", machine->_current_state, current_state->_state_name,
                             current_state, current_state->f_enter);
            if (process_enter_exit_states) current_state->f_enter(machine, noop_event);

            ret = ok_result;

            break;

        } else {
            if (transition._target_state != target_state) { ret = no_rule_result;           i++;   }
            else                                          { ret = condition_not_met_result; break; }
        }
        
    }
    return ret;
}

uint8_t np_util_statemachine_get_state(np_util_statemachine_t* machine) {
    return machine->_current_state;
}

void np_util_statemachine_add_state(np_util_statemachine_state_t** states, struct np_util_statemachine_state_s state)
{
    size_t state_size = sizeof(struct np_util_statemachine_state_s);

    // fprintf(stdout, "\n");
    // fprintf(stdout, " s: %d.%25s -> %p\n", state._state_id, state._state_name, states);
    
    states[state._state_id] = malloc(state_size);

    states[state._state_id]->_state_id = state._state_id;
    strncpy(states[state._state_id]->_state_name, state._state_name, 25);

    states[state._state_id]->_transitions = 0;
    states[state._state_id]->_transition_table = NULL;

    states[state._state_id]->f_enter = state.f_enter;
    states[state._state_id]->f_exit  = state.f_exit;
    states[state._state_id]->f_error = state.f_error;    

    /*
    fprintf(stdout, " s: %d.%25s -> %p / %p\n", 
            states[state._state_id]->_state_id, states[state._state_id]->_state_name,
            states, states[state._state_id] );
    */
}

void np_util_statemachine_add_transition(np_util_statemachine_state_t** states, uint8_t state, struct np_util_statemachine_transition_s trans)
{
    np_util_statemachine_state_t* st = states[state];
    
    uint8_t count = st->_transitions;
    size_t transition_size = sizeof(struct np_util_statemachine_transition_s);
    
    // fprintf(stdout, " t:   %25s -> %p / %d\n", st->_state_name, st->_transition_table, trans._target_state);
    struct np_util_statemachine_transition_s* old = st->_transition_table;
    st->_transition_table = calloc(count+1, transition_size);
    for (uint8_t i = 0; i < count; i++) st->_transition_table[i] = old[i];
    free(old);

    struct np_util_statemachine_transition_s* iter = &st->_transition_table[count];

    iter->f_action = trans.f_action;
    iter->f_condition = trans.f_condition;
    iter->_active = trans._active;
    iter->_source_state = trans._source_state;
    iter->_target_state = trans._target_state;
    // memcpy(st->_transition_table+transition_offset, &trans, transition_size);

    st->_transitions++;
    // st->_transition_table = &temp;

/*
    fprintf(stdout, " t:   %25s ->   %p / %d -> %d (c: %p / a: %p)\n", 
            st->_state_name, transition, transition->_source_state, transition->_target_state,
            transition->f_condition, transition->f_action);

    for (uint8_t m = 0; m < st->_transitions; m++) {
        transition_offset = m*transition_size;
        struct np_util_statemachine_transition_s* transition = st->_transition_table+transition_offset;
        fprintf(stdout, " t:   %25s ->   %p / %d -> %d\n", st->_state_name, transition, transition->_source_state, transition->_target_state);
    }
*/
}
