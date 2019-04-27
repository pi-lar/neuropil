//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdbool.h>
#include <stdbool.h>
#include <inttypes.h>

#include "np_util.h"
#include "util/np_statemachine.h"


const struct np_util_event_s noop_event = { .type = noop };

const struct np_util_statemachine_result_s ok_result                = { .success = true,  .error_code = NO_ERROR          };
const struct np_util_statemachine_result_s condition_not_met_result = { .success = false, .error_code = CONDITION_NOT_MET };
const struct np_util_statemachine_result_s no_rule_result           = { .success = false, .error_code = NO_RULE           };


bool np_util_statemachine_invoke_auto_transition(np_util_statemachine_t *machine, const np_util_event_t ev)
{
    bool ret = false;
    unsigned int i = 0;

    np_util_statemachine_state_t* current_state = machine->_state_table[machine->_current_state];
    struct np_util_statemachine_transition_s* transition = NULL;

    fprintf(stdout, "cs: %s\n", current_state->_state_name);
    while(i < current_state->_transitions ) {

        fprintf(stdout, "cs: %d.%25s -> %d (%d)\n", machine->_current_state, current_state->_state_name, i, current_state->_transitions);
        transition = current_state->_transition_table + (i*sizeof(struct np_util_statemachine_transition_s));

        if (transition->_active && 
            (
                transition->f_condition == NULL ||
                transition->f_condition(machine, ev)
            )
           )
        {
            ret = true;
            
            bool process_enter_exit_states = (transition->_target_state != current_state->_state_id) ? true : false;
            
            if (process_enter_exit_states) current_state->f_exit(machine, ev);
            
            transition->f_action(machine, ev);
            machine->_current_state = transition->_target_state;

            current_state = machine->_state_table[machine->_current_state];

            fprintf(stdout, "cs: %d.%25s -> %p / %p\n", machine->_current_state, current_state->_state_name,
                    current_state, current_state->f_enter);

            if (process_enter_exit_states) current_state->f_enter(machine, ev);

            break; // exit while early after first successful transition
        }
        i++;
    }
    return ret;
}

bool np_util_statemachine_invoke_auto_transitions(np_util_statemachine_t* machine)
{
    bool result, ret = np_util_statemachine_invoke_auto_transition(machine, noop_event);
    if(ret) {
        do {
            result = np_util_statemachine_invoke_auto_transition(machine, noop_event);
        }
        while(result);
    }
    return ret;
}

struct np_util_statemachine_result_s np_util_statemachine_transition(np_util_statemachine_t* machine, uint8_t target_state)
{
    struct np_util_statemachine_result_s ret = no_rule_result;
    unsigned int i = 0;

    np_util_statemachine_state_t* current_state = machine->_state_table[machine->_current_state];
    struct np_util_statemachine_transition_s* transition = NULL;
    
    while(i < current_state->_transitions) {
        
        fprintf(stdout, "cs: %25s -> %d (%d)\n", current_state->_state_name, i, current_state->_transitions);
        transition = current_state->_transition_table + (i*sizeof(struct np_util_statemachine_transition_s));
        
        fprintf(stdout, " t: %25s -> %p / %p\n", current_state->_state_name, current_state->_transition_table, transition);

        if (!transition->_active)  { i++; continue; }

        if (transition->_target_state == target_state &&
            (transition->f_condition == NULL ||
             transition->f_condition(machine, noop_event)) )
        {
            bool process_enter_exit_states = (transition->_target_state != current_state->_state_id) ? true : false;
            if (process_enter_exit_states) current_state->f_exit(machine, noop_event);

            transition->f_action(machine, noop_event);
            machine->_current_state = transition->_target_state;
            ret = ok_result;

            current_state = machine->_state_table[machine->_current_state];
            if (process_enter_exit_states) current_state->f_enter(machine, noop_event);

            break;

        } else {
            if (transition->_target_state != target_state) { ret = no_rule_result;           i++;   }
            else                                           { ret = condition_not_met_result; break; }
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

    fprintf(stdout, "\n");
    fprintf(stdout, " s: %d.%25s -> %p\n", state._state_id, state._state_name, states);
    
    states[state._state_id] = malloc( state_size);    

    states[state._state_id]->_state_id = state._state_id;
    strncpy(states[state._state_id]->_state_name, state._state_name, 25);
    states[state._state_id]->_transitions = 0;
    states[state._state_id]->_transition_table = NULL;
    states[state._state_id]->f_enter = state.f_enter;
    states[state._state_id]->f_enter = state.f_error;
    states[state._state_id]->f_exit  = state.f_exit;

    fprintf(stdout, " s: %d.%25s -> %p / %p\n", 
            states[state._state_id]->_state_id, states[state._state_id]->_state_name,
            states, states[state._state_id]);
}

void np_util_statemachine_add_transition(np_util_statemachine_state_t** states, uint8_t state, struct np_util_statemachine_transition_s trans)
{
    np_util_statemachine_state_t* st = states[state];
    
    uint8_t count = st->_transitions;
    size_t transition_size = sizeof(struct np_util_statemachine_transition_s);
    size_t transition_offset = count*transition_size;
    
    fprintf(stdout, " t:   %25s -> %p / %d\n", st->_state_name, st->_transition_table, st->_transitions);

    struct np_util_statemachine_transition_s* new_transition = NULL;
    
    new_transition = calloc(count+1, transition_size);
    for (uint8_t m = 0; m < st->_transitions; m++)
        memcpy(new_transition+(m*transition_size), st->_transition_table+(m*transition_size), transition_size);
    memcpy(new_transition, st->_transition_table, transition_offset);
    free(st->_transition_table);
    st->_transition_table = new_transition;

    new_transition = st->_transition_table+transition_offset;
    memcpy(new_transition, &trans, transition_size);

    st->_transitions++;

    for (uint8_t m = 0; m < st->_transitions; m++) {
        transition_offset = m*transition_size;
        fprintf(stdout, " t:   %25s ->   %p\n", st->_state_name, st->_transition_table+transition_offset);
    }
}
