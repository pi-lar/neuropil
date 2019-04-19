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

    uint32_t state_offset = machine->_current_state*sizeof(struct np_util_statemachine_state_s);
    struct np_util_statemachine_state_s* current_state = machine->_state_table+state_offset;
    struct np_util_statemachine_transition_s* transition = NULL;

    fprintf(stdout, "cs: %s\n", current_state->_state_name);
    while(i < current_state->_transitions ) {

        fprintf(stdout, "cs: %s -> %d (%d)\n", current_state->_state_name, i, current_state->_transitions);
        transition = current_state->_transition_table + (i*sizeof(struct np_util_statemachine_transition_s));

        if (!transition->_active)  { i++; continue; }

        if (transition->f_condition == NULL ||
            transition->f_condition(machine, ev) )
        {
            ret = true;
            
            bool process_enter_exit_states = (transition->_target_state != current_state->_state_id) ? true : false;
            if (process_enter_exit_states) current_state->f_exit(machine, ev);
            
            transition->f_action(machine, ev);
            machine->_current_state = transition->_target_state;

            state_offset = machine->_current_state*sizeof(struct np_util_statemachine_state_s);
            current_state = machine->_state_table+state_offset;
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

    uint32_t state_offset = machine->_current_state*sizeof(struct np_util_statemachine_state_s);
    struct np_util_statemachine_state_s* current_state = machine->_state_table+state_offset;
    struct np_util_statemachine_transition_s* transition = NULL;
    
    while(i < current_state->_transitions) {
        
        fprintf(stdout, "cs: %s -> %d (%d)\n", current_state->_state_name, i, current_state->_transitions);
        transition = current_state->_transition_table + (i*sizeof(struct np_util_statemachine_transition_s));

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

            state_offset = machine->_current_state*sizeof(struct np_util_statemachine_state_s);
            current_state = machine->_state_table+state_offset;
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

void np_util_statemachine_add_state(np_util_statemachine_t *machine, struct np_util_statemachine_state_s state)
{
    uint8_t num_states = ++machine->_states;
    uint32_t offset = (num_states-1)*sizeof(struct np_util_statemachine_state_s);

    fprintf(stdout, "s: %d.%s -> %p\n", num_states, state._state_name, machine->_state_table);

    machine->_state_table = realloc(machine->_state_table, num_states*sizeof(struct np_util_statemachine_state_s));

    fprintf(stdout, "s: %d.%s -> %p / %p\n", num_states, state._state_name, machine->_state_table, machine->_state_table+offset);

    memcpy(machine->_state_table+offset, &state, sizeof(struct np_util_statemachine_state_s));
}

void np_util_statemachine_add_transition(np_util_statemachine_t *machine, uint8_t state, struct np_util_statemachine_transition_s trans)
{
    ASSERT(state < machine->_states, "adding transition to unknown state" );

    uint32_t state_offset = state*sizeof(struct np_util_statemachine_state_s);
    struct np_util_statemachine_state_s* st = (struct np_util_statemachine_state_s*) machine->_state_table+state_offset;

    uint8_t count = ++st->_transitions;
    uint32_t offset = (count-1)*sizeof(struct np_util_statemachine_transition_s);

    fprintf(stdout, "t: %s -> %p\n", st->_state_name, st->_transition_table);

    st->_transition_table = realloc(st->_transition_table, count*sizeof(struct np_util_statemachine_transition_s));

    fprintf(stdout, "t: %s -> %p / %p\n", st->_state_name, st->_transition_table, st->_transition_table+offset);

    memcpy(st->_transition_table+offset,
           &trans,
           sizeof(struct np_util_statemachine_transition_s));
}
