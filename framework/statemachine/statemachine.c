//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdbool.h>
#include <stdbool.h>
#include <inttypes.h>
#include "statemachine.h"

#include "np_util.h"

//TODO: Protect statmachine instances with mutex?

const struct np_fwk_statemachine_result_s ok_result = {
    .success = true,
    .error_code = NO_ERROR
};

const struct np_fwk_statemachine_result_s condition_not_met_result = {
    .success = false,
    .error_code = CONDITION_NOT_MET
};
const struct np_fwk_statemachine_result_s no_rule_result = {
    .success = false,
    .error_code = NO_RULE
};
np_fwk_statemachine_t np_fwk_statemachine_init(struct np_fwk_statemachine_config_s config){
    np_fwk_statemachine_t ret = {0};
    ret._config = config;
    ret._current_state = config.start_state;
    return ret;
}
bool np_fwk_statemachine_invoke_auto_transition(np_fwk_statemachine_t* machine){
    bool ret = false;
    unsigned int i = 0;
    while(i < ARRAY_SIZE(machine->_config.rules)){
        struct np_fwk_statemachine_config_rule_s rule = machine->_config.rules[i];
        if(!rule.active) break; // exit while early

        if(rule.source_state == machine->_current_state){                        
            if(rule.condition == NULL || rule.condition(machine, machine->_config.userdata)){
                ret = true;
                machine->_current_state = rule.target_state;
                rule.action(machine, machine->_config.userdata);
                break; // exit while early after first successfull transition
            }
        }
    }    
    return ret;
}
bool np_fwk_statemachine_invoke_auto_transitions(np_fwk_statemachine_t* machine){
    bool result, ret = np_fwk_statemachine_invoke_auto_transition(machine);
    if(ret){
        do{
            result = np_fwk_statemachine_invoke_auto_transition(machine);
        }
        while(result);
    }
    return ret;
}
struct np_fwk_statemachine_result_s np_fwk_statemachine_transition(np_fwk_statemachine_t* machine, unsigned int target_state){
    struct np_fwk_statemachine_result_s ret = no_rule_result;  
    unsigned int i = 0;
    while(i < ARRAY_SIZE(machine->_config.rules)){
        struct np_fwk_statemachine_config_rule_s rule = machine->_config.rules[i];
        if(!rule.active) break; // exit while early

        if(rule.source_state == machine->_current_state && rule.target_state == target_state){            
            if(rule.condition == NULL || rule.condition(machine, machine->_config.userdata)){
                ret = ok_result;
                machine->_current_state = rule.target_state;
                rule.action(machine, machine->_config.userdata);
            }else{
                ret = condition_not_met_result;
            }
        }
    }
    return ret;
}
unsigned int np_fwk_statemachine_get_state(np_fwk_statemachine_t* machine){    
    return machine->_current_state;
}


