//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_FWK_STATEMACHINE_H_
#define _NP_FWK_STATEMACHINE_H_
#include <stdbool.h>
#include <stdbool.h>

enum np_fwk_statemachine_error_codes{
    NO_ERROR,
    CONDITION_NOT_MET,
    NO_RULE,
}; 
typedef struct np_fwk_statemachine_s np_fwk_statemachine_t;

typedef bool (*np_fwk_statemachine_config_rule_condition)(np_fwk_statemachine_t* statemachine, unsigned char* userdata);
typedef void (*np_fwk_statemachine_config_rule_action)(np_fwk_statemachine_t* statemachine, unsigned char* userdata);

struct np_fwk_statemachine_config_rule_s{
    bool active;
    unsigned int source_state, target_state; 
    np_fwk_statemachine_config_rule_action action;
    np_fwk_statemachine_config_rule_condition condition;

};
struct np_fwk_statemachine_config_s{
     unsigned int start_state;
    struct np_fwk_statemachine_config_rule_s rules[200];
    unsigned char* userdata;
};
struct np_fwk_statemachine_s{
    struct np_fwk_statemachine_config_s _config;
    unsigned int _current_state;
};

struct np_fwk_statemachine_result_s{
    bool success;
    int error_code;
}; 

np_fwk_statemachine_t np_fwk_statemachine_init(struct np_fwk_statemachine_config_s config);
unsigned int np_fwk_statemachine_get_state(np_fwk_statemachine_t* machine);

bool np_fwk_statemachine_invoke_auto_transition(np_fwk_statemachine_t* machine);
/**
 * Calls np_fwk_statemachine_invoke_auto_transition till no transition is possible anymore
 */
bool np_fwk_statemachine_invoke_auto_transitions(np_fwk_statemachine_t* machine);
struct np_fwk_statemachine_result_s np_fwk_statemachine_transition(np_fwk_statemachine_t* machine, unsigned int target_state);


#define NP_FWK_STATEMACHINE_RULE(SOURCE_STATE, TARGET_STATE, ACTION, CONDITION) {.active=true, .source_state=SOURCE_STATE,    .target_state=TARGET_STATE, .action=ACTION, .condition=CONDITION}
#define NP_FWK_STATEMACHINE_INIT(START_STATE, USERDATA, /*RULES*/...)     \
    np_fwk_statemachine_init((struct np_fwk_statemachine_config_s){       \
        .start_state=START_STATE,                                         \
        .userdata=USERDATA,                                               \
        .rules = { __VA_ARGS__ },                                         \
    });

#endif // _NP_FWK_STATEMACHINE_H_