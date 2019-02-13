#include <stdbool.h>
#include <inttypes.h>

#include <criterion/criterion.h>

#include "statemachine/statemachine.h"

TestSuite(np_fwk_statemachine_t);

enum NP_TEST_STATEMACHINE_STATES{
    IDLE,
    RUNNING,
    INVALID
};
int job = 0;

void action(np_fwk_statemachine_t* statemachine, unsigned char* userdata){

}

bool has_job(np_fwk_statemachine_t* statemachine, unsigned char* userdata){
 return job > 0;
}
bool invalid_condition(np_fwk_statemachine_t* statemachine, unsigned char* userdata){
 return false;
}

Test(np_fwk_statemachine_t, _np_fwk_statemachine_t, .description = "test the statemachine implementation"){
  
    np_fwk_statemachine_t sm = NP_FWK_STATEMACHINE_INIT(IDLE, NULL,
        NP_FWK_STATEMACHINE_RULE(IDLE,    RUNNING, action, has_job),
        NP_FWK_STATEMACHINE_RULE(IDLE,    INVALID, action, invalid_condition),
        NP_FWK_STATEMACHINE_RULE(RUNNING, IDLE,    action, NULL),
    );

    struct np_fwk_statemachine_result_s result;
    bool auto_transition_result;
    
    cr_assert(np_fwk_statemachine_get_state(&sm) == IDLE, "State of sm needs to be IDLE");
    job = 1;
    auto_transition_result = np_fwk_statemachine_invoke_auto_transitions(&sm); // IDLE -> RUNNING (ok as condition is met)
    cr_assert(auto_transition_result == true ,"Do transition as condition is met");
    cr_assert(np_fwk_statemachine_get_state(&sm) == RUNNING,"State of sm needs to be RUNNING");
    job = 0;
    auto_transition_result = np_fwk_statemachine_invoke_auto_transitions(&sm); // Nothing
    cr_assert(auto_transition_result == false ,"Do nothing as no condition is set");
    cr_assert(np_fwk_statemachine_get_state(&sm) == RUNNING,"State of sm needs to be RUNNING");

    result = np_fwk_statemachine_transition(&sm, IDLE); // RUNNING -> IDLE (ok, as per rule)
    cr_assert(result.success == true,"Success attribute has to be true not %"PRIu8,result.success);
    cr_assert(result.error_code == NO_ERROR,"Errorcode attribute has to be NO_ERROR not %"PRIu16, result.error_code);

    result = np_fwk_statemachine_transition(&sm, IDLE); // IDLE -> IDLE (nok, no rule set)
    cr_assert(result.success ==  false,"Success attribute has to be false not %"PRIu8,result.success);
    cr_assert(result.error_code == NO_RULE,"Errorcode attribute has to be NO_RULE not %"PRIu16, result.error_code);
    
    result = np_fwk_statemachine_transition(&sm, INVALID); // IDLE -> INVALID (nok, rule condition not ok)
    cr_assert(result.success ==  false,"Success attribute has to be false not %"PRIu8,result.success);
    cr_assert(result.error_code == CONDITION_NOT_MET,"Errorcode attribute has to be CONDITION_NOT_MET not %"PRIu16, result.error_code);   
}