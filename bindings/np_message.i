//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") np_message

%{
#include "../include/np_message.h"
%}

%rename(np_message) np_message_s;
%rename(np_message) np_message_t;


%extend np_message_s {
    %ignore obj;
}

%ignore _np_message_setfooter;
%ignore _np_message_add_bodyentry;
%ignore _np_message_add_instruction;
%ignore _np_message_add_property;
%ignore _np_message_del_bodyentry;
%ignore _np_message_del_footerentry;
%ignore _np_message_del_instruction;
%ignore _np_message_del_property;
%ignore _np_message_setfooter;
%ignore _np_message_add_footerentry;

%include "../include/np_message.h"
