from ctypes import c_uint8, c_int8, c_int16

import neuropil as np


def my_python_authn_callback(token):
    print token.issuer
    return True

def my_python_authz_callback(token):
    print token.issuer
    return True

ping_count = 0
pong_count = 0

def my_python_data_callback_handle(msg, properties, body):
    print msg
    msg_subject = msg.find_str(np._NP_MSG_HEADER_SUBJECT).value.s

    print msg_subject
    print properties
    print body

    print body.find_str(np.NP_MSG_BODY_TEXT)
    print properties.find_str(np._NP_MSG_INST_SEQ)

    if msg_subject == "pong":
        np.np_send_text("ping", "ping", ping_count, None);
        ping_count = ping_count + 1
    if msg_subject == "ping":
        np.np_send_text("pong", "pong", pong_count, None);
        pong_count = pong_count + 1

    return True # return true to acknowldege the message

some_value = np.np_treeval( 3 );
int_value = np.np_treeval( 3 );
other_value = np.np_treeval('dies ist ein test;');

print some_value, some_value.type, some_value.size
print int_value, int_value.type, int_value.size
print other_value, other_value.type, other_value.size

print np.none_type

tree = np.np_tree()
tree.insert_str('test1', np.np_treeval(27) )
tree.insert_str('test2', np.np_treeval('zweimal test') )
tree.insert_str('test3', np.np_treeval(0.31415) )
tree.insert_str('test0', np.np_treeval(29) )

some_value = tree.find_str('test3')
print some_value.type, some_value.size, some_value.value, some_value.value.d

some_value = tree.find_str('test2')
print some_value.type, some_value.size, some_value.value, some_value.value.s

some_value = tree.replace_str('test2', np.np_treeval('dreimal test;'))
some_value = tree.find_str('test2')
print some_value.type, some_value.size, some_value.value.s


#
# start an example implementation
#
np.np_log_init('../../neuropil_python_test.log', np.LOG_ERROR | np.LOG_WARN | np.LOG_INFO | np.LOG_DEBUG)
state = np.np_init('udp4', '4444', None)

state.py_set_authenticate_func(my_python_authn_callback)
state.py_set_authorize_func(my_python_authz_callback)

state.py_set_listener('ping', my_python_data_callback_handle)
state.py_set_listener('pong', my_python_data_callback_handle)

np.np_start_job_queue(4)
# np.np_send_join('*:udp4:brandon.in.pi-lar.net:3333')

while(True):
    pass
