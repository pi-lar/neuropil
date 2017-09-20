from ctypes import c_uint8, c_int8, c_int16

from time import sleep
import neuropil as np

def my_python_authn_callback(token):
    print "authn: r:" + token.realm + " i: " + token.issuer + " s:" + token.subject
    return True

def my_python_authz_callback(token):
    print "authz: r:" + token.realm + " i: " + token.issuer + " s:" + token.subject
    return True


def my_python_data_callback_handle(msg, properties, body):

    print "message"
    print msg

    print "header"
    print msg.header

    print "properties"
    print properties

    print "body"
    print msg.body
    print body

    msg_subject = msg.header.find_str("_np.subj")

    if msg_subject is None:
        print "no subject in header found"
    else:
        print msg_subject.type, msg_subject.size, msg_subject.value, msg_subject.value.s

    print my_python_data_callback_handle.ping_count
    print my_python_data_callback_handle.pong_count

    try:
        if "pong" == msg_subject.value.s:
            my_python_data_callback_handle.ping_count += 1
            print ("pong message received, sending ping #%d " % (my_python_data_callback_handle.ping_count))
            np.np_send_text("ping", "ping", 1, None);
        else:
            print "not a pong message"

        if 'ping' == msg_subject.value.s:
            my_python_data_callback_handle.pong_count += 1
            print ("ping message received, sending pong #%d" % (my_python_data_callback_handle.pong_count))
            np.np_send_text("pong", "pong", 1, None);
        else:
            print "not a ping message"

    except Exception as e:
         print e

    return True

    # return True to acknowldege the message
my_python_data_callback_handle.ping_count = 0
my_python_data_callback_handle.pong_count = 0

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
print some_value.type, some_value.size, some_value.value, some_value.value.f
print some_value.type, some_value.size, some_value.value, some_value.value.f
print some_value.type, some_value.size, some_value.value, some_value.value.f

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

state.set_authn_func(my_python_authn_callback)
state.set_authz_func(my_python_authz_callback)

state.set_listener('ping', my_python_data_callback_handle)
state.set_listener('pong', my_python_data_callback_handle)

np.np_start_job_queue(4)

# np.np_send_join('*:udp4:brandon.in.pi-lar.net:3333')
# np.np_set_mx_property("pong", "", np_treeval_t value);


while(True):
    sleep(5)
    np.np_send_text("pong", "pong", 1, None);
    sleep(5)
    np.np_send_text("ping", "ping", 1, None);
