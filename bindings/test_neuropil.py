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
	msg_subject = msg.header.find_str('_np.subj')
	if msg_subject is None:
		print "no subject in header found"
	else:
		print msg_subject.type, msg_subject.size, msg_subject.value, msg_subject.value.s
	# print my_python_data_callback_handle.ping_count + '/' + my_python_data_callback_handle.pong_count

	try:
		if 'pong' == msg_subject.value.s:
			my_python_data_callback_handle.ping_count += 1
			print ("pong message received, sending ping #%d " % (my_python_data_callback_handle.ping_count))
			np.np_send_text('ping', 'ping', my_python_data_callback_handle.ping_count, None);
		elif 'ping' == msg_subject.value.s:
			my_python_data_callback_handle.pong_count += 1
			print ("ping message received, sending pong #%d" % (my_python_data_callback_handle.pong_count))
			np.np_send_text('pong', 'pong', my_python_data_callback_handle.pong_count, None);
		else:
			print "uncrecognized message subject"

	except Exception as e:
		print e

    # return True to acknowldege the message
	return True

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
print ""
print "#### starting a test neuropil node"
print "#"
print "# log file      : ../../neuropil_python_test.log"

np.np_log_init('../../neuropil_python_test.log', np.LOG_ERROR | np.LOG_WARN | np.LOG_INFO)
state = np.np_init('udp4', '4444', None)

print "# node address  : %s " % (state.get_connection_string(), )

state.set_authn_func(my_python_authn_callback)
state.set_authz_func(my_python_authz_callback)


ping_mx_prop = state.get_inout_mx_property('ping')
ping_mx_prop.msg_ttl = 20.0
ping_mx_prop.mep_type = np.ANY_TO_ANY
ping_mx_prop.max_threshold = 20
ping_mx_prop.ack_mode = np.ACK_NONE
state.set_listener('ping', my_python_data_callback_handle)

print '# mx properties for \"%s\"' % (ping_mx_prop.msg_subject,)
print '#   %f msg_ttl / %i max_threshold / %i mep_type / %i ack_mode' % (ping_mx_prop.msg_ttl, ping_mx_prop.max_threshold, ping_mx_prop.mep_type, ping_mx_prop.ack_mode)


pong_mx_prop = state.get_inout_mx_property('pong')
pong_mx_prop.msg_ttl = 20.0
pong_mx_prop.mep_type = np.ANY_TO_ANY
pong_mx_prop.max_threshold = 20
pong_mx_prop.ack_mode = np.ACK_NONE
state.set_listener('pong', my_python_data_callback_handle)

print '# mx properties for \"%s\"' % (pong_mx_prop.msg_subject,)
print "#   %f msg_ttl / %i max_threshold / %i mep_type / %i ack_mode" %(pong_mx_prop.msg_ttl, pong_mx_prop.max_threshold, pong_mx_prop.mep_type, pong_mx_prop.ack_mode)



print "# jobqueue uses : 4 threads"
np.np_start_job_queue(4)

print "#\n# %s\n# %s\n" % (np.NEUROPIL_COPYRIGHT, np.NEUROPIL_TRADEMARK)

np.np_send_join('*:udp4:192.168.178.21:3333')

while(True):
	sleep(6)
	np.np_send_text('pong', 'pong', my_python_data_callback_handle.pong_count, None);
	print "send a pong message"
	sleep(3)
	np.np_send_text('ping', 'ping', my_python_data_callback_handle.ping_count, None);
	print "send a ping message"