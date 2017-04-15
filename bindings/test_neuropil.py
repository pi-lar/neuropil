
import neuropil as np

def my_python_auth_callback(token):
    print token.issuer
    return True

some_value = np.new_val_sh(3);
other_value = np.new_val_s('dies ist ein test;');

print some_value, some_value.type, some_value.size
print other_value, other_value.type, other_value.size


tree = np.np_tree_s()
tree.insert_str('test1', np.new_val_i(27))
tree.insert_str('test2', np.new_val_s('zweimal test'))
tree.insert_str('test3', np.new_val_d(0.31415) )
tree.insert_str('test0', np.new_val_l(29))

some_value = tree.find_str('test3')
print some_value.type, some_value.size, some_value.value, some_value.value.d

some_value = tree.find_str('test2')
print some_value.type, some_value.size, some_value.value, some_value.value.s

some_value = tree.replace_str('test2', np.new_val_s('dreimal test;'))
some_value = tree.find_str('test2')
print some_value.type, some_value.size, some_value.value.s


np.np_log_init('./test.log', np.LOG_DEBUG)
state = np.np_init('udp4', '3333', np.FALSE)

state.py_set_authenticate_func(my_python_auth_callback)

np.np_start_job_queue(4)

while(True):
    pass
