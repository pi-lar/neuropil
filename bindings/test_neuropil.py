
import neuropil

def my_python_auth_callback(token):
    print token.issuer
    return True


neuropil.np_log_init('./test.log', neuropil.LOG_DEBUG)
state = neuropil.np_init('udp4', '3333', neuropil.FALSE)

state.py_set_authenticate_func(my_python_auth_callback)

neuropil.np_start_job_queue(4)

while(True):
    pass
