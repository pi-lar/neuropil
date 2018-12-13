#!/usr/bin/env python3
import os
import sys
import time
try:
    import neuropil    
except ImportError:
    # Using the build version of neuropil instad of the installed
    from glob import glob
    import platform

    if platform.system() == 'Linux' and ( 'LD_LIBRARY_PATH' not in os.environ or '../../build/lib' not in os.environ['LD_LIBRARY_PATH']):
        os.environ['LD_LIBRARY_PATH'] = '../../build/lib/:$LD_LIBRARY_PATH'
        try:        
            print('Restarting executable to add LD_LIBRARY_PATH')
            os.execl(sys.executable, 'python', __file__, *sys.argv[1:])
        except Exception as exc:
            print( 'Failed re-exec:', exc)
            sys.exit(1)
    
    for dir in glob("./build/lib*/"):
        print("appending %s to path"%dir)
        sys.path.append(dir)
        break
        
    from _neuropil import ffi
    from neuropil import *
    print("Using Build Library")



def my_authn_cb(token):
    print("{type} {token}".format(type="authn", token=ffi.string(token.subject)) )
    return True


def my_authz_cb(token):
    print("{type} {token}".format(type="authz", token=ffi.string(token.subject) ))
    return True

class NeuropilListener(Neuropil):    

    def my_acc_cb(self, token):
        print("{type} {token}".format(type="authz", token=ffi.string(token.subject) ))
        return True

    def test_ping_callback(self, message):
        data=ffi.string(message.data, message.data_length)
        print("{type}: {data}".format(type="ping", data=data) )        
        
        self.send(b'pong', bytes('some data', encoding='utf_8') )    
        return True
    
    def test_pong_callback(self, message):
        data=ffi.string(message.data, message.data_length)
        print("{type}: {data}".format(type="pong", data=data) )                
        self.send(b'ping', b'some data')    
        return True

def main():
    
    np_1 = NeuropilListener()
    np_2 = NeuropilListener()    
    
    # start node as passive (aka behind a stateful firewall)
    status1 = np_1.listen(b'udp4', b'localhost', 4444)
    status2 = np_2.listen(b'udp4', b'localhost', 5555)

    status1 = np_1.set_authenticate_cb(my_authn_cb)
    status1 = np_1.set_authorize_cb(my_authz_cb)
    status1 = np_1.set_accounting_cb(np_1.my_acc_cb)
    status1 = np_1.set_receive_cb(b'ping', np_1.test_ping_callback)
    status1 = np_1.set_receive_cb(b'pong', np_1.test_pong_callback)

    status2 = np_2.set_authenticate_cb(my_authn_cb)
    status2 = np_2.set_authorize_cb(my_authz_cb)
    status2 = np_2.set_accounting_cb(np_2.my_acc_cb)
    status2 = np_2.set_receive_cb(b'ping', np_2.test_ping_callback)
    status2 = np_2.set_receive_cb(b'pong', np_2.test_pong_callback)
    
    # connect to a node in the internet
    #status1 = np_1.join(b'*:udp4:demo.neuropil.io:31418')
    status2 = np_2.join(b'*:udp4:localhost:4444')

    # run the loop for 10 seconds
    print('neuropil start !')
    np_1.send(b'ping', b'some data') 

    t1 = time.time()
    status1 = np_1.run(0.0)
    status2 = np_2.run(0.0)    

    max_runtime = 15 #sec        
    while True:
        time.sleep(0.001)            
        status1 = np_1.get_status()
        status2 = np_2.get_status()            
        if not((time.time() - t1) < max_runtime and status1 == neuropil.np_running and status2 == neuropil.np_running):
            break

    print('neuropil shutdown!')
    np_1.shutdown()
    np_2.shutdown()

if __name__ == "__main__":
    main()