#!/usr/bin/env python3
import os
import sys
import time
try:
    import Neuropil    
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
        
    from _neuropil import lib, ffi
    from neuropil_obj import Neuropil



@ffi.callback("bool(np_context* context, struct np_token*)")
def my_authn_cb(context, token):
    print("{type} {token}".format(type="authn", token=ffi.string(token.subject)) )
    return True

@ffi.callback("bool(np_context* context, struct np_token*)")
def my_authz_cb(context, token):
    print("{type} {token}".format(type="authz", token=ffi.string(token.subject) ))
    return True

class NeuropilListener(Neuropil):
    def __init__(self):
        super().__init__()        
        ffi_handle = ffi.new_handle(self)
        self.set_userdata(ffi_handle)

    @ffi.callback("bool(np_context* context, struct np_message*)")
    def test_ping_callback(context, message):
        data=ffi.string(message.data, message.data_length)
        print("{type}: {data}".format(type="ping", data=data) )
        
        np_x = ffi.from_handle(lib.np_get_userdata(context))
        np_x.send(b'ping', bytes('some data', encoding='utf_8') ) 
    
        return True


def main():

    np_1 = NeuropilListener()
    np_2 = NeuropilListener()    

    # start node as passive (aka behind a stateful firewall)
    status1 = np_1.listen(b'udp4', b'localhost', 4444)
    if status1 is not lib.np_ok:
        print("{error} {errorcode}".format(error="listen (1)", errorcode=status1) )

    status2 = np_2.listen(b'udp4', b'localhost', 5555)
    if status2 is not lib.np_ok:
        print("{error} {errorcode}".format(error="listen (2)", errorcode=status2) )

    status1 = np_1.set_authn_cb(my_authn_cb)
    status1 = np_1.set_authz_cb(my_authz_cb)
    status1 = np_1.set_receive_cb(b'ping', np_1.test_ping_callback)
    if status1 is not lib.np_ok:
        print("{error} {errorcode}".format(error="receiv (1)", errorcode=status1) )

    status2 = np_2.set_authn_cb(my_authn_cb)
    status2 = np_2.set_authz_cb(my_authz_cb)
    status2 = np_2.set_receive_cb(b'ping', np_2.test_ping_callback)
    if status2 is not lib.np_ok:
        print("{error} {errorcode}".format(error="receiv (2)", errorcode=status2) )
    
    # connect to a node in the internet
    status1 = np_1.join(b'*:udp4:localhost:3333')
    status2 = np_2.join(b'*:udp4:localhost:3333')

    # run the loop for 10 seconds
    print('neuropil start !')
    np_1.send(b'ping', bytes('some data', encoding='utf_8') ) 

    while status1 is lib.np_ok and status2 is lib.np_ok:
        status1 = np_1.run(0.0)
        status2 = np_2.run(0.0)        
        time.sleep(0.001)


    print('neuropil end !')    


if __name__ == "__main__":
    main()