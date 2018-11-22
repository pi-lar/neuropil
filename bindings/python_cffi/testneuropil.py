import sys
import time

sys.path.append('./build/lib.macosx-10.11-x86_64-3.6')

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
    
    @ffi.callback("bool(np_context* context, struct np_message*)")
    def test_ping_callback(context, message):
        data=ffi.string(message.data, message.data_length)
        print("{type}: {data}".format(type="ping", data=data) )
        
        np_x = ffi.from_handle(lib.np_get_userdata(context))
        np_x.send(b'ping', bytes('some data', encoding='utf_8') ) 
    
        return True


def main():

    np_1 = NeuropilListener()
    np_1_ud = ffi.new_handle(np_1)
    np_1.set_userdata(np_1_ud)

    np_2 = NeuropilListener()
    np_2_ud = ffi.new_handle(np_2)
    np_2.set_userdata(np_2_ud)

    # start node as passive (aka behind a stateful firewall)
    status = np_1.listen(b'udp4', b'localhost', 4444)
    if status is not lib.np_ok:
        print("{error} {errorcode}".format(error="listen (1)", errorcode=status) )

    status = np_2.listen(b'udp4', b'localhost', 5555)
    if status is not lib.np_ok:
        print("{error} {errorcode}".format(error="listen (2)", errorcode=status) )

    status = np_1.set_authn_cb(my_authn_cb)
    status = np_1.set_authz_cb(my_authz_cb)
    status = np_1.set_receive_cb(b'ping', np_1.test_ping_callback)
    if status is not lib.np_ok:
        print("{error} {errorcode}".format(error="receiv (1)", errorcode=status) )

    status = np_2.set_authn_cb(my_authn_cb)
    status = np_2.set_authz_cb(my_authz_cb)
    status = np_2.set_receive_cb(b'ping', np_2.test_ping_callback)
    if status is not lib.np_ok:
        print("{error} {errorcode}".format(error="receiv (2)", errorcode=status) )
    
    # connect to a node in the internet
    status = np_1.join(b'*:udp4:localhost:3333')
    status = np_2.join(b'*:udp4:localhost:3333')

    # run the loop for 10 seconds
    print('neuropil start !')
    np_1.send(b'ping', bytes('some data', encoding='utf_8') ) 

    while status is lib.np_ok:
        status = np_2.run(0.0)
        status = np_1.run(0.0)
        time.sleep(0.001)

    print('neuropil end !')    


if __name__ == "__main__":
    main()