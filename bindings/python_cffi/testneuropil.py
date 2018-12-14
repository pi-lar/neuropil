#!/usr/bin/env python3
import os
import sys
import time   

try:
    from neuropil import NeuropilNode, NeuropilCluster, neuropil
except ImportError:
    # Using the build version of neuropil instad of the installed
    from glob import glob
    import platform   

    path_root = os.path.dirname(__file__) # relative directory path
    if platform.system() == 'Linux':
        path_lib = os.path.join(path_root, '..','..','build','lib')        
        if 'LD_LIBRARY_PATH' not in os.environ or path_lib not in os.environ['LD_LIBRARY_PATH']:
            os.environ['LD_LIBRARY_PATH'] = f'{path_lib}:$LD_LIBRARY_PATH'
            try:        
                print('Restarting executable to add LD_LIBRARY_PATH')
                os.execl(sys.executable, 'python', __file__, *sys.argv[1:])
            except Exception as exc:
                print( 'Failed re-exec:', exc)
                sys.exit(1)
    
    for dir in glob(os.path.join(path_root,"build","lib*")):
        print("appending %s to path"%dir)
        sys.path.append(dir)
        break
            
    from neuropil import NeuropilNode, NeuropilCluster, neuropil
    print("Using Build Library")

def my_authn_cb(token):    
    print("{type} {token}".format(type="authn", token=token.subject))
    return True

def my_authz_cb(token):
    print("{type} {token}".format(type="authz", token=token.subject))
    return True

class NeuropilListener(NeuropilNode):    
    def __init(self, port, host = b'localhost', proto= b'udp4', auto_run=True, **settings):
        super().__init__(port, host, proto, auto_run, True, **settings)
        self.set_authenticate_cb(my_authn_cb)
        self.set_authorize_cb(my_authz_cb)
        self.set_accounting_cb(self.my_acc_cb)
        self.set_receive_cb(b'tick', self.test_tick_callback)
        self.set_receive_cb(b'tock', self.test_tock_callback)
    
    def my_acc_cb(self, token):
        print("{type} {token}".format(type="authz", token=token.subject))
        return True

    def test_tick_callback(self, message):        
        print("{type}: {data}".format(type="tick", data=message.raw()))
        self.send('tock', bytes('tock data (bytes)', encoding='utf_8'))
        return True
    
    def test_tock_callback(self, message):
        print("{type}: {data}".format(type="tock", data=message.raw()))
        self.send('tick', b'tick data (str)')
        return True

def main():    
    
    max_runtime = 10 #sec        

    np_1 = NeuropilListener(4444, host="192.168.30.151", no_threads=3)
    np_2 = NeuropilListener(5555,host="192.168.30.151")
    np_c = NeuropilCluster(3,port_range=4000, host="192.168.30.151")

    # connect to a node in the internet
    #internet = '*:udp4:demo.neuropil.io:31418'
    #internet = '*:udp4:192.168.30.151:3000'
    #print(f"Node 1 connects to the internet (aka: {internet})")
    #np_1.join(internet)

    np1_addr = np_1.get_address()
    print(f"Others nodes connect to node 1 (aka: {np1_addr})")
    np_2.join(np1_addr)
    np_c.join(np1_addr)

    t1 = time.time()    
    np_1.send('tick', b'some data') 
    while True:
        status = [np_1.get_status(),np_2.get_status()] + [ s for n, s in np_c.get_status()] 

        if not((time.time() - t1) < max_runtime and all([s == neuropil.np_running for s in status])):
            break
                
        if int(time.time() - t1) % 5 == 0:            
            np_1.send('tick', b'some data') 

    print('neuropil shutdown!')
    np_1.shutdown()
    np_2.shutdown()
    np_c.shutdown()

if __name__ == "__main__":
    main()