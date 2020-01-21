import unittest
import time  
from neuropil import NeuropilNode, NeuropilCluster, neuropil, np_token, np_message

class SmokeTests(unittest.TestCase):

    def setUp(self):
        pass
    def tearDown(self):
        pass

    @staticmethod
    def authn_allow_all(node:NeuropilNode, token:np_token):    
        #print("{node}: {type}: {token} {id}".format(node=node.get_fingerprint(), type="authn", token=token.subject, id=token.get_fingerprint()))
        return True

    @staticmethod
    def authz_allow_all(node:NeuropilNode,token:np_token):
        #print("{node}: {type}: {token} {id}".format(node=node.get_fingerprint(),type="authz", token=token.subject, id=token.get_fingerprint()))
        return True

    @staticmethod
    def acc_allow_all(node:NeuropilNode, token:np_token):
        #print("{node}: {type}: {token}".format(node=node.get_fingerprint(), type="acc", token=token.subject))
        return True

    def test_connectivity(self):
        np_c = NeuropilCluster(    3, port_range=4000, auto_run=False, log_file_prefix="logs/smoke_test_connectivity_cl_")
        np_1 = NeuropilNode(4444, log_file="logs/smoke_test_connectivity_nl1.log", auto_run=False, no_threads=6)
        np_2 = NeuropilNode(5555, log_file="logs/smoke_test_connectivity_nl2.log",auto_run=False)

        np_c.set_authenticate_cb(self.authn_allow_all)
        np_c.set_authorize_cb(self.authz_allow_all)
        np_c.set_accounting_cb(self.acc_allow_all)
        np_c.run(0)
        
        np_1.set_authenticate_cb(self.authn_allow_all)
        np_1.set_authorize_cb(self.authz_allow_all)
        np_1.set_accounting_cb(self.acc_allow_all)
        np_1.run(0)
                
        np_2.set_authenticate_cb(self.authn_allow_all)
        np_2.set_authorize_cb(self.authz_allow_all)
        np_2.set_accounting_cb(self.acc_allow_all)
        np_2.run(0)        

        np1_addr = np_1.get_address()
        np2_addr = np_2.get_address()    
                            
        np_2.join(np1_addr)
        np_c.join(np2_addr)

        t1 = time.time()

        try:
            while True:
                elapsed = float(time.time() - t1)

                if elapsed % 2 == 0:
                    self.assertTrue(np_1.get_status() == neuropil.np_running)
                    self.assertTrue(np_2.get_status() == neuropil.np_running)                
                    for n, s in np_c.get_status():
                        self.assertTrue(s == neuropil.np_running)

                if elapsed > 5:
                    self.assertTrue(np_1.has_joined())
                    self.assertTrue(np_2.has_joined())
                    break

        finally:
            np_1.shutdown()
            np_2.shutdown()
            np_c.shutdown()
            



if __name__ == "__main__":
    unittest.main() # run all tests