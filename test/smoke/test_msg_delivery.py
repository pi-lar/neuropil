import unittest
import time  
from neuropil import NeuropilNode, NeuropilCluster, neuropil, np_token, np_message
from misc import TestHelper

msg_delivery_succ = False
class MsgDeliveryTest(unittest.TestCase):
    @staticmethod
    def msg_received(node:NeuropilNode, message:np_message):    
        global msg_delivery_succ
        msg_delivery_succ = True        
        return True

    def test_msg_delivery(self):
        global msg_delivery_succ

        np_c = NeuropilCluster(    3, port_range=4000, auto_run=False, log_file_prefix="logs/smoke_msg_delivery_cl_")
        np_1 = NeuropilNode(4444, log_file="logs/smoke_test_msg_delivery_nl1.log", auto_run=False, no_threads=6)
        np_2 = NeuropilNode(5555, log_file="logs/smoke_test_msg_delivery_nl2.log",auto_run=False)

        subject = b"NP.TEST.msg_delivery"
        mxp = np_1.get_mx_properties(subject)        
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.max_retry = 10
        mxp.apply()

        mxp = np_2.get_mx_properties(subject)        
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.apply()
        np_2.set_receive_cb(subject, self.msg_received)

        np_c.set_authenticate_cb(TestHelper.authn_allow_all)
        np_c.set_authorize_cb(TestHelper.authz_allow_all)
        np_c.set_accounting_cb(TestHelper.acc_allow_all)
        np_c.run(0)
        
        np_1.set_authenticate_cb(TestHelper.authn_allow_all)
        np_1.set_authorize_cb(TestHelper.authz_allow_all)
        np_1.set_accounting_cb(TestHelper.acc_allow_all)
        np_1.run(0)
                
        np_2.set_authenticate_cb(TestHelper.authn_allow_all)
        np_2.set_authorize_cb(TestHelper.authz_allow_all)
        np_2.set_accounting_cb(TestHelper.acc_allow_all)
        np_2.run(0)        

        np1_addr = np_1.get_address()
        np2_addr = np_2.get_address()    
                            
        np_2.join(np1_addr)
        np_c.join(np2_addr)

        t1 = time.time()
        timeout = 120 #sec
        send = False
        try:
            while True:
                elapsed = float(time.time() - t1)
                # TODO: remove elapsed > 90 condition after reimplementation of np_has_receiver_for
                if np_1.np_has_receiver_for(subject) and elapsed > 90 and not send :
                    np_1.send(subject, b'test')
                    send = True

                if msg_delivery_succ or elapsed > timeout:
                    break

        finally:
            np_1.shutdown()
            np_2.shutdown()
            np_c.shutdown()
                    
        self.assertTrue(send)       
        self.assertTrue(msg_delivery_succ)