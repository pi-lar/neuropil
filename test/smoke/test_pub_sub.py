import unittest
import time  
import math
from neuropil import NeuropilNode, NeuropilCluster, neuropil, np_token, np_message, np_id, _NeuropilHelper
from _neuropil import ffi
from misc import TestHelper

from ctypes import c_char, c_bool

class PubSubTest(unittest.TestCase):

    np_c_fp = []
    received = {}
    msg_delivery_succ = 0
    send = False

    @staticmethod
    def authn_allow_cluster(node:NeuropilNode, token:np_token):
        id = ffi.new("np_id", b'\0')
        ret = neuropil.np_token_fingerprint(node._context, _NeuropilHelper.convert_from_python(token), False, ffi.addressof(id))
        if ret is not neuropil.np_ok:
            return False

        for node_obj, node_fp in PubSubTest.np_c_fp: 
            if str(np_id(id)) == str(node_fp):
                # print ("{time:.3f} / {node}: 1 authentication granted to {fp}".format(time=float(time.time()), node=node.get_fingerprint(), fp=np_id(id) ))
                return True
            if str(node.get_fingerprint()) == str(node_fp):
                # print ("{time:.3f} / {node}: 2 authentication granted to {fp}".format(time=float(time.time()), node=node.get_fingerprint(), fp=np_id(id) ))
                return True

        return False

    @staticmethod
    def authz_allow_all(node:NeuropilNode, token:np_token):
        id = ffi.new("np_id", b'\0')
        ret = neuropil.np_token_fingerprint(node._context, _NeuropilHelper.convert_from_python(token), False, ffi.addressof(id))
        if ret is not neuropil.np_ok:
            return False
        # print ("{time:.3f} / {node}: 1 authorization granted to {fp}".format(time=float(time.time()), node=node.get_fingerprint(), fp=np_id(id) ))
        return True

    @staticmethod
    def msg_received(node:NeuropilNode, message:np_message):
        # print ("{time:.3f} / {node}: 2 msg received from {sender}".format(time=float(time.time()), node=node.get_fingerprint(), sender=np_id(message.__getattribute__('from')) ))
        PubSubTest.received[np_id(message.__getattribute__('from'))] = True
        PubSubTest.msg_delivery_succ = len(PubSubTest.received)
        return True

    def test_pub_sub(self):

        np_c  = NeuropilCluster(    3, port_range=5500, auto_run=False, log_file_prefix="logs/smoke_pubsub_cl_", no_threads=3)
        np_r1 = NeuropilNode(5505, log_file="logs/smoke_test_pubsub_r1.log", auto_run=False, no_threads=3)
        np_r2 = NeuropilNode(5506, log_file="logs/smoke_test_pubsub_r2.log", auto_run=False, no_threads=3)
        np_s1 = NeuropilNode(5507, log_file="logs/smoke_test_pubsub_s1.log", auto_run=False, no_threads=3)

        subject = b"NP.TEST.pubsub.1"
        
        mxp = np_r1.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.max_retry = 5
        mxp.apply()
        np_r1.set_receive_cb(subject, self.msg_received)

        mxp = np_r2.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.apply()
        np_r2.set_receive_cb(subject, self.msg_received)

        mxp = np_s1.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.apply()

        np_c.set_authenticate_cb(TestHelper.authn_allow_all)
        np_c.set_authorize_cb(TestHelper.authz_allow_all)
        np_c.set_accounting_cb(TestHelper.acc_allow_all)
        np_c.run(0)
        
        np_r1.set_authenticate_cb(PubSubTest.authn_allow_cluster)
        np_r1.set_authorize_cb(TestHelper.authz_allow_all)
        np_r1.set_accounting_cb(TestHelper.acc_allow_all)
        np_r1.run(0)
        
        np_r2.set_authenticate_cb(PubSubTest.authn_allow_cluster)
        np_r2.set_authorize_cb(TestHelper.authz_allow_all)
        np_r2.set_accounting_cb(TestHelper.acc_allow_all)
        np_r2.run(0)        

        np_s1.set_authenticate_cb(PubSubTest.authn_allow_cluster)
        np_s1.set_authorize_cb(PubSubTest.authz_allow_all)
        np_s1.set_accounting_cb(TestHelper.acc_allow_all)
        np_s1.run(0)        

        PubSubTest.np_c_fp  = np_c.get_fingerprint()

        nps1_addr = np_s1.get_address()
        npr1_addr = np_r1.get_address()
        npr2_addr = np_r2.get_address()

        np_c.join(npr1_addr)
        np_c.join(npr2_addr)
        np_c.join(nps1_addr)

        t1 = time.time()
        timeout = 150 #sec
        send = False
        try:
            while True:
                elapsed = float(time.time() - t1)
                # TODO: remove elapsed > 90 condition after reimplementation of np_has_receiver_for
                if np_s1.np_has_receiver_for(subject) and elapsed > 90 and not send :
                    np_s1.send(subject, b'test')
                    PubSubTest.send = True

                if PubSubTest.msg_delivery_succ >= 2 or elapsed > timeout:
                    break

                np_s1.run(math.pi/100)
                np_r2.run(math.pi/100)
                np_r1.run(math.pi/100)
                np_c.run(math.pi/100)

        finally:
            np_s1.shutdown()
            np_r1.shutdown()
            np_r2.shutdown()
            np_c.shutdown()

    def tearDown(self):
        self.assertTrue(True == PubSubTest.send)       
        self.assertTrue(2 == PubSubTest.msg_delivery_succ)
