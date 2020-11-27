import unittest
import time
import math
from neuropil import NeuropilNode, NeuropilCluster, neuropil, np_token, np_message
from misc import TestHelper
from multiprocessing import Value
from ctypes import c_char, c_bool

class MsgDeliveryTest(unittest.TestCase):
    msg_delivery_succ = Value(c_bool, False)

    @staticmethod
    def msg_received(node:NeuropilNode, message:np_message):
        MsgDeliveryTest.msg_delivery_succ.value = True
        return True

    def test_msg_delivery(self):

        np_c = NeuropilCluster(    3, port_range=4010, auto_run=False, log_file_prefix="logs/smoke_msg_delivery_cl_")
        np_1 = NeuropilNode(4001, log_file="logs/smoke_test_msg_delivery_nl1.log", auto_run=False, no_threads=6)
        np_2 = NeuropilNode(4002, log_file="logs/smoke_test_msg_delivery_nl2.log",auto_run=False)

        subject = b"NP.TEST.msg_delivery"
        mxp1 = np_1.get_mx_properties(subject)
        mxp1.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp1.max_retry = 10
        mxp1.apply()

        mxp2 = np_2.get_mx_properties(subject)
        mxp2.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp2.apply()
        np_2.set_receive_cb(subject, self.msg_received)

        TestHelper.disableAAA(np_c).run(0)
        TestHelper.disableAAA(np_1).run(0)
        TestHelper.disableAAA(np_2).run(0)

        np1_addr = np_1.get_address()
        np2_addr = np_2.get_address()

        np_2.join(np1_addr)
        np_c.join(np2_addr)

        timeout = 120 #sec

        t1 = time.time()
        elapsed = 0.
        send = False
        try:
            while elapsed < timeout and not MsgDeliveryTest.msg_delivery_succ.value:
                elapsed = float(time.time() - t1)
                # TODO: remove elapsed > X condition after reimplementation of np_has_receiver_for or a corresponding cache system
                if np_1.np_has_receiver_for(subject) and (elapsed > mxp1.message_ttl or not send) :
                    if np_1.send(subject, b'test') != neuropil.np_ok:
                        print("ERROR sending Data")
                    else:
                        send = True
                np_1.run(math.pi/10)

        finally:
            np_1.shutdown()
            np_2.shutdown()
            np_c.shutdown()

        self.assertTrue(send)
        self.assertTrue(MsgDeliveryTest.msg_delivery_succ.value)