# SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

import unittest
import time
import math
from neuropil import NeuropilNode, NeuropilCluster, neuropil, np_token, np_message
from misc import TestHelper
from multiprocessing import Value
from ctypes import c_char, c_bool

import random
import string
import sys

class MsgDeliveryTest(unittest.TestCase):

    def msg_received(self, node:NeuropilNode, message:np_message):
        self.msg_delivery_succ.value = True
        self.assertEqual(sys.getsizeof(message.raw()), self.target_size)
        return True

    def _test_msg_X_delivery(self, size):
        self.msg_delivery_succ = Value(c_bool, False)
        self.target_size = size

        np_c = NeuropilCluster(    3, port_range=4010, auto_run=False, log_file_prefix="logs/smoke_test_msg_delivery_cl_")
        np_1 = NeuropilNode(4001, log_file="logs/smoke_test_msg_delivery_nl1.log", auto_run=False, n_threads=6)
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

        timeout = 180 #sec

        t1 = time.time()
        elapsed = 0.
        send = False
        data = ''.join(random.choice(string.ascii_uppercase) for i in range(self.target_size-33)).encode("utf-8")

        try:
            while elapsed < timeout and not self.msg_delivery_succ.value:
                elapsed = float(time.time() - t1)

                if np_1.np_has_receiver_for(subject) and not send:
                    if np_1.send(subject, data) != neuropil.np_ok:
                        print("ERROR sending Data")
                    else:
                        send = True

                if self.msg_delivery_succ.value:
                    break
                np_1.run(math.pi/10)

        finally:
            np_1.shutdown()
            np_2.shutdown()
            np_c.shutdown()

        self.assertTrue(send)
        self.assertTrue(self.msg_delivery_succ.value)

    def test_msg_1k_delivery(self):
        self._test_msg_X_delivery(1000)
    def test_msg_10k_delivery(self):
        self._test_msg_X_delivery(1000*50)
    #def test_msg_100k_delivery(self):
    #    self._test_msg_X_delivery(1000*100)
    #def test_msg_1MB_delivery(self):
    #    self._test_msg_X_delivery(1000*1000)
    #def test_msg_10MB_delivery(self):
    #    self._test_msg_X_delivery(1000*1000*10)