# SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
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

    def _test_msg_X_delivery(self, size, protocol_sender="udp4",protocol_receiver="udp4"):
        self.msg_delivery_succ = Value(c_bool, False)
        self.target_size = size

        np_c = NeuropilCluster(    3, port_range=4010, auto_run=False, log_file_prefix=f"logs/smoke_test_msg_delivery_{size}_{protocol_sender}_{protocol_receiver}_cluster_")
        np_1 = NeuropilNode(4001,proto=protocol_sender,   log_file=f"logs/smoke_test_msg_delivery_{size}_{protocol_sender}_{protocol_receiver}_sender.log", auto_run=False)
        np_2 = NeuropilNode(4002,proto=protocol_receiver, log_file=f"logs/smoke_test_msg_delivery_{size}_{protocol_sender}_{protocol_receiver}_receiver.log",auto_run=False)

        subject = b"NP.TEST.msg_delivery"
        mxp1 = np_1.get_mx_properties(subject)
        mxp1.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp1.role = neuropil.NP_MX_PROVIDER
        mxp1.max_retry = 10
        mxp1.apply()

        mxp2 = np_2.get_mx_properties(subject)
        mxp2.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp2.role = neuropil.NP_MX_CONSUMER
        mxp2.apply()
        np_2.set_receive_cb(subject, self.msg_received)

        TestHelper.disableAAA(np_c).run(0)
        TestHelper.disableAAA(np_1).run(0)
        TestHelper.disableAAA(np_2).run(0)

        np1_addr = np_1.get_address()
        np2_addr = np_2.get_address()

        np_c.join(np1_addr)
        np_2.join(np1_addr)

        timeout = 40 #sec

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
                        timeout = 160 #sec
                        send = True

                if self.msg_delivery_succ.value:
                    break
                np_1.run(0.01)

        finally:
            np_1.shutdown()
            np_2.shutdown()
            np_c.shutdown()

        self.assertTrue(send,f"Could not send data as no token was received in {timeout}sec.")
        self.assertTrue(self.msg_delivery_succ.value,f"Did not receive data in {timeout}sec, but did receive token.")

    def test_msg_delivery_tcp4_pas4(self):
        self._test_msg_X_delivery(1000,protocol_sender="tcp4",protocol_receiver="pas4")
    def test_msg_delivery_udp4_pas4(self):
        self._test_msg_X_delivery(1000,protocol_sender="udp4", protocol_receiver="pas4")
    def test_msg_delivery_tcp4_udp4(self):
        self._test_msg_X_delivery(1000,protocol_sender="tcp4",protocol_receiver="udp4")
    def test_msg_delivery_udp4_tcp4(self):
        self._test_msg_X_delivery(1000,protocol_sender="udp4",protocol_receiver="tcp4")
    def test_msg_delivery_tcp4_tcp4(self):
        self._test_msg_X_delivery(1000,protocol_sender="tcp4",protocol_receiver="tcp4")
    def test_msg_delivery_udp4_udp4(self):
        self._test_msg_X_delivery(1000,protocol_sender="udp4",protocol_receiver="udp4")
    def test_msg_1k_delivery(self):
        self._test_msg_X_delivery(1000)
    def test_msg_10k_delivery(self):
        self._test_msg_X_delivery(1000*10)
    #def test_msg_100k_delivery(self):
    #    self._test_msg_X_delivery(1000*100)
    #def test_msg_1MB_delivery(self):
    #    self._test_msg_X_delivery(1000*1000)
    #def test_msg_10MB_delivery(self):
    #    self._test_msg_X_delivery(1000*1000*10)