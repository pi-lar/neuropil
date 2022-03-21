# SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

from socket import timeout
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

port_index = 1
class MsgDeliveryTest(unittest.TestCase):
    msg_size = 100
    cluster_size = 0
    protocol_cluster="udp4"
    protocol_sender="udp4"
    protocol_receiver="udp4"
    token_timeout = 140 #sec
    send_timeout = 240 #sec

    def msg_received(self, node:NeuropilNode, message:np_message):
        self.msg_delivery_succ.value = True
        self.assertEqual(sys.getsizeof(message.raw()), self.target_size)
        return True

    def test_msg_X_delivery(self):
        global port_index

        self.msg_delivery_succ = Value(c_bool, False)
        self.target_size = self.msg_size
        np_c = None
        if self.cluster_size > 0:
            np_c = NeuropilCluster(    self.cluster_size, proto=self.protocol_cluster, port_range=4001+port_index, auto_run=False, log_file_prefix=f"logs/smoke_test_msg_delivery_{self.cluster_size}_{self.protocol_sender}_{self.protocol_receiver}_cluster_")
        port_index += self.cluster_size
        np_1 = NeuropilNode(4002 + port_index, proto=self.protocol_sender,   log_file=f"logs/smoke_test_msg_delivery_{self.cluster_size}_{self.protocol_sender}_{self.protocol_receiver}_sender.log", auto_run=False)
        port_index += 1
        np_2 = NeuropilNode(4003 + port_index, proto=self.protocol_receiver, log_file=f"logs/smoke_test_msg_delivery_{self.cluster_size}_{self.protocol_sender}_{self.protocol_receiver}_receiver.log",auto_run=False)
        port_index += 1

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

        if np_c:
            TestHelper.disableAAA(np_c).run(0)
        TestHelper.disableAAA(np_1).run(0)
        TestHelper.disableAAA(np_2).run(0)

        np1_addr = np_1.get_address()
        np2_addr = np_2.get_address()
        
        if np_c:
            np_c.join(np1_addr)
        np_2.join(np1_addr)

        
        timeout = self.token_timeout
        t1 = time.time()
        elapsed = 0.
        send = False
        data = ''.join(random.choice(string.ascii_uppercase) for i in range(self.target_size-33)).encode("utf-8")

        try:
            while elapsed < timeout and not self.msg_delivery_succ.value:
                elapsed = float(time.time() - t1)

                if not send and np_1.np_has_receiver_for(subject):
                    if np_1.send(subject, data) != neuropil.np_ok:
                        print("ERROR sending Data")
                    else:
                        timeout = self.send_timeout
                        send = True

                if self.msg_delivery_succ.value:
                    break
                np_1.run(0.01)

        finally:
            np_1.shutdown()
            np_2.shutdown()
            if np_c:
                np_c.shutdown()

        self.assertTrue(send,f"Could not send data as no token was received in {self.token_timeout}sec.")
        self.assertTrue(self.msg_delivery_succ.value,f"Did not receive data in {self.send_timeout}sec, but did receive token.")

class MsgDeliveryTest_udp4_pas4(MsgDeliveryTest):
    protocol_sender="udp4"
    protocol_receiver="pas4"

class MsgDeliveryTest_tcp4_pas4(MsgDeliveryTest):
    protocol_cluster="tcp4"
    protocol_sender="tcp4"
    protocol_receiver="pas4"
class MsgDeliveryTest_tcp4_udp4(MsgDeliveryTest):
    protocol_sender="tcp4"
    protocol_receiver="udp4"
class MsgDeliveryTest_udp4_tcp4(MsgDeliveryTest):
    protocol_sender="udp4"
    protocol_receiver="tcp4"
class MsgDeliveryTest_tcp4_tcp4(MsgDeliveryTest):
    protocol_cluster="tcp4"
    protocol_sender="tcp4"
    protocol_receiver="tcp4"
class MsgDeliveryTest_udp4_udp4(MsgDeliveryTest):
    protocol_sender="udp4"
    protocol_receiver="udp4"
class MsgDeliveryTest_1k(MsgDeliveryTest):
    msg_size = 1000
class MsgDeliveryTest_10k(MsgDeliveryTest):
    msg_size = 1000*10