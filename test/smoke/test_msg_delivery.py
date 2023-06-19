# SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

from socket import timeout
import unittest
import time
from neuropil import NeuropilNode, NeuropilCluster, neuropil, np_message
from misc import TestHelper

import random
import string
import sys

port_index = 1


class MsgDeliveryTest(unittest.TestCase):
    msg_size = 100
    cluster_size = 0
    protocol_cluster = "udp4"
    protocol_sender = "udp4"
    protocol_receiver = "udp4"
    token_timeout = 140  # sec
    send_timeout = 240  # sec
    set_identity_sender = False
    set_identity_receiver = False
    set_identity_cluster = False

    def msg_received(self, node: NeuropilNode, message: np_message):
        self.msg_delivery_succ = True
        self.assertEqual(sys.getsizeof(message.raw()), self.target_size)
        return True

    def test_msg_X_delivery(self):
        global port_index

        self.msg_delivery_succ = False
        self.target_size = self.msg_size
        np_c = None

        log_file_prefix = f"logs/smoke_test_msg_delivery_{self.cluster_size}_{self.msg_size}_sender:{self.protocol_sender}_receiver:{self.protocol_receiver}"

        if self.cluster_size > 0:
            np_c = NeuropilCluster(
                self.cluster_size,
                proto=self.protocol_cluster,
                port_range=4000 + port_index,
                auto_run=False,
                log_file_prefix=f"{log_file_prefix}_cluster_",
            )
            if self.set_identity_cluster:
                np_c.use_identity(np_1.new_identity())
        port_index += self.cluster_size
        np_1 = NeuropilNode(
            4100 + port_index,
            proto=self.protocol_sender,
            log_file=f"{log_file_prefix}_sender.log",
            auto_run=False,
        )
        port_index += 1
        np_2 = NeuropilNode(
            4200 + port_index,
            proto=self.protocol_receiver,
            log_file=f"{log_file_prefix}_receiver.log",
            auto_run=False,
        )
        port_index += 1

        if self.set_identity_sender:
            np_1.use_identity(np_1.new_identity())
        if self.set_identity_receiver:
            np_2.use_identity(np_2.new_identity())

        subject = b"NP.TEST.msg_delivery"
        mxp1 = np_1.get_mx_properties(subject)
        mxp1.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp1.role = neuropil.NP_MX_PROVIDER
        mxp1.intent_ttl = 300
        mxp1.intent_update_after = 20
        mxp1.max_retry = 3
        mxp1.apply()

        mxp2 = np_2.get_mx_properties(subject)
        mxp2.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp2.role = neuropil.NP_MX_CONSUMER
        mxp2.intent_ttl = 300
        mxp2.intent_update_after = 20
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

        np_1.run(0.01)
        np_2.run(0.01)
        if np_c:
            np_c.run(0.01)

        timeout = self.token_timeout
        t1 = time.time()
        elapsed = 0.0
        send = False
        data = "".join(
            random.choice(string.ascii_uppercase) for i in range(self.target_size - 33)
        ).encode("utf-8")

        try:
            while elapsed < timeout and not self.msg_delivery_succ:
                elapsed = float(time.time() - t1)

                if not send and np_1.np_has_receiver_for(subject):
                    if np_1.send(subject, data) != neuropil.np_ok:
                        print("ERROR sending Data")
                    else:
                        timeout = self.send_timeout
                        send = True

                if self.msg_delivery_succ:
                    break

                np_1.run(0.01)
                np_2.run(0.01)
                if np_c:
                    np_c.run(0.01)

        finally:
            np_1.shutdown()
            np_2.shutdown()
            if np_c:
                np_c.shutdown()

        self.assertTrue(
            send,
            f"Could not send data as no token was received in {self.token_timeout}sec.",
        )
        self.assertTrue(
            self.msg_delivery_succ,
            f"Did not receive data in {self.send_timeout}sec, but did receive token.",
        )


class MsgDeliveryTest_udp4_pas4(MsgDeliveryTest):
    protocol_sender = "udp4"
    protocol_receiver = "pas4"


class MsgDeliveryTest_tcp4_pas4(MsgDeliveryTest):
    protocol_cluster = "tcp4"
    protocol_sender = "tcp4"
    protocol_receiver = "pas4"


class MsgDeliveryTest_tcp4_udp4(MsgDeliveryTest):
    protocol_sender = "tcp4"
    protocol_receiver = "udp4"


class MsgDeliveryTest_udp4_tcp4(MsgDeliveryTest):
    protocol_sender = "udp4"
    protocol_receiver = "tcp4"


class MsgDeliveryTest_tcp4_tcp4(MsgDeliveryTest):
    protocol_cluster = "tcp4"
    protocol_sender = "tcp4"
    protocol_receiver = "tcp4"


class MsgDeliveryTest_udp4_udp4(MsgDeliveryTest):
    protocol_sender = "udp4"
    protocol_receiver = "udp4"


class MsgDeliveryTest_1k(MsgDeliveryTest):
    msg_size = 1000


class MsgDeliveryTest_10k(MsgDeliveryTest):
    msg_size = 1000 * 10


class MsgDeliveryTest_udp4_udp4_ident_s_r(MsgDeliveryTest):
    protocol_sender = "udp4"
    protocol_receiver = "udp4"
    set_identity_sender = True
    set_identity_receiver = True
