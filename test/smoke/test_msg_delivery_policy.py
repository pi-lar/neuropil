# SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

import unittest
import time
import inspect
from neuropil import NeuropilNode, NeuropilCluster, neuropil, np_token, np_message
from misc import TestHelper


class MsgPolicyDeliveryTest(unittest.TestCase):
    def cb_payload_1_received(self, node: NeuropilNode, message: np_message):
        try:
            self.assertTrue(message.raw() == b"test_payload_1")
            self.payload_1_received = True
        except AssertionError:
            self.cause += " did not receive payload_1"
            self.cause += f" but {message.raw()} via {message.uuid}"
            self.abort_test = True
        return True

    def cb_payload_2_received(self, node: NeuropilNode, message: np_message):
        try:
            self.assertTrue(message.raw() == b"test_payload_2")
            self.payload_2_received = True
        except AssertionError:
            self.cause += " did not receive payload_2"
            self.cause += f" but {message.raw()} via {message.uuid}"
            self.abort_test = True
        return True

    def cb_msg_never_received(self, node: NeuropilNode, message: np_message):
        self.cause += " did receive data "
        self.abort_test = True
        self.payload_1_received = False
        # should never trigger
        return True

    def test_policy_1sender_2receiver_1receiver_blocked(self):
        self.abort_test = False
        self.cause = ""
        self.payload_1_received = False
        self.payload_2_received = False

        fn = inspect.stack()[0][3]
        sender_1 = NeuropilNode(
            4001, log_file=f"logs/smoke_{fn}_sender_1.log", auto_run=False
        )
        receiver_1 = NeuropilNode(
            4002, log_file=f"logs/smoke_{fn}_receiver_1.log", auto_run=False
        )
        receiver_2 = NeuropilNode(
            4003, log_file=f"logs/smoke_{fn}_receiver_2.log", auto_run=False
        )

        subject = b"NP.TEST.msg_delivery"
        mxp = sender_1.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.role = neuropil.NP_MX_PROVIDER
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.max_retry = 3
        mxp.apply()
        mxp.set_attr_policy_bin("test_attr", b"test")

        mxp = receiver_2.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.role = neuropil.NP_MX_CONSUMER
        mxp.apply()
        receiver_2.set_attr_bin(
            "test_attr", b"test2", inheritance=neuropil.NP_ATTR_INTENT
        )
        receiver_2.set_receive_cb(subject, self.cb_msg_never_received)

        mxp = receiver_1.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.role = neuropil.NP_MX_CONSUMER
        mxp.apply()
        receiver_1.set_attr_bin(
            "test_attr", b"test", inheritance=neuropil.NP_ATTR_INTENT
        )
        receiver_1.set_receive_cb(subject, self.cb_payload_1_received)

        TestHelper.disableAAA(sender_1).run(0)
        TestHelper.disableAAA(receiver_1).run(0)
        TestHelper.disableAAA(receiver_2).run(0)

        sender_addr = sender_1.get_address()

        receiver_1.join(sender_addr)
        receiver_2.join(sender_addr)

        sender_1.run(0.01)
        receiver_1.run(0.01)
        receiver_2.run(0.01)

        timeout = 240  # sec
        t1 = time.time()
        payload_1_send = False
        elapsed = 0.0
        try:
            while elapsed < timeout and not self.abort_test:
                elapsed = float(time.time() - t1)

                if sender_1.np_has_receiver_for(subject) and not payload_1_send:
                    if sender_1.send(subject, b"test_payload_1") != neuropil.np_ok:
                        print("ERROR sending Data")
                    else:
                        payload_1_send = True

                if self.payload_1_received:
                    break

                sender_1.run(0.01)
                receiver_1.run(0.01)
                receiver_2.run(0.01)

        finally:
            sender_1.shutdown()
            receiver_1.shutdown()
            receiver_2.shutdown()

        self.assertFalse(self.abort_test, self.cause)
        self.assertTrue(self.payload_1_received)

    def test_policy_2sender_1receiver_1sender_blocked(self):
        self.abort_test = False
        self.cause = ""
        self.payload_1_received = False
        self.payload_2_received = False

        fn = inspect.stack()[0][3]
        sender_1 = NeuropilNode(
            4001, log_file=f"logs/smoke_{fn}_sender_1.log", auto_run=False
        )
        sender_2 = NeuropilNode(
            4002, log_file=f"logs/smoke_{fn}_sender_2.log", auto_run=False
        )
        receiver_1 = NeuropilNode(
            4003, log_file=f"logs/smoke_{fn}_receiver_1.log", auto_run=False
        )

        subject = b"NP.TEST.msg_delivery"
        mxp = sender_1.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.role = neuropil.NP_MX_PROVIDER
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.max_retry = 3
        mxp.apply()
        mxp.set_attr_policy_bin("test_attr", b"test")

        mxp = sender_2.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.role = neuropil.NP_MX_PROVIDER
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.max_retry = 3
        mxp.apply()
        mxp.set_attr_policy_bin("test_attr", b"test2")

        mxp = receiver_1.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.role = neuropil.NP_MX_CONSUMER
        mxp.apply()
        receiver_1.set_attr_bin(
            "test_attr", b"test", inheritance=neuropil.NP_ATTR_INTENT
        )
        receiver_1.set_receive_cb(subject, self.cb_payload_1_received)

        TestHelper.disableAAA(sender_1).run(0)
        TestHelper.disableAAA(receiver_1).run(0)
        TestHelper.disableAAA(sender_2).run(0)

        sender_1_addr = sender_1.get_address()
        sender_2_addr = sender_2.get_address()
        receiver_1_addr = receiver_1.get_address()

        sender_1.join(sender_2_addr)
        sender_2.join(receiver_1_addr)
        receiver_1.join(sender_1_addr)

        sender_1.run(0.01)
        sender_2.run(0.01)
        receiver_1.run(0.01)

        payload_1_send = False

        timeout = 240  # sec
        t1 = time.time()
        elapsed = 0.0
        try:
            while elapsed < timeout and not self.abort_test:
                elapsed = float(time.time() - t1)

                if sender_1.np_has_receiver_for(subject) and not payload_1_send:
                    if sender_1.send(subject, b"test_payload_1") != neuropil.np_ok:
                        print("ERROR sending Data")
                    else:
                        payload_1_send = True
                if sender_2.np_has_receiver_for(subject):
                    if sender_2.send(subject, b"test_payload_2") != neuropil.np_ok:
                        print("ERROR sending Data")

                if self.payload_1_received:
                    break

                sender_1.run(0.01)
                sender_2.run(0.01)
                receiver_1.run(0.01)

        finally:
            sender_1.shutdown()
            receiver_1.shutdown()
            sender_2.shutdown()

        self.assertFalse(self.abort_test, self.cause)
        self.assertTrue(self.payload_1_received)

    def test_policy_2sender_2receiver_2_channel(self):
        self.abort_test = False
        self.cause = ""
        self.payload_1_received = False
        self.payload_2_received = False

        fn = inspect.stack()[0][3]
        sender_1 = NeuropilNode(
            4001, log_file=f"logs/smoke_{fn}_sender_1.log", auto_run=False
        )
        sender_2 = NeuropilNode(
            4002, log_file=f"logs/smoke_{fn}_sender_2.log", auto_run=False
        )
        receiver_1 = NeuropilNode(
            4003, log_file=f"logs/smoke_{fn}_receiver_1.log", auto_run=False
        )
        receiver_2 = NeuropilNode(
            4004, log_file=f"logs/smoke_{fn}_receiver_2.log", auto_run=False
        )

        subject = b"NP.TEST.msg_delivery"
        mxp = sender_1.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.role = neuropil.NP_MX_PROVIDER
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.max_retry = 3
        mxp.apply()
        mxp.set_attr_policy_bin("test_attr", b"test")

        mxp = receiver_1.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.role = neuropil.NP_MX_CONSUMER
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.apply()
        receiver_1.set_attr_bin(
            "test_attr", b"test", inheritance=neuropil.NP_ATTR_INTENT
        )
        receiver_1.set_receive_cb(subject, self.cb_payload_1_received)

        mxp = sender_2.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.role = neuropil.NP_MX_PROVIDER
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.max_retry = 3
        mxp.apply()
        mxp.set_attr_policy_bin("test_attr", b"test2")

        mxp = receiver_2.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.role = neuropil.NP_MX_CONSUMER
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.apply()
        receiver_2.set_attr_bin(
            "test_attr", b"test2", inheritance=neuropil.NP_ATTR_INTENT
        )
        receiver_2.set_receive_cb(subject, self.cb_payload_2_received)

        TestHelper.disableAAA(sender_1).run(0)
        TestHelper.disableAAA(receiver_1).run(0)
        TestHelper.disableAAA(receiver_2).run(0)
        TestHelper.disableAAA(sender_2).run(0)

        sender_1_addr = sender_1.get_address()
        sender_2_addr = sender_2.get_address()
        receiver_1_addr = receiver_1.get_address()
        receiver_2_addr = receiver_2.get_address()

        sender_1.join(sender_2_addr)
        sender_1.join(receiver_1_addr)
        sender_1.join(receiver_2_addr)
        sender_2.join(receiver_1_addr)
        sender_2.join(receiver_2_addr)
        receiver_1.join(receiver_2_addr)

        setup_elapsed = time.time()
        while (time.time() - setup_elapsed) <= 90.0:
            sender_1.run(0.01)
            sender_2.run(0.01)
            receiver_1.run(0.01)
            receiver_2.run(0.01)

        payload_1_send = False
        payload_2_send = False
        timeout = 240  # sec
        t1 = time.time()
        elapsed = 0.0
        try:
            while elapsed < timeout and not self.abort_test:
                elapsed = float(time.time() - t1)

                if sender_1.np_has_receiver_for(subject) and not payload_1_send:
                    if sender_1.send(subject, b"test_payload_1") != neuropil.np_ok:
                        print("ERROR sending Data")
                    else:
                        payload_1_send = True
                if sender_2.np_has_receiver_for(subject) and not payload_2_send:
                    if sender_2.send(subject, b"test_payload_2") != neuropil.np_ok:
                        print("ERROR sending Data")
                    else:
                        payload_2_send = True

                if self.payload_1_received and self.payload_2_received:
                    break

                sender_1.run(0.01)
                sender_2.run(0.01)
                receiver_1.run(0.01)
                receiver_2.run(0.01)

        finally:
            sender_1.shutdown()
            sender_2.shutdown()
            receiver_1.shutdown()
            receiver_2.shutdown()

        self.assertFalse(self.abort_test, self.cause)
        self.assertTrue(self.payload_1_received or self.payload_2_received)
        self.assertTrue(self.payload_1_received)
        self.assertTrue(self.payload_2_received)

    def test_policy_2sender_2receiver_2_channel_cloud(self):
        self.abort_test = False
        self.cause = ""
        self.payload_1_received = False
        self.payload_2_received = False

        fn = inspect.stack()[0][3]
        cloud = NeuropilCluster(
            2,
            4050,
            log_file_prefix=f"logs/smoke_{fn}_cloud",
        )
        sender_1 = NeuropilNode(
            4001, proto="pas4", log_file=f"logs/smoke_{fn}_sender_1.log", auto_run=False
        )
        sender_2 = NeuropilNode(
            4002, proto="pas4", log_file=f"logs/smoke_{fn}_sender_2.log", auto_run=False
        )
        receiver_1 = NeuropilNode(
            4003,
            proto="pas4",
            log_file=f"logs/smoke_{fn}_receiver_1.log",
            auto_run=False,
        )
        receiver_2 = NeuropilNode(
            4004,
            proto="pas4",
            log_file=f"logs/smoke_{fn}_receiver_2.log",
            auto_run=False,
        )

        subject = b"NP.TEST.msg_delivery"

        mxp = sender_1.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.role = neuropil.NP_MX_PROVIDER
        mxp.max_retry = 3
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.apply()
        mxp.set_attr_policy_bin("test_attr", b"test")

        mxp = sender_2.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.role = neuropil.NP_MX_PROVIDER
        mxp.max_retry = 3
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.apply()
        mxp.set_attr_policy_bin("test_attr", b"test2")

        mxp = receiver_1.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.role = neuropil.NP_MX_CONSUMER
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.apply()
        receiver_1.set_attr_bin(
            "test_attr", b"test", inheritance=neuropil.NP_ATTR_INTENT
        )
        receiver_1.set_receive_cb(subject, self.cb_payload_1_received)

        mxp = receiver_2.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.role = neuropil.NP_MX_CONSUMER
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.apply()
        receiver_2.set_attr_bin(
            "test_attr", b"test2", inheritance=neuropil.NP_ATTR_INTENT
        )
        receiver_2.set_receive_cb(subject, self.cb_payload_2_received)

        TestHelper.disableAAA(cloud).run(0)
        TestHelper.disableAAA(sender_1).run(0)
        TestHelper.disableAAA(receiver_1).run(0)
        TestHelper.disableAAA(receiver_2).run(0)
        TestHelper.disableAAA(sender_2).run(0)

        addresses = cloud.get_address()
        bootstrapper_node, c_prev_addr = addresses[0]

        for c_node, c_addr in addresses[1:]:
            c_node.join(c_prev_addr)
            receiver_1.join(c_prev_addr)
            receiver_2.join(c_prev_addr)
            sender_1.join(c_prev_addr)
            sender_2.join(c_prev_addr)

            c_prev_addr = c_addr

        setup_elapsed = time.time()
        while (time.time() - setup_elapsed) <= 90.0:
            cloud.run(0.01)
            sender_1.run(0.01)
            sender_2.run(0.01)
            receiver_1.run(0.01)
            receiver_2.run(0.01)

        payload_1_send = False
        payload_2_send = False

        timeout = 240  # sec
        t1 = time.time()
        elapsed = 0.0
        try:
            while elapsed < timeout and not self.abort_test:
                elapsed = float(time.time() - t1)

                if sender_1.np_has_receiver_for(subject) and not payload_1_send:
                    if sender_1.send(subject, b"test_payload_1") != neuropil.np_ok:
                        print("ERROR sending Data")
                    else:
                        payload_1_send = True
                if sender_2.np_has_receiver_for(subject) and not payload_2_send:
                    if sender_2.send(subject, b"test_payload_2") != neuropil.np_ok:
                        print("ERROR sending Data")
                    else:
                        payload_2_send = True

                cloud.run(0.01)
                if self.payload_1_received and self.payload_2_received:
                    break
        finally:
            sender_1.shutdown()
            sender_2.shutdown()
            receiver_1.shutdown()
            receiver_2.shutdown()

        self.assertFalse(self.abort_test, self.cause)
        self.assertTrue(self.payload_1_received or self.payload_2_received)
        self.assertTrue(self.payload_1_received)
        self.assertTrue(self.payload_2_received)
