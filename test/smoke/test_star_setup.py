# SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

import unittest
import time
import math
from neuropil import (
    NeuropilNode,
    NeuropilCluster,
    _NeuropilHelper,
    neuropil,
    np_token,
    np_message,
    np_id,
)
from _neuropil import ffi

import random
from multiprocessing import Process, Value, Array
from ctypes import c_char, c_bool


class StarSetupTest(unittest.TestCase):
    # common class variables for each process
    np_0_addr = b"*:udp4:localhost:4001"
    subject = b"urn:np:test:subject:1"

    np_0_fp = Array(
        c_char, b"de19bde3dc1aaaf4b196d1c0941c2fbe1478649367c710062586825c76673da1"
    )

    # test targets
    msg_delivery_succ = Value(c_bool, False)
    send = Value(c_bool, False)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @staticmethod
    def msg_received(node: NeuropilNode, message: np_message):
        StarSetupTest.msg_delivery_succ.value = True
        # print("received message complete")
        return True

    @staticmethod
    def authn_allow_all(node: NeuropilNode, token: np_token):
        _id = ffi.new("np_id", b"\0")
        ret = neuropil.np_token_fingerprint(
            node._context,
            _NeuropilHelper.convert_from_python(token),
            False,
            ffi.addressof(_id),
        )
        if ret is not neuropil.np_ok:
            return False

        # print ("{time:.3f} / {node}: A authentication granted to {fp}".format(time=float(time.time()), node=node.get_fingerprint(), fp=np_id(_id)) )
        return True

    @staticmethod
    def authn_allow_star(node: NeuropilNode, token: np_token):
        # global np_0_fp
        _id = ffi.new("np_id", b"\0")
        ret = neuropil.np_token_fingerprint(
            node._context,
            _NeuropilHelper.convert_from_python(token),
            False,
            ffi.addressof(_id),
        )
        if ret is not neuropil.np_ok:
            return False

        if str(np_id(_id)) == StarSetupTest.np_0_fp.value.decode():
            # print ("{time:.3f} / {node}: S authentication granted to {fp}".format(time=float(time.time()), node=node.get_fingerprint(), fp=np_id(_id) ))
            return True
        else:
            # print ("{time:.3f} / {node}: S authentication reject  to {fp}".format(time=float(time.time()), node=node.get_fingerprint(), fp=np_id(_id) ))
            return False

    @staticmethod
    def authz_allow_all(node: NeuropilNode, token: np_token):
        # print ("{time:.3f} / authorization granted to {issuer} / {fp} for {subject}".format(time=float(time.time()), issuer=token.issuer, fp=token.get_fingerprint(), subject=token.subject))
        return True

    def run_sender(self):
        sender = NeuropilNode(
            4002, log_file="logs/smoke_test_star_n1.log", auto_run=False, n_threads=5
        )
        # configure node 1 as sender
        mxp = sender.get_mx_properties(StarSetupTest.subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.role = neuropil.NP_MX_PROVIDER
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.max_retry = 3
        mxp.apply()

        sender.set_authenticate_cb(StarSetupTest.authn_allow_star)
        sender.set_authorize_cb(StarSetupTest.authz_allow_all)
        sender.run(0)
        sender.join(StarSetupTest.np_0_addr)
        # print("{time:.3f} / {node} --> {addr}".format(time=float(time.time()),
        #                                           node=np_1.get_fingerprint(),
        #                                           addr=np_1.get_address()) )
        sender.run(math.pi / 10)
        t1 = time.time()
        timeout = 120  # sec
        while not self.isOK():
            elapsed = float(time.time() - t1)
            # TODO: remove elapsed > 90 condition after reimplementation of np_has_receiver_for
            if elapsed % 2 == 0:
                self.assertTrue(sender.get_status() == neuropil.np_running)

            if (
                sender.np_has_receiver_for(StarSetupTest.subject)
                and not StarSetupTest.send.value
            ):
                sender.send(StarSetupTest.subject, b"test data blob")
                StarSetupTest.send.value = True
                # print("sending message complete")

            if StarSetupTest.msg_delivery_succ.value or elapsed > timeout:
                break
            sender.run(math.pi / 10)
        sender.shutdown()

    def run_receiver(self):
        global subject
        global np_0_addr

        receiver = NeuropilNode(
            4003, log_file="logs/smoke_test_star_n2.log", auto_run=False, n_threads=5
        )
        # configure node 2 as receiver
        mxp = receiver.get_mx_properties(StarSetupTest.subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.role = neuropil.NP_MX_CONSUMER
        mxp.apply()

        receiver.set_receive_cb(StarSetupTest.subject, self.msg_received)
        receiver.set_authenticate_cb(StarSetupTest.authn_allow_star)
        receiver.set_authorize_cb(StarSetupTest.authz_allow_all)
        receiver.run(0)
        receiver.join(StarSetupTest.np_0_addr)
        # print("{time:.3f} / {node} --> {addr}".format(time=float(time.time()),
        #                                           node=np_2.get_fingerprint(),
        #                                           addr=np_2.get_address()) )
        receiver.run(math.pi / 10)

        t1 = time.time()
        timeout = 120  # sec
        while not self.isOK():
            elapsed = float(time.time() - t1)
            # TODO: remove elapsed > 90 condition after reimplementation of np_has_receiver_for
            if elapsed % 2 == 0:
                self.assertTrue(receiver.get_status() == neuropil.np_running)
            # if elapsed > 20:
            #     self.assertTrue(np_2.has_joined())
            if StarSetupTest.msg_delivery_succ.value or elapsed > timeout:
                break
            receiver.run(math.pi / 10)
        receiver.shutdown()

    def run_mitm(self):
        np_0 = NeuropilNode(
            4001, log_file="logs/smoke_test_star_n0.log", auto_run=False, n_threads=5
        )
        # np_0_addr = np_0.get_address()
        StarSetupTest.np_0_fp.value = str(np_0.get_fingerprint()).encode()
        # print("{time:.3f} / {node} --> {addr}".format(time=float(time.time()),
        #                                           node=StarSetupTest.np_0_fp.value,
        #                                           addr=StarSetupTest.np_0_addr))
        np_0.run(math.pi / 10)

        t1 = time.time()
        timeout = 120  # sec
        while not self.isOK():
            elapsed = float(time.time() - t1)
            # TODO: remove elapsed > 90 condition after reimplementation of np_has_receiver_for
            if elapsed % 2 == 0:
                self.assertTrue(np_0.get_status() == neuropil.np_running)
            # if elapsed > 20:
            #     self.assertTrue(np_0.has_joined())
            if StarSetupTest.msg_delivery_succ.value or elapsed > timeout:
                break
            np_0.run(math.pi / 10)
        np_0.shutdown()

    def isOK(self):
        return StarSetupTest.send.value and StarSetupTest.msg_delivery_succ.value

    def test_star_setup_delivery(self):
        processes = []
        pm = Process(target=self.run_mitm, args=([]))
        processes.append(pm)
        pm.start()

        time.sleep(1)

        pr = Process(target=self.run_receiver, args=([]))
        processes.append(pr)
        pr.start()

        ps = Process(target=self.run_sender, args=([]))
        processes.append(ps)
        ps.start()

        # Ensure all processes have finished execution
        for p in processes:
            p.join()

        # test our results
        self.assertTrue(StarSetupTest.send.value)
        self.assertTrue(StarSetupTest.msg_delivery_succ.value)


if __name__ == "__main__":
    unittest.main()  # run all tests
