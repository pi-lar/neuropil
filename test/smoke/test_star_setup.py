# SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

import unittest
import time
import math
from neuropil import (
    NeuropilNode,
    _NeuropilHelper,
    neuropil,
    np_token,
    np_message,
    np_id,
)
from _neuropil import ffi


class StarSetupTest(unittest.TestCase):
    # common class variables for each process
    np_0_addr = b"*:udp4:localhost:4001"
    subject = b"urn:np:test:subject:1"
    np_0_fp = b"de19bde3dc1aaaf4b196d1c0941c2fbe1478649367c710062586825c76673da1"

    # test targets
    msg_delivery_succ = False
    send = False

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @staticmethod
    def msg_received(node: NeuropilNode, message: np_message):
        StarSetupTest.msg_delivery_succ = True
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

        if str(np_id(_id)) == StarSetupTest.np_0_fp.decode():
            print (f"{float(time.time()):.3f} / {node.get_fingerprint()}: S authentication granted to {np_id(_id)}")
            return True
        else:
            print (f"{float(time.time()):.3f} / {node.get_fingerprint()}: S authentication reject  to {np_id(_id)}")
            return False

    @staticmethod
    def authz_allow_all(node: NeuropilNode, token: np_token):
        # print ("{time:.3f} / authorization granted to {issuer} / {fp} for {subject}".format(time=float(time.time()), issuer=token.issuer, fp=token.get_fingerprint(), subject=token.subject))
        return True

    def test_star_setup_delivery(self):
        # start the relay
        np_0 = NeuropilNode(
            4001, log_file="logs/smoke_test_star_n0.log", auto_run=False, n_threads=5
        )
        StarSetupTest.np_0_fp = str(np_0.get_fingerprint()).encode()
        np_0.run(0)

        # start the sender
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

        # start the receiver
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

        sender.join(StarSetupTest.np_0_addr)
        receiver.join(StarSetupTest.np_0_addr)

        np_0.run(0)
        receiver.run(0)
        sender.run(0)

        t1 = time.time()
        timeout = 120  # sec
        while not self.isOK():
            elapsed = float(time.time() - t1)
            # TODO: remove elapsed > 90 condition after re-implementation of np_has_receiver_for
            if elapsed % 2 == 0:
                self.assertTrue(sender.get_status() == neuropil.np_running)

            if (
                sender.np_has_receiver_for(StarSetupTest.subject)
                and not StarSetupTest.send
            ):
                sender.send(StarSetupTest.subject, b"test data blob")
                StarSetupTest.send = True

            if StarSetupTest.msg_delivery_succ or elapsed > timeout:
                break

            sender.run(math.pi / 100)
            receiver.run(math.pi / 100)
            np_0.run(math.pi / 100)

        sender.shutdown()
        receiver.shutdown()
        np_0.shutdown()

        # test our results
        self.assertTrue(StarSetupTest.send)
        self.assertTrue(StarSetupTest.msg_delivery_succ)

    def isOK(self):
        return StarSetupTest.send and StarSetupTest.msg_delivery_succ


if __name__ == "__main__":
    unittest.main()  # run all tests
