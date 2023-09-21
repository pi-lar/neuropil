# SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

import unittest
import time
import math
from neuropil import (
    NeuropilNode,
    NeuropilCluster,
    neuropil,
    np_token,
    np_message,
    np_id,
    _NeuropilHelper,
)
from _neuropil import ffi
from misc import TestHelper

from ctypes import c_char, c_bool


class PubSubTest(unittest.TestCase):
    np_c_fp = []
    received = {}
    pubsub_nodes = {}
    pubsub_nodes_length = 0
    msg_delivery_succ = 0
    send = False

    @staticmethod
    def authn_allow_cluster(node: NeuropilNode, token: np_token):
        token_id = token.get_fingerprint(False)
        for node_obj, node_fp in PubSubTest.np_c_fp:
            if str(token_id) == str(node_fp):
                # print ("{time:.3f} / {node}: 1 authentication granted to {fp}".format(time=float(time.time()), node=node.get_fingerprint(), fp=np_id(id) ))
                return True
            if str(node.get_fingerprint()) == str(node_fp):
                # print ("{time:.3f} / {node}: 2 authentication granted to {fp}".format(time=float(time.time()), node=node.get_fingerprint(), fp=np_id(id) ))
                return True
        # print ("{time:.3f} / {node}: 3 authentication NOT granted to {fp}".format(time=float(time.time()), node=node.get_fingerprint(), fp=token_id ))
        return False

    @staticmethod
    def authz_allow_all(node: NeuropilNode, token: np_token):
        token_fp = token.get_fingerprint(False)
        PubSubTest.pubsub_nodes[str(token_fp)] = True
        PubSubTest.pubsub_nodes_length = len(PubSubTest.pubsub_nodes.keys())

        # print ("{time:.3f} / {node}: 1 authorization granted to token {fp} / {issuer}".format(time=float(time.time()), node=node.get_fingerprint(), fp=np_id(id), issuer=token.issuer ))
        return True

    @staticmethod
    def msg_received(node: NeuropilNode, message: np_message):
        # print ("{time:.3f} / {node}: 2 msg received from {sender}".format(time=float(time.time()), node=node.get_fingerprint(), sender=message.__getattribute__('from')))
        PubSubTest.received[str(node.get_fingerprint())] = True
        PubSubTest.msg_delivery_succ = len(PubSubTest.received.keys())
        return True

    def test_pub_sub(self):
        np_c = NeuropilCluster(
            7,
            port_range=5500,
            auto_run=False,
            log_file_prefix="logs/smoke_test_pubsub_cl_",
            n_threads=4,
        )
        np_r1 = NeuropilNode(
            5510, log_file="logs/smoke_test_pubsub_r1.log", auto_run=False, n_threads=4
        )
        np_r2 = NeuropilNode(
            5511, log_file="logs/smoke_test_pubsub_r2.log", auto_run=False, n_threads=4
        )
        np_s1 = NeuropilNode(
            5512, log_file="logs/smoke_test_pubsub_s1.log", auto_run=False, n_threads=4
        )

        subject = b"NP.TEST.pubsub.1"

        mxp = np_r1.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.max_retry = 3
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.role = neuropil.NP_MX_CONSUMER
        mxp.apply()
        np_r1.set_receive_cb(subject, self.msg_received)

        mxp = np_r2.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.role = neuropil.NP_MX_CONSUMER
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.apply()
        np_r2.set_receive_cb(subject, self.msg_received)

        mxp = np_s1.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_DESTINATION
        mxp.role = neuropil.NP_MX_PROVIDER
        mxp.intent_ttl = 300
        mxp.intent_update_after = 20
        mxp.apply()

        np_c.set_authenticate_cb(TestHelper.authn_allow_all)
        # np_c.set_authorize_cb(TestHelper.authz_allow_all)
        np_c.set_accounting_cb(TestHelper.acc_allow_all)
        np_c.run(0)
        np_r1.set_authenticate_cb(PubSubTest.authn_allow_cluster)
        np_r1.set_authorize_cb(PubSubTest.authz_allow_all)
        np_r1.set_accounting_cb(TestHelper.acc_allow_all)
        np_r1.run(0)

        np_r2.set_authenticate_cb(PubSubTest.authn_allow_cluster)
        np_r2.set_authorize_cb(PubSubTest.authz_allow_all)
        np_r2.set_accounting_cb(TestHelper.acc_allow_all)
        np_r2.run(0)

        np_s1.set_authenticate_cb(PubSubTest.authn_allow_cluster)
        np_s1.set_authorize_cb(PubSubTest.authz_allow_all)
        np_s1.set_accounting_cb(TestHelper.acc_allow_all)
        np_s1.run(0)

        PubSubTest.np_c_fp = np_c.get_fingerprint()

        nps1_addr = np_s1.get_address()
        npr1_addr = np_r1.get_address()
        npr2_addr = np_r2.get_address()

        np_c.join(npr1_addr)
        np_c.join(npr2_addr)
        np_c.join(nps1_addr)

        t1 = time.time()
        timeout = 150  # sec
        try:
            while PubSubTest.msg_delivery_succ < 2:
                if np_s1.np_has_receiver_for(subject):
                    if not PubSubTest.send and PubSubTest.pubsub_nodes_length == 3:
                        # print ("{time:.3f} / {node}: 2 sending message".format(time=float(time.time()), node=np_s1.get_fingerprint() ) )
                        np_s1.send(subject, b"test")
                        PubSubTest.send = True

                elapsed = float(time.time() - t1)
                if elapsed > timeout:
                    break

                np_c.run(math.pi / 100)

        finally:
            np_s1.shutdown(False)
            np_r1.shutdown(False)
            np_r2.shutdown(False)
            np_c.shutdown(False)

    def tearDown(self):
        self.assertTrue(True == PubSubTest.send)
        self.assertTrue(2 == PubSubTest.msg_delivery_succ)
