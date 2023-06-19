# SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

import unittest
import time
import tqdm
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


class PubSubTest32(unittest.TestCase):
    outer_cluster_list = {}
    received = {}
    msg_delivery_succ = 0
    receiver_authz_list = {}
    receiver_authn_list = {}
    receiver_list_complete = 0
    send = False

    progress_bar = None

    @staticmethod
    def authn_allow_cluster(node: NeuropilNode, token: np_token):
        token_id = str(token.get_fingerprint())
        node_id = str(node.get_fingerprint())
        if token_id in PubSubTest32.outer_cluster_list.keys():
            PubSubTest32.receiver_authn_list[node_id] = True
            # print(
            #     f"{node_id[:8]}: r authentication granted to {token_id[:8]} {len(PubSubTest32.receiver_authn_list.keys())}"
            # )
            return True
        return False

    @staticmethod
    def authn_outer_cluster(node: NeuropilNode, token: np_token):
        token_id = str(token.get_fingerprint())
        node_id = str(node.get_fingerprint())
        # PubSubTest32.inner_cluster_list[token_id] = True
        PubSubTest32.outer_cluster_list[node_id] = True
        # print(
        #     f"{node_id[:8]}: co authentication granted to {token_id[:8]} {len(PubSubTest32.outer_cluster_list.keys())} "
        # )
        # )
        return True

    @staticmethod
    def authz_r_allow_all(node: NeuropilNode, token: np_token):
        # print ("{time:.3f} / {node}: 1 authorization granted to token {fp} / {issuer}".format(time=float(time.time()), node=node.get_fingerprint(), fp=np_id(id), issuer=token.issuer ))
        return True

    @staticmethod
    def authz_s_allow_all(node: NeuropilNode, token: np_token):
        node_id = str(node.get_fingerprint())
        token_id = str(token.get_fingerprint())
        issuer = str(token.issuer)

        PubSubTest32.receiver_authz_list[token_id] = True
        PubSubTest32.receiver_list_complete = len(PubSubTest32.receiver_authz_list)
        return True

    @staticmethod
    def msg_received(node: NeuropilNode, message: np_message):
        node_id = str(node.get_fingerprint())

        # print ("{time:.3f} / {node}: 2 msg received from {sender}".format(time=float(time.time()), node=node.get_fingerprint(), sender=message.__getattribute__('from')))
        PubSubTest32.received[node_id] = True
        PubSubTest32.msg_delivery_succ = len(PubSubTest32.received)
        PubSubTest32.progress_bar.set_description_str(
            f"received message at {PubSubTest32.msg_delivery_succ} receivers"
        )
        return True

    def run_pub_sub_32(self, cluster_size, receiver_size):
        total = 8
        PubSubTest32.received.clear()
        PubSubTest32.outer_cluster_list.clear()
        PubSubTest32.receiver_authn_list.clear()
        PubSubTest32.receiver_authz_list.clear()

        PubSubTest32.send = False
        PubSubTest32.msg_delivery_succ = 0
        PubSubTest32.receiver_list_complete = 0

        PubSubTest32.progress_bar = tqdm.tqdm(total=total)

        PubSubTest32.progress_bar.set_description_str("initializing nodes")
        outer_cluster_size = cluster_size
        np_o_c = NeuropilCluster(
            outer_cluster_size,
            port_range=5550,
            auto_run=False,
            log_file_prefix=f"logs/smoke_test_pubsub_{receiver_size}_cl_o_",
            n_threads=1,
        )
        rc = NeuropilCluster(
            receiver_size,
            5600,
            proto="pas4",
            log_file_prefix=f"logs/smoke_test_pubsub_{receiver_size}_r_",
            auto_run=False,
            n_threads=1,
        )
        np_s1 = NeuropilNode(
            5700,
            proto="pas4",
            log_file=f"logs/smoke_test_pubsub_{receiver_size}_s1.log",
            auto_run=False,
            n_threads=1,
        )
        PubSubTest32.progress_bar.update()

        PubSubTest32.progress_bar.set_description_str("set up data channel")
        subject = b"NP.TEST.pubsub.32"
        r_mxp = rc.get_mx_properties(subject)
        for node, mxp in r_mxp:
            mxp.ackmode = neuropil.NP_MX_ACK_NONE
            mxp.max_retry = 3
            mxp.intent_ttl = 6000
            mxp.intent_update_after = 19
            mxp.role = neuropil.NP_MX_CONSUMER
            mxp.apply()

            node.run(0.1)

        rc.set_receive_cb(subject, self.msg_received)

        mxp = np_s1.get_mx_properties(subject)
        mxp.ackmode = neuropil.NP_MX_ACK_NONE
        mxp.max_retry = 3
        mxp.intent_ttl = 6000
        mxp.intent_update_after = 19
        mxp.role = neuropil.NP_MX_PROVIDER
        mxp.apply()
        PubSubTest32.progress_bar.update()

        PubSubTest32.progress_bar.set_description_str("set up access rights")
        np_o_c.set_authenticate_cb(PubSubTest32.authn_outer_cluster)
        np_o_c.run(0)

        rc.set_authenticate_cb(PubSubTest32.authn_allow_cluster)
        rc.set_authorize_cb(PubSubTest32.authz_r_allow_all)
        rc.run(0)

        np_s1.set_authenticate_cb(PubSubTest32.authn_allow_cluster)
        np_s1.set_authorize_cb(PubSubTest32.authz_s_allow_all)
        np_s1.run(0)
        PubSubTest32.progress_bar.update()

        cluster_addresses = np_o_c.get_address()

        PubSubTest32.progress_bar.set_description_str(
            f"connecting {cluster_size} cluster nodes"
        )

        for i in range(0, cluster_size):
            np_o_c.join(cluster_addresses[i][1])

        setup_elapsed = time.time()
        while (time.time() - setup_elapsed) <= 60.0:
            np_o_c.run(0.0)
        PubSubTest32.progress_bar.update()

        PubSubTest32.progress_bar.set_description_str(
            f"connecting {receiver_size} receiver and sender nodes"
        )
        for i in range(0, cluster_size):
            rc.join(cluster_addresses[i][1])
            np_s1.join(cluster_addresses[i][1])
            np_s1.run(0.02)
            rc.run(0.25)

        setup_elapsed = time.time()
        while (time.time() - setup_elapsed) <= 160.0:
            rc.run(0.0)
            np_o_c.run(0.0)

        PubSubTest32.progress_bar.update()

        t1 = time.time()
        timeout = 300  # sec
        try:
            PubSubTest32.progress_bar.set_description_str(
                f"waiting for all receiver {PubSubTest32.receiver_list_complete} / {receiver_size}"
            )
            while PubSubTest32.msg_delivery_succ < receiver_size:
                elapsed = float(time.time() - t1)

                if not np_s1.np_has_receiver_for(subject):
                    PubSubTest32.progress_bar.update()
                else:
                    if (
                        PubSubTest32.receiver_list_complete == receiver_size
                        and not PubSubTest32.send
                    ):
                        np_s1.send(subject, b"test")
                        PubSubTest32.send = True
                        PubSubTest32.progress_bar.set_description_str(
                            "send single message to all receivers"
                        )
                        PubSubTest32.progress_bar.update()

                if not PubSubTest32.send:
                    PubSubTest32.progress_bar.set_description_str(
                        f"waiting for all receiver {PubSubTest32.receiver_list_complete} / {receiver_size}"
                    )

                if elapsed > timeout:
                    PubSubTest32.progress_bar.update()
                    break

                rc.run(0.0)
                np_s1.run(0.1)
                # PubSubTest32.progress_bar.refresh()
        finally:
            PubSubTest32.progress_bar.set_description_str(
                "cleanup started", refresh=True
            )
            np_s1.shutdown(False)
            rc.shutdown(False)
            np_o_c.shutdown(False)
            PubSubTest32.progress_bar.update()

        self.assertTrue(True == PubSubTest32.send)
        self.assertTrue(receiver_size == PubSubTest32.msg_delivery_succ)

        PubSubTest32.progress_bar.close()

    # def test_pub_sub_07(self):
    #     self.run_pub_sub_32(2, 7)

    # def test_pub_sub_11(self):
    #     self.run_pub_sub_32(3, 11)

    # def test_pub_sub_17(self):
    #     self.run_pub_sub_32(5, 17)

    # def test_pub_sub_23(self):
    #     self.run_pub_sub_32(7, 23)

    def test_pub_sub_32(self):
        self.run_pub_sub_32(11, 32)

    def tearDown(self):
        pass
        # self.assertTrue(True == PubSubTest32.send)
        # self.assertTrue(32 == PubSubTest32.msg_delivery_succ)


if __name__ == "__main__":
    x = PubSubTest32()
    x.run_pub_sub_32(2, 7)

    x.run_pub_sub_32(3, 11)
    # PubSubTest32.progress_bar.reset()x
    # x.run_pub_sub_32(2, 13)
    # PubSubTest32.progress_bar.reset()
    x.run_pub_sub_32(4, 17)

    x.run_pub_sub_32(5, 23)

    x.run_pub_sub_32(6, 32)
    # PubSubTest32.progress_bar.reset()
    # x.run_pub_sub_32(4, 31)
