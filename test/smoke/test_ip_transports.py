# SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

import unittest
import time
import math
from neuropil import NeuropilNode, NeuropilCluster, _NeuropilHelper, neuropil, np_token, np_message, np_id
from _neuropil import ffi

import random
from multiprocessing import Process, Value, Array
from ctypes import c_char, c_bool, c_int


class IPTransportTest(unittest.TestCase):
    # test targets
    udp4_connections = Value(c_int, 0)
    udp6_connections = Value(c_int, 0)
    tcp4_connections = Value(c_int, 0)
    tcp6_connections = Value(c_int, 0)
    pas4_connections = Value(c_int, 0)
    pas6_connections = Value(c_int, 0)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @staticmethod
    def authn_allow_all(node:NeuropilNode, token:np_token):

        # print("{node} is authenticating issuer: {subject}".format(node=node.get_fingerprint(), subject=token.subject))

        if (token.subject.find("tcp4")):
            IPTransportTest.tcp4_connections.value += 1
        if (token.subject.find("udp4")):
            IPTransportTest.udp4_connections.value += 1
        if (token.subject.find("tcp6")):
            IPTransportTest.tcp6_connections.value += 1
        if (token.subject.find("udp6")):
            IPTransportTest.udp6_connections.value += 1
        if (token.subject.find("pas4")):
            IPTransportTest.pas4_connections.value += 1
        if (token.subject.find("pas6")):
            IPTransportTest.pas6_connections.value += 1

        return True

    def run_node(self, port, proto, join_to=None):
        timeout = 180 #sec

        node = NeuropilNode(port, log_file="logs/smoke_test_ip_transport_tcp4.log", proto=proto, auto_run=True, n_threads=0)
        node.set_authenticate_cb(IPTransportTest.authn_allow_all)
        if join_to:
            node.join(join_to)
        node.run(0.0)

        t1 = time.time()
        self.assertTrue(node.get_status() == neuropil.np_running)
        while not self.isOK() and node.get_status() == neuropil.np_running:
            elapsed = float(time.time() - t1)
            if elapsed > timeout:
                break
            node.run(0.0)
        node.shutdown()


    def isOK(self):
        return (
            IPTransportTest.udp4_connections.value >= 4 and
            IPTransportTest.udp6_connections.value >= 4 and
            IPTransportTest.tcp4_connections.value >= 4 and
            IPTransportTest.tcp6_connections.value >= 4 and
            IPTransportTest.pas4_connections.value >= 2 and
            IPTransportTest.pas6_connections.value >= 2
        )
    def isOKAssert(self):

        self.assertGreaterEqual(IPTransportTest.udp4_connections.value, 4)
        self.assertGreaterEqual(IPTransportTest.udp6_connections.value, 4)
        self.assertGreaterEqual(IPTransportTest.tcp4_connections.value, 4)
        self.assertGreaterEqual(IPTransportTest.tcp6_connections.value, 4)
        self.assertGreaterEqual(IPTransportTest.pas4_connections.value, 2)
        self.assertGreaterEqual(IPTransportTest.pas6_connections.value, 2)

    def test_ip_transports(self):

        processes = []

        pm = Process(target=self.run_node, args=([4000, "udp4"]))
        processes.append(pm)
        pm.start()

        pm = Process(target=self.run_node, args=([4001, "udp6", b"*:udp4:localhost:4000"]))
        processes.append(pm)
        pm.start()

        pm = Process(target=self.run_node, args=([4002, "tcp4", b"*:udp4:localhost:4000"]))
        processes.append(pm)
        pm.start()

        pm = Process(target=self.run_node, args=([4003, "tcp6", b"*:udp4:localhost:4000"]))
        processes.append(pm)
        pm.start()

        pm = Process(target=self.run_node, args=([4004, "pas4", b"*:udp4:localhost:4000"]))
        processes.append(pm)
        pm.start()

        pm = Process(target=self.run_node, args=([4005, "pas6",  b"*:udp4:localhost:4000"]))
        processes.append(pm)
        pm.start()

        # Ensure all processes have finished execution
        for p in processes:
            p.join()

        # test targets
        self.isOKAssert()

