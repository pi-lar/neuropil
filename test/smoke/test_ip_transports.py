import unittest
import time 
import math
from neuropil import NeuropilNode, NeuropilCluster, _NeuropilHelper, neuropil, np_token, np_message, np_id
from _neuropil import ffi

import random
from multiprocessing import Process, Value, Array
from ctypes import c_char, c_bool, c_int


class IPTransportTest(unittest.TestCase):
    
    # common class variables for each process
    np_0_addr = b"*:tcp4:localhost:4444"
    np_1_addr = b"*:udp4:localhost:5555"
    np_2_addr = b"*:tcp6:localhost:6666"
    np_3_addr = b"*:udp6:localhost:7777"
    np_4_addr = b"*:pas4:localhost:8888"
    np_5_addr = b"*:pas6:localhost:9999"

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

        if (token.subject.find("tcp4:localhost:4444")):
            IPTransportTest.tcp4_connections.value += 1
        if (token.subject.find("udp4:localhost:5555")):
            IPTransportTest.udp4_connections.value += 1
        if (token.subject.find("tcp6:localhost:6666")):
            IPTransportTest.tcp6_connections.value += 1
        if (token.subject.find("udp6:localhost:7777")):
            IPTransportTest.udp6_connections.value += 1
        if (token.subject.find("pas4:localhost")):
            IPTransportTest.pas4_connections.value += 1
        if (token.subject.find("pas6:localhost")):
            IPTransportTest.pas6_connections.value += 1

        return True

    def run_tcp4(self):
        np_0 = NeuropilNode(4444, log_file="logs/smoke_test_ip_transport_tcp4.log", auto_run=False, n_threads=5)
        np_0.set_authenticate_cb(IPTransportTest.authn_allow_all)
        # print("{time:.3f} / {node} --> {addr}".format(time=float(time.time()), 
        #                                           node=IPTransportTest.np_0_fp.value, 
        #                                           addr=IPTransportTest.np_0_addr))
        np_0.join(IPTransportTest.np_1_addr)
        np_0.run(math.pi/10)

        t1 = time.time()
        timeout = 120 #sec
        while True:
            elapsed = float(time.time() - t1)
            if elapsed % 2 == 0:
                self.assertTrue(np_0.get_status() == neuropil.np_running)
            if elapsed > timeout:
                break
            np_0.run(math.pi/10)
        np_0.shutdown()

    def run_tcp6(self):
        np_2 = NeuropilNode(6666, log_file="logs/smoke_test_ip_transport_tcp6.log", auto_run=False, n_threads=5)
        np_2.set_authenticate_cb(IPTransportTest.authn_allow_all)
        # print("{time:.3f} / {node} --> {addr}".format(time=float(time.time()), 
        #                                           node=IPTransportTest.np_0_fp.value, 
        #                                           addr=IPTransportTest.np_0_addr))
        np_2.join(IPTransportTest.np_1_addr)
        np_2.run(math.pi/10)

        t1 = time.time()
        timeout = 120 #sec
        while True:
            elapsed = float(time.time() - t1)
            if elapsed % 2 == 0:
                self.assertTrue(np_2.get_status() == neuropil.np_running)
            if elapsed > timeout:
                break
            np_2.run(math.pi/10)
        np_2.shutdown()

    def run_udp4(self):
        np_1 = NeuropilNode(5555, log_file="logs/smoke_test_ip_transport_udp4.log", auto_run=False, n_threads=5)
        np_1.set_authenticate_cb(IPTransportTest.authn_allow_all)
        # print("{time:.3f} / {node} --> {addr}".format(time=float(time.time()), 
        #                                           node=IPTransportTest.np_0_fp.value, 
        #                                           addr=IPTransportTest.np_0_addr))
        np_1.run(math.pi/10)

        t1 = time.time()
        timeout = 120 #sec
        while True:
            elapsed = float(time.time() - t1)
            if elapsed % 2 == 0:
                self.assertTrue(np_1.get_status() == neuropil.np_running)
            if elapsed > timeout:
                break
            np_1.run(math.pi/10)
        np_1.shutdown()

    def run_udp6(self):
        np_3 = NeuropilNode(7777, log_file="logs/smoke_test_ip_transport_udp6.log", auto_run=False, n_threads=5)
        np_3.set_authenticate_cb(IPTransportTest.authn_allow_all)
        # print("{time:.3f} / {node} --> {addr}".format(time=float(time.time()), 
        #                                           node=IPTransportTest.np_0_fp.value, 
        #                                           addr=IPTransportTest.np_0_addr))
        np_3.join(IPTransportTest.np_1_addr)
        np_3.run(math.pi/10)

        t1 = time.time()
        timeout = 120 #sec
        while True:
            elapsed = float(time.time() - t1)
            if elapsed % 2 == 0:
                self.assertTrue(np_3.get_status() == neuropil.np_running)
            if elapsed > timeout:
                break
            np_3.run(math.pi/10)
        np_3.shutdown()

    def run_pas4(self):
        np_4 = NeuropilNode(8888, log_file="logs/smoke_test_ip_transport_pas4.log", proto="pas4", auto_run=False, n_threads=5)
        np_4.set_authenticate_cb(IPTransportTest.authn_allow_all)
        # print("{time:.3f} / {node} --> {addr}".format(time=float(time.time()), 
        #                                           node=IPTransportTest.np_0_fp.value, 
        #                                           addr=IPTransportTest.np_0_addr))
        np_4.join(IPTransportTest.np_1_addr)
        np_4.run(math.pi/10)

        t1 = time.time()
        timeout = 120 #sec
        while True:
            elapsed = float(time.time() - t1)
            if elapsed % 2 == 0:
                self.assertTrue(np_4.get_status() == neuropil.np_running)
            if elapsed > timeout:
                break
            np_4.run(math.pi/10)
        np_4.shutdown()

    def run_pas6(self):
        np_5 = NeuropilNode(9999, log_file="logs/smoke_test_ip_transport_pas6.log", proto="pas6", auto_run=False, n_threads=5)
        np_5.set_authenticate_cb(IPTransportTest.authn_allow_all)
        # print("{time:.3f} / {node} --> {addr}".format(time=float(time.time()), 
        #                                           node=IPTransportTest.np_0_fp.value, 
        #                                           addr=IPTransportTest.np_0_addr))
        np_5.join(IPTransportTest.np_1_addr)
        np_5.run(math.pi/10)

        t1 = time.time()
        timeout = 120 #sec
        while True:
            elapsed = float(time.time() - t1)
            if elapsed % 2 == 0:
                self.assertTrue(np_5.get_status() == neuropil.np_running)
            if elapsed > timeout:
                break
            np_5.run(math.pi/10)
        np_5.shutdown()


    def test_ip_transports(self):

        processes = []
        pm = Process(target=self.run_udp4,args=([]))
        processes.append(pm)
        pm.start()
        pm = Process(target=self.run_udp6,args=([]))
        processes.append(pm)
        pm.start()

        pm = Process(target=self.run_tcp4,args=([]))
        processes.append(pm)
        pm.start()
        pm = Process(target=self.run_tcp6,args=([]))
        processes.append(pm)
        pm.start()

        pm = Process(target=self.run_pas4,args=([]))
        processes.append(pm)
        pm.start()
        pm = Process(target=self.run_pas6,args=([]))
        processes.append(pm)
        pm.start()

        # Ensure all processes have finished execution
        for p in processes:
            p.join()

        # test targets
        self.assertTrue(IPTransportTest.udp4_connections.value >= 4)# = Value(c_int, 0)
        self.assertTrue(IPTransportTest.udp6_connections.value >= 4)# = Value(c_int, 0)
        self.assertTrue(IPTransportTest.tcp4_connections.value >= 4)# = Value(c_int, 0)
        self.assertTrue(IPTransportTest.tcp6_connections.value >= 4)# = Value(c_int, 0)
        self.assertTrue(IPTransportTest.pas4_connections.value >= 2)# = Value(c_int, 0)
        self.assertTrue(IPTransportTest.pas6_connections.value >= 2)# = Value(c_int, 0)

