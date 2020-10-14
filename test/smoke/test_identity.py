import unittest
import time
from neuropil import NeuropilNode, NeuropilCluster, neuropil, np_token, np_message
from misc import TestHelper
np_1_ident = None
np_2_ident = None
check_np_1_ident_ok = False
check_np_2_ident_ok = False

class IdentityTest(unittest.TestCase):
    @staticmethod
    def check_ident(token:np_token, node:NeuropilNode, incomming_token:np_token):
        incomming_fp = str(incomming_token.get_fingerprint())
        fp = str(token.get_fingerprint())
        #print(f"\ncurrent node: {node.get_fingerprint()}"
        #      f"\nincomming id: {incomming_fp} / {incomming_token.uuid}"
        #      f"\n  compare id: {fp} / {token.uuid}"
        #      f"\ncmp: {incomming_fp == fp}"
        #      )
        return incomming_fp == fp

    @staticmethod
    def authz_allow_all_check_ident_1(node:NeuropilNode,token:np_token):
        global np_1_ident
        global check_np_1_ident_ok
        check_np_1_ident_ok = IdentityTest.check_ident(np_1_ident, node,token)
        return check_np_1_ident_ok

    @staticmethod
    def authz_allow_all_check_ident_2(node:NeuropilNode,token:np_token):
        global np_2_ident
        global check_np_2_ident_ok
        check_np_2_ident_ok = IdentityTest.check_ident(np_2_ident, node,token)
        return check_np_2_ident_ok

    def test_identity(self):
        global np_1_ident
        global np_2_ident
        global check_np_1_ident_ok
        global check_np_2_ident_ok

        np_1 = NeuropilNode(4001, log_file="logs/smoke_test_identity_nl1.log", auto_run=False, no_threads=6)
        np_2 = NeuropilNode(4002, log_file="logs/smoke_test_identity_nl2.log", auto_run=False)

        np_2_ident = np_2.new_identity()
        np_2.use_identity(np_2_ident)
        TestHelper.disableAAA(np_2)
        np_2.set_authenticate_cb(IdentityTest.authz_allow_all_check_ident_1)
        np_2.run(0)

        np_1_ident = np_1.new_identity()
        np_1.use_identity(np_1_ident)
        TestHelper.disableAAA(np_1)
        np_1.set_authenticate_cb(IdentityTest.authz_allow_all_check_ident_2)
        np_1.run(0)
        #print("")
        #print(f"Node 1 fp: {np_1_ident.get_fingerprint()} / {np_1_ident.uuid} on {np_1.get_fingerprint()} ")
        #print(f"Node 2 fp: {np_2_ident.get_fingerprint()} / {np_2_ident.uuid} on {np_2.get_fingerprint()} ")
        np1_addr = np_1.get_address()
        np2_addr = np_2.get_address()

        np_2.join(np1_addr)
        np_1.join(np2_addr)

        timeout = 60 #sec

        t1 = time.time()
        elapsed = 0.
        try:
            while elapsed < timeout:
                elapsed = float(time.time() - t1)

                if elapsed % 2 == 0:
                    self.assertTrue(np_1.get_status() == neuropil.np_running)
                    self.assertTrue(np_2.get_status() == neuropil.np_running)

                if check_np_1_ident_ok and check_np_2_ident_ok:
                    break
                np_1.run(0.1)
                np_2.run(0.1)
        finally:
            np_1.shutdown()
            np_2.shutdown()

        self.assertTrue(check_np_1_ident_ok)
        self.assertTrue(check_np_2_ident_ok)