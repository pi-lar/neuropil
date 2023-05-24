import os
import unittest
import time
from neuropil import NeuropilNode, NeuropilCluster, neuropil, np_token, np_message
from misc import TestHelper

attribute_found = [False, False, False, False]


class IdentityAttributeTest(unittest.TestCase):
    @staticmethod
    def check_attribute(node: NeuropilNode, token: np_token):
        global attribute_found
        for i in range(1, 5):
            data = token.get_attr_bin(f"{i}TEST")
            if data.decode("utf-8") == f"LOREM IPSUM{i}":
                attribute_found[i - 1] = True

        return any(attribute_found)

    def test_connect(self):
        global attribute_found

        np_1 = NeuropilNode(
            4001,
            log_file=f"logs/smoke_{os.path.basename(__file__)}_nl1.log",
            auto_run=False,
            n_threads=0,
        )
        np_2 = NeuropilNode(
            4002,
            log_file=f"logs/smoke_{os.path.basename(__file__)}_nl2.log",
            auto_run=False,
            n_threads=0,
        )

        ident = np_1.new_identity()
        ident.set_attr_bin("1TEST", b"LOREM IPSUM1")
        np_1.use_identity(ident)
        np_1.set_attr_bin(
            "2TEST", b"LOREM IPSUM2", inheritance=neuropil.NP_ATTR_IDENTITY
        )
        np_1.set_attr_bin(
            "3TEST", b"LOREM IPSUM3", inheritance=neuropil.NP_ATTR_IDENTITY_AND_USER_MSG
        )
        np_1.set_attr_bin(
            "4TEST", b"LOREM IPSUM4", inheritance=neuropil.NP_ATTR_INTENT_AND_IDENTITY
        )

        np_2.set_authenticate_cb(IdentityAttributeTest.check_attribute)
        # np_2.set_authorize_cb(IdentityAttributeTest.check_attribute)
        # np_2.set_accounting_cb(IdentityAttributeTest.check_attribute)

        TestHelper.disableAAA(np_1)

        np_1.run(0)
        np_2.run(0)

        np1_addr = np_1.get_address()
        np2_addr = np_2.get_address()

        # print(f"Connecting to {np2_addr}")
        np_1.join(np2_addr)
        timeout = 120  # sec

        t1 = time.time()
        elapsed = 0.0
        try:
            while elapsed < timeout:
                elapsed = float(time.time() - t1)

                np_1.run(0.01)
                np_2.run(0.01)

                if all(attribute_found):
                    break

        finally:
            np_1.shutdown()
            np_2.shutdown()

        for i in range(1, 5):
            self.assertTrue(attribute_found[i - 1], f"attribute {i} not found")
