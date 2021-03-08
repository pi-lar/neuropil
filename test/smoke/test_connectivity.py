import unittest
import os
import time
from neuropil import NeuropilNode, NeuropilCluster, neuropil, np_token, np_message
from misc import TestHelper

class ConnectivityTest(unittest.TestCase):
    def test_connectivity(self):
        np_c = NeuropilCluster(    3, port_range=4010, auto_run=False, log_file_prefix="logs/smoke_test_connectivity_cl_")
        np_1 = NeuropilNode(4001, log_file=f"logs/smoke_{os.path.basename(__file__)}_nl1.log", auto_run=False, no_threads=6)
        np_2 = NeuropilNode(4002, log_file=f"logs/smoke_{os.path.basename(__file__)}_nl2.log", auto_run=False)

        TestHelper.disableAAA(np_c).run(0)
        TestHelper.disableAAA(np_1).run(0)
        TestHelper.disableAAA(np_2).run(0)

        np1_addr = np_1.get_address()
        np2_addr = np_2.get_address()

        np_2.join(np1_addr)
        np_c.join(np2_addr)

        timeout = 60 #sec

        t1 = time.time()
        elapsed = 0.
        np_1_joined = False
        np_2_joined = False
        try:
            while elapsed < timeout:
                elapsed = float(time.time() - t1)

                if elapsed % 2 == 0:
                    self.assertTrue(np_1.get_status() == neuropil.np_running)
                    self.assertTrue(np_2.get_status() == neuropil.np_running)
                    for n, s in np_c.get_status():
                        self.assertTrue(s == neuropil.np_running)

                np_1_joined = np_1.has_joined()
                np_2_joined = np_2.has_joined()

                if (np_1_joined and np_2_joined):
                    break
                np_1.run(0.1)

        finally:
            np_1.shutdown()
            np_2.shutdown()
            np_c.shutdown()

        self.assertTrue(np_1_joined)
        self.assertTrue(np_2_joined)