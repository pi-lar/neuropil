# SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

import unittest
import time
import math
from neuropil import neuropil, np_get_id
from neuropil import NeuropilCluster, np_token, np_message

# from neuropil import SEARCH_SERVER, SEARCH_CLIENT, FIXED_SHINGLE_256
from neuropil_search import NeuropilSearchNode, NeuropilSearchCluster
from neuropil_search import np_searchquery, np_searchresult, np_searchentry
from misc import TestHelper
from multiprocessing import Value
from ctypes import c_char, c_bool

import random
import string
import sys


class FrameworkSearchTest(unittest.TestCase):
    bootstrap_node = None
    relay_cluster = None
    search_cluster = None
    private_search_cluster = None
    query_node = None
    inject_node = None
    private_inject_node = None

    def setUp(self):
        # create a set of message relaying nodes to protect privacy of each participant
        if FrameworkSearchTest.relay_cluster is None:
            print(f"setting up relay server", end="\r")
            FrameworkSearchTest.relay_cluster = NeuropilCluster(
                count=5,
                port_range=4010,
                auto_run=False,
                log_file_prefix=f"logs/smoke_test_fwk_search_relay_",
            )
            # WARNING ! never disable authorizations in real environment
            TestHelper.disableAAA(FrameworkSearchTest.relay_cluster).run(0)
            np1_r_node, np1_r_addr = FrameworkSearchTest.relay_cluster.get_address()[0]
            print(f"connecting relay server", end="\r")
            FrameworkSearchTest.relay_cluster.join(np1_r_addr)
            FrameworkSearchTest.relay_cluster.run(20.0)  # run each node 16 seconds
            FrameworkSearchTest.bootstrap_node = np1_r_addr

        # start the query node, so that discovery of index serving nodes starts immediately
        if FrameworkSearchTest.query_node is None:
            print(f"setting up single query node (client only)", end="\r")
            FrameworkSearchTest.query_node = NeuropilSearchNode(
                4040,
                node_type=neuropil.SEARCH_NODE_CLIENT,
                host=b"localhost",
                proto=b"pas4",
                auto_run=False,
                log_file="logs/smoke_test_fwk_search_query.log",
            )
            TestHelper.disableAAA(FrameworkSearchTest.query_node).run(0)
            print(f"connecting single query node", end="\r")
            FrameworkSearchTest.query_node.join(FrameworkSearchTest.bootstrap_node)
            FrameworkSearchTest.query_node.run(20.0)

        # create a search cluster
        if FrameworkSearchTest.search_cluster is None:
            print(f"setting up search cluster", end="\r")
            FrameworkSearchTest.search_cluster = NeuropilSearchCluster(
                node_type=neuropil.SEARCH_NODE_SERVER,
                count=8,
                port_range=4020,
                auto_run=False,
                proto=b"pas4",
                log_file_prefix=f"logs/smoke_test_fwk_search_content_cluster_",
            )
            # WARNING ! never disable authorizations in real environment
            TestHelper.disableAAA(FrameworkSearchTest.search_cluster).run(0)
            print(f"connecting search cluster", end="\r")
            FrameworkSearchTest.search_cluster.join(FrameworkSearchTest.bootstrap_node)
            FrameworkSearchTest.search_cluster.run(
                20.0
            )  # run each node 16 seconds, token refresh is once in a minute
            (
                inject_node,
                search_injection_addr,
            ) = FrameworkSearchTest.search_cluster.get_address()[0]
            FrameworkSearchTest.inject_node = inject_node

        # eventually, you may create private search clusters
        if FrameworkSearchTest.private_search_cluster is None:
            print(f"setting up private search cluster", end="\r")
            private_space = np_get_id(
                to_id="my private search cluster"
            )  # use a seed to create a sub-search-space
            FrameworkSearchTest.private_search_cluster = NeuropilSearchCluster(
                node_type=neuropil.SEARCH_NODE_SERVER,
                search_space=private_space,
                count=2,
                port_range=4030,
                auto_run=False,
                proto=b"pas4",
                log_file_prefix=f"logs/smoke_test_fwk_search_private_cluster_",
            )
            # WARNING ! never disable authorizations in real environment
            TestHelper.disableAAA(FrameworkSearchTest.private_search_cluster).run(0)
            print(f"connecting private search cluster", end="\r")
            FrameworkSearchTest.private_search_cluster.join(
                FrameworkSearchTest.bootstrap_node
            )
            FrameworkSearchTest.private_search_cluster.run(
                20.0
            )  # run each node 40 seconds
            (
                inject_node,
                search_injection_addr,
            ) = FrameworkSearchTest.private_search_cluster.get_address()[0]
            FrameworkSearchTest.private_inject_node = inject_node

        # wait a while to settle initial discovery phase fo peers and search nodes
        timeout = 120  # sec
        t1 = time.time()
        elapsed = 0.0
        while elapsed < timeout:
            elapsed = float(time.time() - t1)
            FrameworkSearchTest.relay_cluster.run(0.01)
            FrameworkSearchTest.search_cluster.run(0.01)
            FrameworkSearchTest.private_search_cluster.run(0.01)
            FrameworkSearchTest.query_node.run(0.01)
            print(f"settling connections {elapsed:.2f}", end="\r")
        print("setUp done")

    def tearDown(self) -> None:
        print("tear down query nodes")
        FrameworkSearchTest.query_node.shutdown()
        print("tear down private search cluster")
        FrameworkSearchTest.private_search_cluster.shutdown()
        print("tear down search cluster")
        FrameworkSearchTest.search_cluster.shutdown()
        print("tear down relay nodes")
        FrameworkSearchTest.relay_cluster.shutdown()

    def _test_search_X_content(
        self,
        search_content=None,
        query_text=None,
        query_probability=0.75,
        **search_attributes,
    ):
        random_id = "".join(
            random.choice(string.ascii_lowercase + string.digits) for _ in range(12)
        )
        # by now all search nodes should be connected, let's add content if available
        # if search_content_file is not None:
        # load our search content into the index
        if search_content is not None and len(search_content) > 0:
            print("adding search content")
            FrameworkSearchTest.inject_node.add_searchentry(
                key=random_id, search_text=search_content, **search_attributes
            )

        if query_text is not None and len(query_text) > 0:
            #     # search for previously loaded text
            print("query search content")
            FrameworkSearchTest.query_node.query(
                key=random_id,
                search_probability=query_probability,
                search_text=query_text,
            )
            FrameworkSearchTest.relay_cluster.run(0.01)
            FrameworkSearchTest.search_cluster.run(0.01)
            FrameworkSearchTest.private_search_cluster.run(0.01)
            FrameworkSearchTest.query_node.run(1.0)

            search_result = FrameworkSearchTest.query_node.get_queryresult(
                key=random_id
            )
            if len(search_result) > 0:
                for result in search_result:
                    print(
                        result.level,
                        result.hit_counter,
                        result.label,
                        result.result_entry,
                    )

        # run all the nodes once
        FrameworkSearchTest.relay_cluster.run(0.1)
        FrameworkSearchTest.search_cluster.run(0.1)
        FrameworkSearchTest.private_search_cluster.run(0.1)
        FrameworkSearchTest.query_node.run(0.1)

    def test_search_simple_content(self):
        # let's insert some text
        search_attributes = {}
        search_attributes["urn"] = "urn://somewhere.lost.in.space"
        search_attributes["title"] = "Ltd. Com. Data Lost in Space"

        self._test_search_X_content(
            search_content="This is a very simple example search text",
            **search_attributes,
        )
        # sleep because the search content needs to "settle"
        time.sleep(5)

        # query for the text
        self._test_search_X_content(
            query_text="This simple example search", query_probability=0.75
        )
        # not found? try with less probability
        self._test_search_X_content(
            query_text="simple example search", query_probability=0.40
        )
        # not found? try with more text
        self._test_search_X_content(
            query_text="This very simple example search text", query_probability=0.40
        )


if __name__ == "__main__":
    fst = FrameworkSearchTest()
    fst.setUp()
    fst.test_search_simple_content()
    fst.tearDown()
