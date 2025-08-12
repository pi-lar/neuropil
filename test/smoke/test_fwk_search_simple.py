# SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

import unittest
import time
import math

from neuropil import neuropil
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

    search_node = None

    def setUp(self):
        if FrameworkSearchTest.search_node is None:
            print(f"setting up single search node (client/server)", end="\r")
            FrameworkSearchTest.search_node = NeuropilSearchNode(
                4030,
                host=b"localhost",
                proto=b"udp4",
                auto_run=False,
                log_file="logs/smoke_test_fwk_search_query.log",
                node_type=neuropil.SEARCH_NODE_SERVER,
            )
            TestHelper.disableAAA(FrameworkSearchTest.search_node).run(0)
            print(f"connecting search client", end="\r")
            # FrameworkSearchTest.query_node.join(FrameworkSearchTest.bootstrap_node)

        # wait a while to settle initial discovery phase fo peers and search nodes
        FrameworkSearchTest.search_node.run(0.0)
        print("setUp done")

    def tearDown(self) -> None:
        FrameworkSearchTest.search_node.shutdown()
        return super().tearDown()

    def _test_search_X_content(
        self,
        search_content=None,
        query_text=None,
        query_probability=0.75,
        **search_attributes,
    ):

        if search_content is not None and len(search_content) > 0:
            # insert some text
            FrameworkSearchTest.search_node.add_searchentry(
                key="some_random_id", search_text=search_content, **search_attributes
            )

        if query_text is not None and len(query_text) > 0:
            # search for previously loaded text
            FrameworkSearchTest.search_node.query(
                key="other_random_id",
                search_probability=query_probability,
                search_text=query_text,
            )
            time.sleep(1)
            search_result = FrameworkSearchTest.search_node.get_queryresult(
                key="other_random_id"
            )
            if len(search_result) > 0:
                for result in search_result:
                    print(
                        result.level,
                        result.hit_counter,
                        result.label,
                        result.result_entry,
                    )

    def test_search_simple_content(self):
        # let's insert some text
        search_attributes = {}
        search_attributes["urn"] = "urn://somewhere.lost.in.space"
        search_attributes["title"] = "Ltd. Com. Data Lost in Space"
        self._test_search_X_content(
            search_content="This is a very simple example search text",
            **search_attributes,
        )

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
