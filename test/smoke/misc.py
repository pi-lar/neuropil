# SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

from neuropil import NeuropilNode, NeuropilCluster, neuropil, np_token, np_message
from neuropil_search import NeuropilSearchCluster


class TestHelper:
    @staticmethod
    def authn_allow_all(node: NeuropilNode, token: np_token):
        # print("{node}: {type}: {token} {id}".format(node=node.get_fingerprint(), type="authn", token=token.subject, id=token.get_fingerprint()))
        return True

    @staticmethod
    def authz_allow_all(node: NeuropilNode, token: np_token):
        # print("{node}: {type}: {token} {id}".format(node=node.get_fingerprint(),type="authz", token=token.subject, id=token.get_fingerprint()))
        return True

    @staticmethod
    def acc_allow_all(node: NeuropilNode, token: np_token):
        # print("{node}: {type}: {token}".format(node=node.get_fingerprint(), type="acc", token=token.subject))
        return True

    @staticmethod
    def disableAAA(node: NeuropilNode):
        node.set_authenticate_cb(TestHelper.authn_allow_all)
        node.set_authorize_cb(TestHelper.authz_allow_all)
        node.set_accounting_cb(TestHelper.acc_allow_all)
        return node

    @staticmethod
    def disableAAA(search_cluster: NeuropilSearchCluster):
        search_cluster.set_authenticate_cb(TestHelper.authn_allow_all)
        search_cluster.set_authorize_cb(TestHelper.authz_allow_all)
        search_cluster.set_accounting_cb(TestHelper.acc_allow_all)
        return search_cluster
