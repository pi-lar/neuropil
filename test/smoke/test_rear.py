# SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

import json
import time
import unittest
import logging
import sys
import random
import string

from datetime import datetime

from rear_models.node_identity import NodeIdentity
from rear_models.additional_information import AdditionalInformation
from rear_models.flavor import Flavor, Location, FlavourType, Owner, Price, Name
from rear_models.k8slice import (
    NetworkAuthorizations,
    K8SliceSchema as K8SSchema,
    Properties,
    Characteristics,
    Policies,
    Partitionability,
)


from neuropil import (
    NeuropilNode,
    NeuropilCluster,
    NeuropilException,
    _NeuropilHelper,
    neuropil,
    np_token,
    np_message,
    np_id,
    np_subject,
)
from _neuropil import ffi


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s __ %(levelname)s __ %(message)s"
)
logger = logging.getLogger(__name__)

# This is a smoke tests of the neuropil cybersecurity mesh. It simulates the message exchange of REAR (REsource Advertisement and Reservation)
# specific messages and shows how the different data types can be exchanged. It is not meant to be complete, but is rather work in progress.
#
# This smoke test is part of the fluidos project (www.fluidos.eu) and serves as a proof of concept that the need messages can be exchanged.
# The main difference between the current REAR data exchange and the example in this file is the switch to the publish subscribe pattern
#
# In the initial phase the fluidos needs to exchange DID information about available clusters (run_fluidos_discovery)
# As a followup the different Fluidos Nodes exchange information about "flavours". Here the publish-subscribe protocol delivers a benefit for all participants
# In the last phase the REAR messages are used to create a contract and a reservation.

# message subject being used in the following code
fluidos_node_discovery_v01 = "urn:eu:fluidos:node:discovery:v0.1"
fluidos_flavor_discovery_v01 = (
    "urn:eu:fluidos:flavor:discovery:v0.1"  # hash xor'ed with node fingerprint
)
fluidos_flavor_update_v01 = (
    "urn:eu:fluidos:flavor:update:v0.1"  # used to send telemetry data?
)

# data objects being used in the following code
fluidos_node_identity_v01 = "eu:fluidos:node:identity:v0.1"
fluidos_node_flavor_v01 = "eu:fluidos:node:flavor:v0.1"


class REARSetupTest(unittest.TestCase):

    # set up some attributes to filter other fluidos nodes
    countries = ["Italy", "Spain", "France", "Germany", "Czech Republic", "Poland"]
    license = ["Apache2.0", "OSL3.0", "GPL3.0", "LGPL2.0", "MPL", "BSD2.0"]
    classification = ["public", "restricted", "confidential"]
    domains = [
        "pi-lar.net",
        "fluidos.eu",
        "fbk.eu",
        "um.es",
        "polito.it",
        "example.com",
    ]

    flavor_subjects = []

    flavorId = []
    providerId = []
    liqoId = []
    flavors = {}

    def setUp(self):
        logger.info("generating unique ID's")
        for n in range(6):
            REARSetupTest.flavorId.append(
                "".join(random.choice(string.ascii_lowercase) for i in range(12))
            )
            REARSetupTest.providerId.append(
                "".join(random.choice(string.ascii_lowercase) for i in range(12))
            )
            REARSetupTest.liqoId.append(
                "".join(random.choice(string.ascii_lowercase) for i in range(12))
            )

    @classmethod
    def authenticate_fluidos_nodes(cls, node: NeuropilNode, token: np_token):
        # logger.info(
        #     f"{str(node.get_fingerprint())[:8]}... authenticating fluidos node {token.subject} {token.get_fingerprint()}"
        # )
        return True

    @classmethod
    def authorize_fluidos_nodes(cls, node: NeuropilNode, token: np_token):
        fluidos_node_type = "consumer"
        country = None
        fluidos_node_info = None
        node_identity = None

        try:
            fluidos_node_info = token.get_attr_bin(
                key=fluidos_node_identity_v01
            ).decode()
            fluidos_node_type = "provider"
            country = token.get_attr_bin(key="country").decode()
        except NeuropilException as ne:
            # ignore non existence of fluidos_type (aka a consumer of fluidos resources) and/or country
            pass

        logger.info(
            f"{str(node.get_fingerprint())[:8]}... authorization of {fluidos_node_type} {token.issuer}"
        )
        if fluidos_node_info:
            node_identity = NodeIdentity.model_validate(json.loads(fluidos_node_info))

        if fluidos_node_type == "provider":
            logger.info(
                f"{str(node.get_fingerprint())[:8]}... can now access the fluidos node in country {country}, domain {node_identity.Domain}, Liqo ID {node_identity.additionalInformation.LiqoID}"
            )
        if fluidos_node_type == "consumer":
            logger.info(
                f"{str(node.get_fingerprint())[:8]}... received fluidos consumer offer"
            )

        return True

    def test_fluidos_node_discovery(self):
        """
        This test case demonstrates how fluidos nodes can inform themselves about their existence in the cybersecurity mesh.
        In addition to transporting the fluidos node identity information, neuropil has the benefit of already pushing
        identity information to the other consumer/provider of fluidos nodes, and thus embracing the zero trust principle
        The example implementation assumes that fluidos nodes are consumer and provider at the same time. In reality, this
        doesn't need to be the case. Also, in reality, a consumer may stay in passive mode behind the firewall. As long as he
        is able to connect to one fluidos member in the cybersecurity mesh, he will receive updates from the other fluidos
        members as well.
        """

        log_file_prefix = "test_fluidos_node_discovery"
        port_index = 1
        cluster_size = 5
        cluster_protocol = "udp4"

        np_fluidos_nodes = []
        # create six fluidos gateway nodes, that will act as simple relay
        for n in range(6):
            np_fluidos_g = NeuropilNode(
                proto="pas4",
                port=1973 * (n + 1),
                auto_run=False,
                log_file_prefix=f"{log_file_prefix}_node_{n}",
            )
            np_fluidos_g.set_authenticate_cb(REARSetupTest.authenticate_fluidos_nodes)
            # if self.set_identity_cluster:
            #     np_k8s_c_1.nodes[0].use_identity(np_k8s_c_1.nodes[0].new_identity())

            # this is our fluidos nodes discovery subject for all nodes
            fluidos_node_discovery_subject = np_subject.generate(
                subject=fluidos_node_discovery_v01
            )

            #
            # setup of fluidos nodes providing resources
            #

            # for simplicity, push the fluidos node discovery subject to the gateway node
            # In a real deployment, there should be another fluidos node running in passive mode
            mxp1 = np_fluidos_g.get_mx_properties(fluidos_node_discovery_subject)
            mxp1.audience_type = neuropil.NP_MX_AUD_VIRTUAL
            mxp1.ackmode = neuropil.NP_MX_ACK_NONE
            mxp1.role = neuropil.NP_MX_PROVIDER
            mxp1.intent_ttl = 600  # the fluidos node lifetime (needs to be adjusted for the real use case)
            mxp1.intent_update_after = 60  # refresh the fluidos node every minute
            mxp1.max_retry = 0
            mxp1.apply()

            # push some attributes to the subject for other nodes to apply filters
            mxp1.set_attr_bin("country", REARSetupTest.countries[n])
            mxp1.set_attr_bin("license", REARSetupTest.license[n])
            mxp1.set_attr_bin("classification", REARSetupTest.classification[n % 2])

            # get and push our gateway address for others to connect
            bootstrap_address = np_fluidos_g.get_address()
            liqo_id = "".join(random.choice(string.ascii_lowercase) for i in range(12))
            addon_data = AdditionalInformation(
                np_bootstrap_address=bootstrap_address, LiqoID=liqo_id
            )  # need to fetch the liqo id from the cluster
            # the NodeID should actually be the fingerprint of the fluidos identity (see line 93)
            fluidos_node_identity = NodeIdentity(
                NodeID=str(np_fluidos_g.get_fingerprint()),
                Domain=REARSetupTest.domains[n],
                IP="127.0.0.1",
                additionalInformation=addon_data,
            )
            logger.info(f"{fluidos_node_identity.model_dump_json()}")

            mxp1.set_attr_bin(
                fluidos_node_identity_v01, fluidos_node_identity.model_dump_json()
            )

            np_fluidos_g.set_authorize_cb(REARSetupTest.authorize_fluidos_nodes)

            #
            # setup of fluidos nodes consuming resources
            #

            # get a random number to search for other clusters
            random_id = n
            while random_id == n:
                random_id = random.randint(0, 5)
            mxp1 = np_fluidos_g.get_mx_properties(fluidos_node_discovery_subject)
            mxp1.audience_type = neuropil.NP_MX_AUD_VIRTUAL
            mxp1.role = neuropil.NP_MX_CONSUMER
            mxp1.intent_ttl = 600  # the fluidos node lifetime (needs to be adjusted for the real use case)
            mxp1.intent_update_after = 60  # refresh the fluidos node every minute
            mxp1.apply()

            # mxp1.set_attr_policy_bin("country", REARSetupTest.countries[random_id])

            # bootstrap_address = np_fluidos_g.get_address()
            # logger.info(f"fluidos gateway node is {bootstrap_address}")
            np_fluidos_nodes.append(np_fluidos_g)

        # setup one "neutral" community bootstrap node
        np_fluidos_b = NeuropilNode(
            proto="udp4",
            port=1951 * port_index,
            auto_run=True,
            log_file_prefix=f"{log_file_prefix}_bt_",
        )
        np_fluidos_b.set_authenticate_cb(self.authenticate_fluidos_nodes)
        np_fluidos_b.run(0)

        bootstrap_address = np_fluidos_b.get_address()
        logger.info(f"fluidos bootstrap node is {bootstrap_address}")

        # join all the gateway nodes to join the bootstrap node
        # note: it doesn't matter which node is the bootstrap node! here we use a dumb relay
        for n in range(6):
            np_fluidos_nodes[n].run(0)
            np_fluidos_nodes[n].join(bootstrap_address)

        timeout = 120
        now = time.time()
        while True:
            elapsed = time.time() - now
            if elapsed > timeout:
                break
            else:
                # run the nodes for the time given
                np_fluidos_b.run(0.0)
                for n in range(6):
                    np_fluidos_nodes[n].run(0)

        for n in range(6):
            np_fluidos_nodes[n].shutdown(False)
        np_fluidos_b.shutdown(False)

        logger.info(f"")
        logger.info(f"FluidOS node discovery test finished")
        logger.info(f"")

    @classmethod
    def receive_fluidos_flavor(cls, node: NeuropilNode, message: np_message):
        logger.info(
            f"{str(node.get_fingerprint())[:8]}... received flavor_data from {str(getattr(message, 'from'))} :: {message._data}"
        )
        return True

    @classmethod
    def authorize_fluidos_provider(cls, node: NeuropilNode, token: np_token):
        fluidos_node_type = "consumer"
        country = None
        fluidos_node_info = None
        node_identity = None

        node_discovery_subject_str = str(
            np_subject.generate(subject=fluidos_node_discovery_v01)
        )

        if token.subject == node_discovery_subject_str:
            try:
                fluidos_node_info = token.get_attr_bin(
                    key=fluidos_node_identity_v01
                ).decode()
                fluidos_node_type = "provider"
                country = token.get_attr_bin(key="country").decode()
            except NeuropilException as ne:
                # ignore non existence of fluidos_type (aka a consumer of fluidos resources) and/or country
                pass

            logger.info(
                f"{str(node.get_fingerprint())[:8]}... authorization of {fluidos_node_type} {token.issuer} from {country}"
            )
            if fluidos_node_info:
                node_identity = NodeIdentity.model_validate(
                    json.loads(fluidos_node_info)
                )
                logger.info(f"{str(node.get_fingerprint())[:8]} ... {node_identity}")

            if fluidos_node_type == "provider":
                logger.info(
                    f"{str(node.get_fingerprint())[:8]}... can now access the fluidos node in Domain {node_identity.Domain} with Liqo ID {node_identity.additionalInformation.LiqoID}"
                )

                # TODO: execute the setup of the additional listener as a async function
                # as a consumer, I'm able to make an educated decision whether the received node is good for me
                # assuming that I like the fluidos node, let's receive some flavor data from it
                flavor_discovery_subject = np_subject(
                    np_id.from_hex(str(token.issuer))._cdata
                )
                flavor_discovery_subject.add(fluidos_flavor_discovery_v01)

                REARSetupTest.flavor_subjects.append(str(flavor_discovery_subject))

                mxp1 = node.get_mx_properties(flavor_discovery_subject)
                mxp1.audience_type = (
                    neuropil.NP_MX_AUD_PUBLIC
                )  # should be neuropil.NP_MX_AUD_PRIVATE
                mxp1.ackmode = neuropil.NP_MX_ACK_NONE
                mxp1.role = neuropil.NP_MX_CONSUMER
                mxp1.intent_ttl = 600  # the fluidos node lifetime (needs to be adjusted for the real use case)
                mxp1.intent_update_after = (
                    60  # refresh the fluidos flavour every minute
                )
                mxp1.message_ttl = 30
                mxp1.max_retry = 3
                mxp1.apply()

                # node.set_authorize_cb(REARSetupTest.authorize_fluidos_provider)
                node.set_receive_cb(
                    flavor_discovery_subject, REARSetupTest.receive_fluidos_flavor
                )
                return True

            if fluidos_node_type == "consumer":
                logger.error(
                    f"{str(node.get_fingerprint())[:8]}... wrong callback function has been set"
                )

        if token.subject in REARSetupTest.flavor_subjects:
            # our own node registered itself before for this specific "flavour" subject
            # TODO: let's compare the fingerprints / public keys of the initial fluidos node discovery and the flavor data exchange
            logger.info(
                f"{str(node.get_fingerprint())[:8]}... provider flavor data authorization from {token.issuer}"
            )
            # TODO: register now for live telemetry updates of the flavor?
            return True

        return False

    @classmethod
    def authorize_fluidos_consumer(cls, node: NeuropilNode, token: np_token):
        fluidos_node_type = "consumer"
        fluidos_node_info = None

        node_discovery_subject_str = str(
            np_subject.generate(subject=fluidos_node_discovery_v01)
        )

        if token.subject == node_discovery_subject_str:
            try:
                fluidos_node_info = token.get_attr_bin(
                    key=fluidos_node_identity_v01
                ).decode()
                fluidos_node_type = "provider"
                country = token.get_attr_bin(key="country").decode()
            except NeuropilException as ne:
                # ignore non existence of fluidos_type (aka a consumer of fluidos resources) and/or country
                pass

            logger.info(
                f"{str(node.get_fingerprint())[:8]}... authorization of {fluidos_node_type} {token.issuer}"
            )
            if fluidos_node_info:
                node_identity = NodeIdentity.model_validate(
                    json.loads(fluidos_node_info)
                )

            if fluidos_node_type == "consumer":
                logger.info(
                    f"{str(node.get_fingerprint())[:8]}... received a fluidos consumer with id {token.issuer}"
                )
                return True
            if fluidos_node_type == "provider":
                logger.error(
                    f"{str(node.get_fingerprint())[:8]}... wrong callback function has been set"
                )
            return False

        else:
            # a consumer has connected to our flavor subject, let's send him some data
            # authorization is here and sending is in the main loop
            # TODO: compare message subject and public keys of participant
            return True

    def test_rear_flavour_discovery(self):
        """
        This test case demonstrates, how fluidos node flavours can be synced across different clusters.
        We will repeat a smaller setup of the previous example, however, a consumer must actively connect to the flavour data channel
        of a fluidos node to receive the updates. This is mainly due to the fact that using one single data channel for all flavours of all fluidos nodes is simply not feasible.
        Instead, we will use the hash chaining feature of neuropil to derive the new sub channels for each fluidos receiver.
        """
        log_file_prefix = "test_fluidos_flavour_discovery"
        port_index = 1
        cluster_size = 5
        cluster_protocol = "udp4"

        np_fluidos_nodes = []
        # create two fluidos gateway nodes, that will act as simple relay
        for n in range(2):
            np_fluidos_g = NeuropilNode(
                proto="udp4",
                port=1973 * (n + 1),
                auto_run=False,
                log_file_prefix=f"{log_file_prefix}_node_{n}",
            )
            np_fluidos_g.set_authenticate_cb(REARSetupTest.authenticate_fluidos_nodes)
            np_fluidos_g.set_authorize_cb(REARSetupTest.authorize_fluidos_consumer)

            # if self.set_identity_cluster:
            #     np_k8s_c_1.nodes[0].use_identity(np_k8s_c_1.nodes[0].new_identity())

            #
            # setup of fluidos nodes providing resources
            #

            # this is our fluidos nodes discovery subject for all nodes
            fluidos_nodes_discovery_subject = np_subject.generate(
                fluidos_node_discovery_v01
            )

            # for simplicity, push the fluidos node discovery subject to the gateway node
            # In a real deployment, there should be another fluidos node running in passive mode
            mxp1 = np_fluidos_g.get_mx_properties(fluidos_nodes_discovery_subject)
            mxp1.audience_type = neuropil.NP_MX_AUD_VIRTUAL
            mxp1.ackmode = neuropil.NP_MX_ACK_NONE
            mxp1.role = neuropil.NP_MX_PROVIDER
            mxp1.intent_ttl = 600  # the fluidos node lifetime (needs to be adjusted for the real use case)
            mxp1.intent_update_after = 60  # refresh the fluidos node every minute
            mxp1.max_retry = 0
            mxp1.apply()

            # push some attributes to the subject for other nodes to apply filters
            mxp1.set_attr_bin("country", REARSetupTest.countries[n])
            mxp1.set_attr_bin("license", REARSetupTest.license[n])
            mxp1.set_attr_bin("classification", REARSetupTest.classification[n % 2])

            # get and push our gateway address for others to connect
            bootstrap_address = np_fluidos_g.get_address()
            liqo_id = "".join(random.choice(string.ascii_lowercase) for i in range(12))
            addon_data = AdditionalInformation(
                np_bootstrap_address=bootstrap_address, LiqoID=liqo_id
            )  # need to fetch the liqo id from the cluster
            # the NodeID should actually be the fingerprint of the fluidos identity (see line 93)
            fluidos_node_identity = NodeIdentity(
                NodeID=str(np_fluidos_g.get_fingerprint()),
                Domain=REARSetupTest.domains[n],
                IP="127.0.0.1",
                additionalInformation=addon_data,
            )
            logger.info(f"{fluidos_node_identity.model_dump_json()}")

            mxp1.set_attr_bin(
                fluidos_node_identity_v01, fluidos_node_identity.model_dump_json()
            )

            # create the xor'ed subject out of "urn:eu:fluidos:flavor:discovery" and the fingerprint of the node
            discovery_subject = np_subject(np_fluidos_g.get_fingerprint()._cdata)
            discovery_subject.add(fluidos_flavor_discovery_v01)

            mxp1 = np_fluidos_g.get_mx_properties(discovery_subject)
            mxp1.audience_type = (
                neuropil.NP_MX_AUD_PUBLIC
            )  # should be neuropil.NP_MX_AUD_PRIVATE
            mxp1.ackmode = neuropil.NP_MX_ACK_NONE
            mxp1.role = neuropil.NP_MX_PROVIDER
            mxp1.intent_ttl = 600  # the fluidos node lifetime (needs to be adjusted for the real use case)
            mxp1.intent_update_after = 60  # refresh the fluidos flavour every minute
            mxp1.message_ttl = 30
            mxp1.max_retry = 0
            mxp1.apply()

            self._get_flavour(n, np_fluidos_g)

            # logger.info(f"fluidos gateway node is {bootstrap_address}")
            np_fluidos_nodes.append(np_fluidos_g)

        # setup one "neutral" community bootstrap node
        np_fluidos_b = NeuropilNode(
            proto="udp4",
            port=1951 * 3,
            auto_run=True,
            log_file_prefix=f"{log_file_prefix}_bt_",
        )
        np_fluidos_b.set_authenticate_cb(self.authenticate_fluidos_nodes)
        np_fluidos_b.run(0)

        bootstrap_address = np_fluidos_b.get_address()
        logger.info(f"fluidos bootstrap node is {bootstrap_address}")

        #
        # setup of fluidos node consumer
        #

        # setup one "consumer" of fluidos resources
        np_fluidos_consumer = NeuropilNode(
            proto="udp4",
            port=1951 * 4,
            auto_run=True,
            log_file_prefix=f"{log_file_prefix}_consumer_",
        )

        # get a random number to search for other clusters
        random_id = n
        while random_id == n:
            random_id = random.randint(0, 5)

        mxp1 = np_fluidos_consumer.get_mx_properties(fluidos_nodes_discovery_subject)
        mxp1.audience_type = neuropil.NP_MX_AUD_VIRTUAL
        mxp1.role = neuropil.NP_MX_CONSUMER
        mxp1.intent_ttl = 600  # the fluidos node lifetime (needs to be adjusted for the real use case)
        mxp1.intent_update_after = 60  # refresh the fluidos node every minute
        mxp1.apply()

        # mxp1.set_attr_policy_bin("country", REARSetupTest.countries[random_id])

        np_fluidos_consumer.set_authenticate_cb(self.authenticate_fluidos_nodes)
        np_fluidos_consumer.set_authorize_cb(self.authorize_fluidos_provider)

        np_fluidos_consumer.run(0)

        # join all the gateway nodes to join the bootstrap node
        # note: it doesn't matter which node is the bootstrap node! here we use a dumb relay
        np_fluidos_consumer.run(0)
        np_fluidos_consumer.join(bootstrap_address)
        for n in range(2):
            np_fluidos_nodes[n].run(0)
            np_fluidos_nodes[n].join(bootstrap_address)

        timeout = 240
        now = time.time()
        last_flavor_update = 0.0
        while True:
            elapsed = time.time() - now
            if elapsed > timeout:
                break
            else:
                # run the nodes for the time given
                np_fluidos_b.run(0.0)
                for n in range(2):
                    # subject: "urn:eu:fluidos:flavor:discovery"
                    discovery_subject = np_subject(
                        np_fluidos_nodes[n].get_fingerprint()._cdata
                    )
                    discovery_subject.add(fluidos_flavor_discovery_v01)

                    if (
                        np_fluidos_nodes[n].np_has_receiver_for(discovery_subject)
                        and (last_flavor_update + 30) < elapsed
                    ):
                        node_fp = str(np_fluidos_nodes[n].get_fingerprint())
                        flavor_data: Flavor = REARSetupTest.flavors[node_fp]
                        np_fluidos_nodes[n].send(
                            discovery_subject, flavor_data.model_dump_json()
                        )
                        logger.info(f"{str(node_fp)[:8]}... sending flavor data")
                        # TODO: trigger automatic update of flavor data in the background
                        last_flavor_update = elapsed
                    np_fluidos_nodes[n].run(0.0)

        # subject: "urn:eu:fluidos:flavours:update"

        for n in range(2):
            np_fluidos_nodes[n].shutdown(False)
        np_fluidos_consumer.shutdown(False)
        np_fluidos_b.shutdown(False)

        logger.info(f"")
        logger.info(f"FluidOS flavor discovery test finished")
        logger.info(f"")

    def _get_flavour(self, n: int, np_fluidos_g: NeuropilNode):

        node_fp = str(np_fluidos_g.get_fingerprint())
        if node_fp not in REARSetupTest.flavors.keys():
            addon_data = AdditionalInformation(
                np_bootstrap_address=np_fluidos_g.get_address(),
                LiqoID=REARSetupTest.liqoId[n],
            )  # need to fetch the liqo id from the cluster

            # the NodeID should actually be the fingerprint of the fluidos identity (see line 93)
            owner = Owner(
                # the "Owner" data object is actually the same as the fluidos "node identity" object (?)
                domain=REARSetupTest.domains[n],
                nodeId=str(np_fluidos_g.get_fingerprint()),
                ip="",
                additionalInformation=addon_data,
            )
            location = Location(city="Cologne", country="Germany")
            price = Price(amount="10", currency="Euro", period="")
            na = NetworkAuthorizations()
            properties = Properties(latency=1, securityStandards=["NIS-2", "ISO27001"])

            characteristics = Characteristics(
                architecture="arm64",
                cpu="".join(str(random.randint(1, 36))),
                memory="".join(str(random.randint(1, 512))) + "G",
                pods="".join(str(random.randint(1, 111))),
            )
            partionability = Partitionability(
                cpuMin="0",
                memoryMin="0",
                memoryStep="100Mi",
                podsMin="0",
                podsStep="0",
                cpuStep="1",
            )
            policies = Policies(partitionability=partionability)

            k8s_slice_data = K8SSchema(
                properties=properties,
                characteristics=characteristics,
                policies=policies,
            )

            flavour_type = FlavourType(name=Name.k8slice, data=k8s_slice_data)
            fluidos_flavour_data = Flavor(
                flavorId=REARSetupTest.flavorId[n],
                providerId=str(np_fluidos_g.get_fingerprint()),
                timestamp=datetime.now().ctime(),
                location=location,
                flavourType=flavour_type,
                price=price,
                owner=owner,
                availability=False,
            )
            logger.info(
                f"created node {n} flavour {fluidos_flavour_data.model_dump_json()}"
            )
            REARSetupTest.flavors[node_fp] = fluidos_flavour_data

        return REARSetupTest.flavors[node_fp]

    def test_rear_aquisition(self):
        # subject: "urn:eu:fluidos:reservation:publish:v0.1"
        # subject: "urn:eu:fluidos:reservation:claim:v0.1"
        # subject: "urn:eu:fluidos:contract:offer:v0.1"
        pass


import time

if __name__ == "__main__":
    x = REARSetupTest()
    x.setUp()
    x.test_fluidos_node_discovery()
    time.sleep(25)
    x.test_rear_flavour_discovery()
