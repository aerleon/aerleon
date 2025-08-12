import re

from absl.testing import absltest

from aerleon import api
from aerleon.lib import naming
from aerleon.lib.policy_builder import PolicyDict
from tests.regression_utils import capture

# fmt: off
GOOD_POLICY_1: PolicyDict = {
    "filename": "raw_policy_all_builtin",
    "filters": [
        {
            "header": {
                "targets": {
                    "cisco": "test-filter"
                },
                "kvs": {
                    "comment": "Sample comment"
                },
            },
            "terms": [
                {
                    "name": "deny-to-reserved",
                    "destination-address": "NET1",
                    "action": "deny"
                },
                {
                    "name": "deny-to-bogons",
                    "destination-address": "NET2",
                    "action": "deny"
                },
                {
                    "name": "allow-web-to-mail",
                    "source-address": "9OCLOCK",
                    "destination-address": "MAIL",
                    "action": "accept",
                },
            ],
        }
    ],
}

SERVICES_1 = {
    "services": {
        "SVC1": [
            {
                "protocol": "tcp",
                "port": 80,
            },
            {
                "protocol": "udp",
                "port": 81,
            },
            {
                "protocol": "tcp",
                "port": 82,
            },
        ],
        "SVC2": [
            {
                "protocol": "tcp",
                "port": 80,
            },
            {
                "protocol": "udp",
                "port": 81,
            },
            {
                "protocol": "tcp",
                "port": 82,
            },
            {
                "name": "SVC2",
            },
        ],
        "SVC3": [
            {
                "protocol": "tcp",
                "port": 80,
            },
            {
                "protocol": "udp",
                "port": 81,
            },
        ],
        "SVC4": [
            {
                "protocol": "tcp",
                "port": 80,
                "comment": "some service"
            },
        ],
        "TCP_90": [
            {
                "protocol": "tcp",
                "port": 90,
            },
        ],
        "SVC5": [
            {
                "name": "TCP_90",
            },
        ],
        "SVC6": [
            {
                "name": "SVC1",
            },
            {
                "name": "SVC5",
            },
        ],
    }
}


NETWORKS_1 = {
    "networks": {
        "NET1": {
            "values": [
                {
                    "address": "10.1.0.0/8",
                    "comment": "network1",
                },
            ]
        },
        "NET2": {
            "values": [
                {
                    "address": "10.2.0.0/16",
                    "comment": "network2.0",
                },
                {
                    "name": "NET1",
                    "comment": "network2.0",
                },
            ]
        },
        "9OCLOCK": {
            "values": [
                {
                    "address": "1.2.3.4/32",
                    "comment": "9 is the time",
                },
            ]
        },
        "MAIL": {
            "values": [
                {
                    "address": "49.1.1.0/24"
                }
            ]
        },
        "FOOBAR": {
            "values": [
                {
                    "name": "9OCLOCK",
                },
            ]
        },
        "FOO_V6": {
            "values": [
                {
                    "address": "::FFFF:FFFF:FFFF:FFFF",
                },
            ]
        },
        "BAR_V6": {
            "values": [
                {
                    "address": "::1/128",
                },
            ]
        },
        "BAZ": {
            "values": [
                {
                    "name": "FOO_V6",
                },
                {
                    "name": "BAR_V6",
                },
            ]
        },
        "BING": {
            "values": [
                {
                    "name": "NET1",
                    "comment": "foo",
                },
                {
                    "name": "BAR_V6",
                },
            ]
        },
    }
}
# fmt: on


class ApiTest(absltest.TestCase):
    def testGenerate(self):
        definitions = naming.Naming()
        definitions.ParseDefinitionsObject(SERVICES_1, "blah")
        definitions.ParseDefinitionsObject(NETWORKS_1, "blah")

        configs = api.Generate([GOOD_POLICY_1], definitions)
        acl = configs["raw_policy_all_builtin.acl"]

        self.assertTrue(re.search(' deny-to-reserved', str(acl)))
        self.assertTrue(re.search(' deny ip any 10.2.0.0 0.0.255.255', str(acl)))

    def testAclCheck(self):
        definitions = naming.Naming()
        definitions.ParseDefinitionsObject(SERVICES_1, "blah")
        definitions.ParseDefinitionsObject(NETWORKS_1, "blah")

        configs = api.AclCheck(GOOD_POLICY_1, definitions, src="10.2.0.0")
        self.assertIn('deny-to-reserved', configs['test-filter'].keys())

        configs = api.AclCheck(GOOD_POLICY_1, definitions, src="1.2.3.4", dst='49.1.1.5')
        self.assertIn('allow-web-to-mail', configs['test-filter'].keys())

    @capture.stdout
    def testDocsExample(self):
        USE_MAIL_SERVER_SET = 1
        mail_server_ips_set0 = ["200.1.1.4/32", "200.1.1.5/32"]
        mail_server_ips_set1 = ["200.1.2.4/32", "200.1.2.5/32"]

        networks = {
            "networks": {
                "RESERVED": {
                    "values": [
                        {
                            "address": "0.0.0.0/8",
                        },
                        {
                            "address": "10.0.0.0/8",
                        },
                    ]
                },
                "BOGON": {
                    "values": [
                        {
                            "address": "192.0.0.0/24",
                        },
                        {
                            "address": "192.0.2.0/24",
                        },
                    ]
                },
                "MAIL_SERVERS": {"values": []},
            }
        }

        if USE_MAIL_SERVER_SET == 0:
            networks["networks"]["MAIL_SERVERS"]["values"] = mail_server_ips_set0
        else:
            networks["networks"]["MAIL_SERVERS"]["values"] = mail_server_ips_set1

        cisco_example_policy: PolicyDict = {
            "filename": "cisco_example_policy",
            "filters": [
                {
                    "header": {
                        "targets": {"cisco": "test-filter"},
                        "kvs": {"comment": "Sample comment"},
                    },
                    "terms": [
                        {
                            "name": "deny-to-reserved",
                            "destination-address": "RESERVED",
                            "action": "deny",
                        },
                        {
                            "name": "deny-to-bogons",
                            "destination-address": "BOGON",
                            "action": "deny",
                        },
                        {
                            "name": "allow-web-to-mail",
                            "destination-address": "MAIL_SERVERS",
                            "action": "accept",
                        },
                    ],
                }
            ],
        }

        definitions = naming.Naming()
        definitions.ParseDefinitionsObject(networks, "")
        configs = api.Generate([cisco_example_policy], definitions)
        acl = configs["cisco_example_policy.acl"]
        print(acl)

        self.assertTrue(re.search(' deny-to-reserved', str(acl)))
        self.assertTrue(re.search(' permit ip any host 200.1.2.4', str(acl)))

    def testGenerateWithTermInclude(self):
        """Verify that term-level includes work with the `includes` parameter."""
        # Main policy with an include directive in its terms list
        main_policy: PolicyDict = {
            "filename": "policy_with_term_include",
            "filters": [
                {
                    "header": {"targets": {"cisco": "filter-with-include"}},
                    "terms": [
                        {
                            "name": "term-before-include",
                            "source-address": "NET1",
                            "action": "accept",
                        },
                        {"include": "common_terms"},
                        {
                            "name": "term-after-include",
                            "source-address": "NET2",
                            "action": "accept",
                        },
                    ],
                }
            ],
        }

        # The dictionary that will be "included"
        included_terms_policy = {
            "terms": [
                {
                    "name": "included-term-1",
                    "destination-address": "MAIL",
                    "action": "accept",
                },
                {
                    "name": "included-term-2",
                    "destination-address": "NET2",
                    "action": "deny",
                },
            ]
        }

        # The `includes` dictionary mapping the include name to the policy dict
        includes_dict = {"common_terms": included_terms_policy}

        definitions = naming.Naming()
        definitions.ParseDefinitionsObject(NETWORKS_1, "")

        # Generate the ACL, providing the `includes` dictionary
        configs = api.Generate([main_policy], definitions, includes=includes_dict)
        acl = configs["policy_with_term_include.acl"]

        # Verify that terms from the main policy and the included policy are present
        self.assertIn("term-before-include", acl)
        self.assertIn("permit ip 10.0.0.0 0.255.255.255 any", acl)

        self.assertIn("included-term-1", acl)
        self.assertIn("permit ip any 49.1.1.0 0.0.0.255", acl)

        self.assertIn("included-term-2", acl)
        self.assertIn("deny ip any 10.2.0.0 0.0.255.255", acl)

        self.assertIn("term-after-include", acl)
        self.assertIn("permit ip 10.2.0.0 0.0.255.255 any", acl)

    def test_aclcheck_api_documentation_example(self):
        test_output = []
        # Define the policy as a Python dictionary
        # This structure mirrors the YAML policy file format.
        example_policy = {
            "filename": "my_api_policy_check",  # Used for context, not for file output in AclCheck
            "filters": [
                {
                    "header": {
                        "targets": {"cisco": "test-filter"},  # Target is needed for policy parsing
                        "kvs": {"comment": "Sample filter for AclCheck API demo"},
                    },
                    "terms": [
                        {
                            "name": "allow-web-traffic",
                            "source-address": "INTERNAL_NETWORK",
                            "destination-address": "WEB_SERVERS",
                            "destination-port": "HTTP",
                            "protocol": "tcp",
                            "action": "accept",
                        },
                        {"name": "deny-all-else", "action": "deny"},
                    ],
                }
            ],
        }

        # Define network and service names
        # This is typically loaded from definition files but can be constructed in code.
        definitions_data = {
            "networks": {
                "INTERNAL_NETWORK": {"values": [{"address": "192.168.1.0/24"}]},
                "WEB_SERVERS": {
                    "values": [{"address": "10.0.0.10/32"}, {"address": "10.0.0.11/32"}]
                },
            },
            "services": {"HTTP": [{"protocol": "tcp", "port": "80"}]},
        }

        # Create a Naming object and parse the definitions
        defs = naming.Naming()
        defs.ParseDefinitionsObject(definitions_data, "")  # Second arg is filename context

        # Perform the AclCheck
        source_ip = "192.168.1.50"
        destination_ip = "10.0.0.10"
        protocol = "tcp"
        destination_port = "80"
        source_port = "49152"  # Ephemeral port

        try:
            # Use AclCheck.FromPolicyDict via the api.AclCheck wrapper
            summary = api.AclCheck(
                input_policy=example_policy,
                definitions=defs,
                src=source_ip,
                dst=destination_ip,
                sport=source_port,
                dport=destination_port,
                proto=protocol,
            )

            # Print the summary
            if summary:
                for filter_name, terms in summary.items():
                    test_output.append(f"  Filter: {filter_name}")
                    for term_name, match_details in terms.items():
                        test_output.append(match_details['message'])
            else:
                test_output.append(
                    f"No matching terms found for traffic from {source_ip}:{source_port} to {destination_ip}:{destination_port} ({protocol})."
                )

        except Exception as e:
            summary = None
            test_output.append(f"An error occurred: {e}")

        test_output = "\n".join(test_output)

        # Assertions on the captured output
        # Verify that the correct filter and term are identified
        self.assertIn("Filter: test-filter", test_output)
        self.assertIn("term: allow-web-traffic", test_output)
        self.assertIn("accept", test_output)

        # Example of what the summary object itself would look like for direct assertion
        expected_summary_structure = {
            "test-filter": {
                "allow-web-traffic": {
                    "possibles": [],
                    "message": "          term: allow-web-traffic\n                accept",
                }
            }
        }
        self.assertEqual(summary, expected_summary_structure)
