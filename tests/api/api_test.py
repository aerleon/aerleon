import logging
import multiprocessing
import os
import pathlib
import re
import shutil
import tempfile
import unittest
from unittest import mock

from absl import logging as absl_logging  # Keep absl logging for explicit usages if any
from absl.testing import absltest

from aerleon import api
from aerleon.lib import aclgenerator, naming, policy
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
                "comment": "Sample comment",
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

        with self.assertLogs(level=logging.WARNING) as generate_logs:
            logging.warning("__SENTINEL__")

            configs = api.Generate([GOOD_POLICY_1], definitions)
            acl = configs["raw_policy_all_builtin.acl"]

        # Verify there were no (unexpected) log messages
        # Filter out DEBUG logs from aclcheck and INFO logs from plugin_supervisor
        relevant_logs = [
            r
            for r in generate_logs.records
            if r.getMessage() != "__SENTINEL__" and r.levelno >= logging.WARNING
        ]
        self.assertEqual(
            relevant_logs,
            [],
            msg=f"Unexpected log messages: {relevant_logs}",
        )

        self.assertTrue(re.search(' deny-to-reserved', str(acl)))
        self.assertTrue(re.search(' deny ip any 10.2.0.0 0.0.255.255', str(acl)))

    def testAclCheck(self):
        definitions = naming.Naming()
        definitions.ParseDefinitionsObject(SERVICES_1, "blah")
        definitions.ParseDefinitionsObject(NETWORKS_1, "blah")

        with self.assertLogs(level=logging.WARNING) as aclcheck_logs:
            logging.warning("__SENTINEL__")

            configs = api.AclCheck(GOOD_POLICY_1, definitions, src="10.2.0.0")
            self.assertIn('deny-to-reserved', configs['test-filter'].keys())

            configs = api.AclCheck(GOOD_POLICY_1, definitions, src="1.2.3.4", dst='49.1.1.5')
            self.assertIn('allow-web-to-mail', configs['test-filter'].keys())

        # Verify there were no (unexpected) log messages
        # Filter out DEBUG logs from aclcheck and INFO logs from plugin_supervisor
        relevant_logs = [
            r
            for r in aclcheck_logs.records
            if r.getMessage() != "__SENTINEL__" and r.levelno >= logging.WARNING
        ]
        self.assertEqual(
            relevant_logs,
            [],
            msg=f"Unexpected log messages: {relevant_logs}",
        )

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
                        "comment": "Sample comment",
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
        with self.assertLogs(level=logging.WARNING) as generate_logs:
            logging.warning("__SENTINEL__")

            configs = api.Generate([cisco_example_policy], definitions)
            acl = configs["cisco_example_policy.acl"]
            print(acl)

            # Verify there were no (unexpected) log messages
            # Filter out DEBUG logs from aclcheck and INFO logs from plugin_supervisor
            relevant_logs = [
                r
                for r in generate_logs.records
                if r.getMessage() != "__SENTINEL__" and r.levelno >= logging.WARNING
            ]
            self.assertEqual(
                relevant_logs,
                [],
                msg=f"Unexpected log messages: {relevant_logs}",
            )

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
                        "comment": "Sample filter for AclCheck API demo",
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
            with self.assertLogs(level=logging.WARNING) as aclcheck_logs:
                logging.warning("__SENTINEL__")

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
        # Verify there were no (unexpected) log messages
        # Filter out DEBUG logs from aclcheck and INFO logs from plugin_supervisor
        relevant_logs = [
            r
            for r in aclcheck_logs.records
            if r.getMessage() != "__SENTINEL__" and r.levelno >= logging.WARNING
        ]
        self.assertEqual(
            relevant_logs,
            [],
            msg=f"Unexpected log messages: {relevant_logs}",
        )

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

    def testGenerateIncludedPathConflict(self):
        """Test that providing both include_path and includes raises a TypeError."""
        definitions = naming.Naming()
        with self.assertRaisesRegex(TypeError, "mutually exclusive"):
            api.Generate([], definitions, include_path="foo", includes={'a': {}})

    def testGenerateWithOutputDirectory(self):
        """Test that api.Generate writes files to the specified output directory."""
        definitions = naming.Naming()
        definitions.ParseDefinitionsObject(NETWORKS_1, "")

        with tempfile.TemporaryDirectory() as tmpdirname:
            tmp_path = pathlib.Path(tmpdirname)
            with self.assertLogs(level=logging.WARNING) as generate_logs:
                logging.warning("__SENTINEL__")
                api.Generate([GOOD_POLICY_1], definitions, output_directory=tmp_path)

            output_file = tmp_path / "raw_policy_all_builtin.acl"
            self.assertTrue(output_file.exists())
            content = output_file.read_text()
            self.assertIn("deny-to-reserved", content)

    def testGeneratePcap(self):
        """Test that pcap targets are generated correctly with -accept and -deny suffixes."""
        pcap_policy = {
            "filename": "pcap_policy",
            "filters": [
                {
                    "header": {
                        "targets": {"pcap": "test-filter"},
                    },
                    "terms": [
                        {
                            "name": "term-1",
                            "source-address": "NET1",
                            "action": "accept",
                        },
                    ],
                }
            ],
        }
        definitions = naming.Naming()
        definitions.ParseDefinitionsObject(NETWORKS_1, "")
        configs = api.Generate([pcap_policy], definitions)
        self.assertIn("pcap_policy-accept.pcap", configs)
        self.assertIn("pcap_policy-deny.pcap", configs)

    def testGenerateMultiprocessing(self):
        """Test that _Generate works correctly when using multiprocessing."""
        definitions = naming.Naming()
        definitions.ParseDefinitionsObject(NETWORKS_1, "")

        configs = api._Generate(
            [GOOD_POLICY_1], definitions, multiprocessing.get_context(), max_renderers=2
        )
        self.assertIn("raw_policy_all_builtin.acl", configs)

    def testGenerateUnknownTarget(self):
        """Test that an unknown target in the policy logs a warning and skips generation."""
        bad_target_policy: PolicyDict = {
            "filename": "bad_target_policy",
            "filters": [
                {
                    "header": {
                        "targets": {"unknown_target_xyz": "test-filter"},
                    },
                    "terms": [
                        {
                            "name": "term-1",
                            "action": "accept",
                        },
                    ],
                }
            ],
        }
        definitions = naming.Naming()

        with self.assertLogs(level=logging.WARNING) as log:
            api.Generate([bad_target_policy], definitions)
            self.assertTrue(any("No generator found" in r.getMessage() for r in log.records))

    def testShadingError(self):
        """Test that shaded terms (unreachable code) log a shading error warning."""
        # Create a policy that causes a shading error
        definitions = naming.Naming()
        definitions.ParseDefinitionsObject(NETWORKS_1, "")

        shading_policy: PolicyDict = {
            "filename": "shading_policy",
            "filters": [
                {
                    "header": {
                        "targets": {"cisco": "test-filter"},
                    },
                    "terms": [
                        {
                            "name": "term-1",
                            "protocol": "tcp",
                            "action": "accept",
                        },
                        {
                            "name": "term-2",
                            "protocol": "tcp",
                            "action": "accept",
                        },
                    ],
                }
            ],
        }

        with self.assertLogs(level=logging.WARNING) as log:
            api.Generate([shading_policy], definitions, shade_check=True)
            # Verify that the specific shading message is present in the logs
            self.assertTrue(
                any("term-2 is shaded by term-1" in r.getMessage() for r in log.records)
            )

    def testIncludePath(self):
        """Test that policy includes are resolved correctly from include_path."""
        with tempfile.TemporaryDirectory() as tmpdirname:
            tmp_path = pathlib.Path(tmpdirname)
            with open(tmp_path / "inc.yaml", "w") as f:
                f.write("terms:\n  - name: included\n    action: accept\n")

            policy_with_include = {
                "filename": "test_include",
                "filters": [
                    {"header": {"targets": {"cisco": "test"}}, "terms": [{"include": "inc.yaml"}]}
                ],
            }

            definitions = naming.Naming()
            api.Generate([policy_with_include], definitions, include_path=tmp_path)

    def testPolicyError(self):
        """Test that invalid policy structure raises an ACLParserError."""
        # Invalid policy structure to trigger parser error
        invalid_policy = {
            "filename": "invalid_policy",
            "filters": [
                {
                    "header": {
                        "targets": {"cisco": "test-filter"},
                    },
                    "terms": [
                        {
                            "name": "term-1",
                            "action": "invalid_action_xyz",
                        },
                    ],
                }
            ],
        }
        definitions = naming.Naming()

        with self.assertRaisesRegex(api.ACLParserError, "Error parsing policy"):
            api.Generate([invalid_policy], definitions)

    def testAclCheckInvalidAction(self):
        """Test that AclCheck raises ACLParserError for invalid actions in policy."""
        # Invalid policy for AclCheck
        invalid_policy = {
            "filename": "invalid_policy",
            "filters": [
                {
                    "header": {
                        "targets": {"cisco": "test-filter"},
                    },
                    "terms": [
                        {
                            "name": "term-1",
                            "action": "invalid_action_xyz",
                        }
                    ],
                }
            ],
        }
        definitions = naming.Naming()
        with self.assertRaisesRegex(api.ACLParserError, "Error parsing policy"):
            api.AclCheck(invalid_policy, definitions, src="10.0.0.1")

    def testNoneInputs(self):
        """Test that None inputs correctly raise TypeError or AttributeError."""
        definitions = naming.Naming()
        # Test None for policies list
        with self.assertRaises(TypeError):
            api.Generate(None, definitions)

        # Test None for definitions
        # This raises ACLParserError because PolicyBuilder fails and it's caught
        with self.assertRaisesRegex(
            api.ACLParserError, "(?s)Error parsing policy.*UndefinedAddressError"
        ):
            api.Generate([GOOD_POLICY_1], None)

    def testGenerateEmptyPolicy(self):
        """Test that an empty policy (no filters) logs a warning."""
        # Using a valid policy structure but with empty filters list
        empty_policy = {
            "filename": "empty_policy",
            "filters": [],
        }
        definitions = naming.Naming()
        with self.assertLogs(level=logging.WARNING) as log:
            api.Generate([empty_policy], definitions)
            self.assertTrue(any("empty" in r.getMessage() for r in log.records))

    def testGenerateGeneratorError(self):
        """Test that generator errors cause ACLGeneratorError."""
        # Mock the generator to force an error, ensuring we test the api.py error handling path
        # regardless of specific policy validity details.
        mock_generator = mock.Mock(side_effect=aclgenerator.Error("mock generator error"))
        # Simulate the class attribute SUFFIX which api.py accesses before instantiation in some paths?

        class MockGen:
            SUFFIX = ".acl"

            def __init__(self, *args, **kwargs):
                raise aclgenerator.Error("mock generator error")

        # Mock Start to avoid overwriting mock generators because PluginSupervisor.Start() normally resets the generator table.
        with mock.patch.object(api.plugin_supervisor.PluginSupervisor, 'Start', return_value=None):
            with mock.patch.dict(
                api.plugin_supervisor.PluginSupervisor.generators, {'cisco': MockGen}
            ):
                policy_dict = {
                    "filename": "test",
                    "filters": [
                        {
                            "header": {"targets": {"cisco": "test"}},
                            "terms": [{"name": "t", "action": "accept"}],
                        }
                    ],
                }
                definitions = naming.Naming()

                with self.assertRaisesRegex(api.ACLGeneratorError, "Error generating target ACL"):
                    api.Generate([policy_dict], definitions)

    def testGenerateMultiprocessingError(self):
        """Test exception handling in multiprocessing worker retrieval."""
        # An invalid target type triggers UnsupportedCiscoAccessListError -> ACLGeneratorError
        bad_cisco_policy = {
            "filename": "bad_cisco_policy",
            "filters": [
                {
                    "header": {
                        "targets": {"cisco": "test-filter invalid_type_xyz"},
                    },
                    "terms": [
                        {
                            "name": "term-1",
                            "action": "accept",
                        },
                    ],
                }
            ],
        }
        definitions = naming.Naming()

        # Expect a warning log about error encountered.
        with self.assertLogs(level=logging.WARNING) as log:
            api._Generate(
                [bad_cisco_policy], definitions, multiprocessing.get_context(), max_renderers=2
            )
            self.assertTrue(any("error encountered" in r.getMessage() for r in log.records))

    @mock.patch.object(policy, 'FromBuilder')
    def testShadingErrorRaise(self, mock_from_builder):
        """Test that policy.ShadingError is caught and logged."""
        mock_from_builder.side_effect = policy.ShadingError("mock shading error")
        definitions = naming.Naming()

        with self.assertLogs(level=logging.WARNING) as log:
            api.Generate([GOOD_POLICY_1], definitions, shade_check=True)
            self.assertTrue(any("shading errors" in r.getMessage() for r in log.records))
