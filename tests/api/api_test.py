import re
from absl.testing import absltest

from aerleon import api
from aerleon.lib import naming


GOOD_POLICY_1 = {
    "filename": "raw_policy_all_builtin",
    "filters": [
        {
            "header": {
                "targets": {"cisco": "test-filter"},
                "kvs": {"comment": "Sample comment"},
            },
            "terms": [
                {"name": "deny-to-reserved", "destination-address": "NET1", "action": "deny"},
                {"name": "deny-to-bogons", "destination-address": "NET2", "action": "deny"},
                {
                    "name": "allow-web-to-mail",
                    "source-address": "9OCLOCK",
                    "destination-address": "NET2",
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
            {"protocol": "tcp", "port": 80, "comment": "some service"},
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


class ApiTest(absltest.TestCase):
    def testGenerate(self):

        definitions = naming.Naming()
        definitions.ParseDefinitionsObject(SERVICES_1, "blah")
        definitions.ParseDefinitionsObject(NETWORKS_1, "blah")

        configs = api.Generate([GOOD_POLICY_1], definitions)
        acl = configs["raw_policy_all_builtin.acl"]

        self.assertTrue(re.search(' deny-to-reserved', str(acl)))
        self.assertTrue(re.search(' deny ip any 10.2.0.0 0.0.255.255', str(acl)))

        print(acl)
