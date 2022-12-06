import re
from absl.testing import absltest

from aerleon import api

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

GOOD_PORTS_1 = {
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


GOOD_IPS_1 = {
    "NET1": [
        {
            "ip": "10.1.0.0/8",
            "comment": "network1",
        },
    ],
    "NET2": [
        {
            "ip": "10.2.0.0/16",
            "comment": "network2.0",
        },
        {
            "name": "NET1",
            "comment": "network2.0",
        },
    ],
    "9OCLOCK": [
        {
            "ip": "1.2.3.4/32",
            "comment": "9 is the time",
        },
    ],
    "FOOBAR": [
        {
            "name": "9OCLOCK",
        },
    ],
    "FOO_V6": [
        {
            "ip": "::FFFF:FFFF:FFFF:FFFF",
        },
    ],
    "BAR_V6": [
        {
            "ip": "::1/128",
        },
    ],
    "BAZ": [
        {
            "name": "FOO_V6",
        },
        {
            "name": "BAR_V6",
        },
    ],
    "BING": [
        {
            "name": "NET1",
            "comment": "foo",
        },
        {
            "name": "BAR_V6",
        },
    ],
}


class ApiTest(absltest.TestCase):
    def testGenerate(self):
        configs = api.Generate([GOOD_POLICY_1], GOOD_PORTS_1, GOOD_IPS_1)
        acl = configs["raw_policy_all_builtin.acl"]
        self.assertTrue(re.search(' deny-to-reserved', str(acl)))
        print(acl)
