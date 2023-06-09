# Aerleon Python API

The Generate API provides the full policy-to-ACL capabilities of the aclgen command line tool. It accepts as input plain Python dictionaries and lists.

This API provides a single method, `Generate()`, that accepts a list of policies and an IP/ports definition object and will transform each policies into platform-specific configs. Each policy should be given as a Python dictionary - no YAML is required here. The IP/ports definitions should be given as a Naming object which can also be constructed from a Python dictionary.

### Example: Generating Cisco ACL Using the Generate API

In this example we want to generate a Cisco ACL named `test-filter`. The filter should first deny packets addressed to reserved or invalid IP addresses ("bogons") and then only accept traffic that addresses the mail server (`MAIL_SERVERS`).

The policy is defined like so. This structure of nested Python dictionaries and keys mirrors exactly the YAML policy file format. At the top level two keys must be defined: "filename", which controls the name of all output files produced from this policy, and "filters", which lists all filters in this policy. Within the "filters" list we have a single filter, which must have a "header" section and a "terms" list. The "header" instructs Aerleon to produce Cisco ACL output. The "terms" list defines the access control behavior we want for this filter.

```python
cisco_example_policy = {
    "filename": "cisco_example_policy",
    "filters": [
        {
            "header": {
                "targets": {
                    "cisco": "test-filter"
                },
                "comment": "Sample comment"
            },
            "terms": [
                {
                    "name": "deny-to-reserved",
                    "destination-address": "RESERVED",
                    "action": "deny"
                },
                {
                    "name": "deny-to-bogons",
                    "destination-address": "BOGON",
                    "action": "deny"
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
```

Because this object is constructed in Python it can incorporate variable data. Users might conditionally construct the policy as part of a network automation workflow.

Now the network names used in this example have to be defined. The naming definitions are constructed as follows. In this example we are dynamically selecting between two sets of IP addresses for the mail server.

```python
mail_server_ips_set0 = ["200.1.1.4/32","200.1.1.5/32"]
mail_server_ips_set1 = ["200.1.2.4/32","200.1.2.5/32"]

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
        "MAIL_SERVERS": {
            "values": []
        }
    }
}

if USE_MAIL_SERVER_SET == 0:
    networks["networks"]["MAIL_SERVERS"]["values"] = mail_server_ips_set0
else:
    networks["networks"]["MAIL_SERVERS"]["values"] = mail_server_ips_set1
```

Now to call the Generate method. We need to first construct a Naming object and load the network definitions, then pass that to Generate along with the policy object.

```python
from aerleon.lib import naming  
from aerleon import api

def main():
    definitions = naming.Naming()
    definitions.ParseDefinitionsObject(networks, "")
    configs = api.Generate([cisco_example_policy], definitions)
    acl = configs["cisco_example_policy.acl"]
    print(acl)

if __name__ == '__main__':
    main()
```

At this point the variable `acl` contains the Cisco ACL we want:
```
$Id:$
! $Date:$
! $Revision:$
no ip access-list extended test-filter
ip access-list extended test-filter
 remark $Id:$


 remark deny-to-reserved
 deny ip any 0.0.0.0 0.255.255.255
 deny ip any 10.0.0.0 0.255.255.255


 remark deny-to-bogons
 deny ip any 192.0.0.0 0.0.0.255
 deny ip any 192.0.2.0 0.0.0.255


 remark allow-web-to-mail
 permit ip any host 200.1.1.4
 permit ip any host 200.1.1.5

exit
```

If we change `USE_MAIL_SERVER_SET` to 1 we can generate the Cisco ACL with an alternative host list.

```
$Id:$
! $Date:$
! $Revision:$
no ip access-list extended test-filter
ip access-list extended test-filter
 remark $Id:$


 remark deny-to-reserved
 deny ip any 0.0.0.0 0.255.255.255
 deny ip any 10.0.0.0 0.255.255.255


 remark deny-to-bogons
 deny ip any 192.0.0.0 0.0.0.255
 deny ip any 192.0.2.0 0.0.0.255


 remark allow-web-to-mail
 permit ip any host 200.1.2.4
 permit ip any host 200.1.2.5

exit
```
