""" Aerleon API

This module accepts plain Python dictionaries and lists as input.
It allows users to use Aerleon's functionality without having to
deal with YAML files, command line scripts, or config files.

This module exposes two APIs:

* Generate API: Provides the policy-to-ACL capabilities of the aclgen
  command line tool.
* Check API: Provides the policy query capabilities of the aclcheck
  command line tool.

## Aerleon "Generate" API

The Generate API provides the full policy-to-ACL capabilities of
the aclgen command line tool. It accepts as input plain Python
dictionaries and lists.

This API provides a single method, "Generate()", that accepts a list of policies
and an IP/ports definition object and will transform each policies
into platform-specific configs. Each policy should be given as a Python
dictionary - no YAML is required here. The IP/ports definitions should be given
as a Naming object which can also be constructed from a Python dictionary.

### Example: Generating Cisco ACL Using the Generate API

In this example we want to generate a Cisco ACL named "test-filter". The
filter should first deny packets addressed to reserved or invalid IP addresses
("bogons") and then only accept traffic if it originates from network "9OCLOCK"
and addresses the mail server ("FOO_V6").

The policy is defined like so. This structure of nested Python dictionaries and keys
mirrors exactly the YAML policy file format. At the top level two keys must be defined:
"filename", which controls the name of all output files produced from this policy, and
"filters", which lists all filters in this policy. Within the "filters" list we
have a single filter, which must have a "header" section and a "terms" list. The
"header" instructs Aerleon to produce Cisco ACL output. The "terms" list defines
the access control behavior we want for this filter.

```
cisco_example_policy = {
    "filename": "cisco_example_policy",
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

Because this object is constructed in Python it can incorporate variable data. Users
might conditionally construct the policy as part of a network automation workflow.

Now the network names used in this example have to be defined. The naming definitions are
constructed as follows. In this example we are dynamically selecting between two sets of IP
addresses for the mail server.

```
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

Now to call the Generate method. We need to first construct a Naming object
and load the network definitions, then pass that to Generate along with the
policy object.

```
definitions = naming.Naming()
definitions.ParseDefinitionsObject(networks, "")
configs = api.Generate([cisco_example_policy], definitions)
acl = configs["cisco_example_policy.acl"]
```

At this point variable "acl" contains the Cisco ACL we want:
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

If we change USE_MAIL_SERVER_SET to 1 we can generate the Cisco ACL with an alternative host list.

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


## Aerleon "AclCheck" API

The AclCheck API provides the policy query capabilities of the aclcheck
command line tool. It accepts as input plain Python dictionaries and lists.


"""
import copy
import multiprocessing
import pathlib
import sys
import typing

from absl import logging

from aerleon.aclgen import (
    ACLGeneratorError,
    ACLParserError,
    RenderACL,
    WriteFiles,
    WriteList,
)
from aerleon.lib import (
    aclcheck,
    aclgenerator,
    naming,
    plugin_supervisor,
    policy,
    policy_builder,
)


def Generate(
    policies: "list[policy_builder.PolicyDict] | list[policy.Policy]",
    definitions: naming.Naming,
    output_directory: pathlib.Path = None,
    optimize: bool = False,
    shade_check: bool = False,
    expiration_weeks: int = 2,
    source_map: bool = False,
) -> "dict[str, str]":
    """Generate ACLs from policies.

    Args:
      policies: A list of dicts where each dict describes a policy. Each dict
        must have keys "filename" with a string value and "filters" with a list
        of filters. Each filter is a dictionary with "header" and "terms" keys.
        The structure of the filters and terms should exactly mirror the YAML
        policy file structure.

        Alternatively, a list of Policy objects.

      definitions: A naming.Naming object containing definitions for all network
        and service names used in the given policies.

      output_directory: Optional, a pathlib.Path specifying a directory to write
        all generated files. If output_directory is None the generated files will
        be returned to the caller as a dictionary. If output_directory is used,
        no data will be returned to the caller and the genereated files will be
        written to the filesystem. Default None.

      optimize: Optional, a boolean. Enables additional optimizations. Default false.

      shade_check: Optional, a boolean. Enables shade checking. Default false.

      exp_info: Optional, a number. Warnings will be generated for any policy terms
        with an expiration date less than this number of weeks in the future.
        Default value is 2.

    Returns:
      A dictionary mapping generated file names to their contents. Users should take
      care to use different file names for each given policy to avoid file name collisions.
      If option output_directory is used the generated files will be written to that output
      directory and no data will be returned to the caller.
    """

    context = multiprocessing.get_context()
    return _Generate(
        policies,
        definitions,
        context,
        output_directory,
        optimize,
        shade_check,
        exp_info=expiration_weeks,
        source_map=source_map,
    )


def _Generate(
    policies: "list[policy_builder.PolicyDict] | list[policy.Policy]",
    definitions: naming.Naming,
    context: multiprocessing.context.BaseContext,
    output_directory: pathlib.Path = None,
    optimize: bool = False,
    shade_check: bool = False,
    exp_info: int = 2,
    max_renderers: int = 1,
    source_map: bool = False,
) -> "dict[str, str]":

    # thead-safe list for storing files to write
    manager: multiprocessing.managers.SyncManager = context.Manager()
    write_files: WriteList = manager.list()
    errors: list = manager.list()
    generated_configs: dict = manager.dict()

    if max_renderers == 1:
        for input_policy in policies:
            _GenerateACL(
                input_policy,
                definitions,
                write_files,
                generated_configs,
                output_directory,
                optimize,
                shade_check,
                exp_info,
                source_map,
            )
    else:
        pool = context.Pool(processes=max_renderers)
        async_results: list[multiprocessing.pool.AsyncResult] = []
        for input_policy in policies:
            async_result = pool.apply_async(
                _GenerateACL,
                args=(
                    input_policy,
                    definitions,
                    write_files,
                    generated_configs,
                    output_directory,
                    optimize,
                    shade_check,
                    exp_info,
                    source_map,
                ),
            )
            async_results.append(async_result)
        pool.close()
        pool.join()
        for result in async_results:
            try:
                result.get()
            except (ACLParserError, ACLGeneratorError) as e:
                logging.warning('\n\nerror encountered in rendering process:\n%s\n\n', e)
                errors.append(e)

    if output_directory:
        WriteFiles(write_files)
        return None
    else:
        return dict(generated_configs)


def _GenerateACL(
    input_policy: "policy_builder.PolicyDict | policy.Policy",
    definitions: naming.Naming,
    write_files: WriteList,
    generated_configs: dict,
    output_directory: pathlib.Path = None,
    optimize: bool = False,
    shade_check: bool = False,
    exp_info: int = 2,
    source_map: bool = False,
):
    def _parsePolicy():
        if isinstance(input_policy, policy.Policy):
            return input_policy, input_policy.filename

        filename = input_policy.get("filename")
        try:
            policy_obj = policy.FromBuilder(
                policy_builder.PolicyBuilder(input_policy, definitions, optimize, shade_check)
            )
        except policy.ShadingError as e:
            logging.warning('shading errors for %s:\n%s', filename, e)
            return
        except (policy.Error, naming.Error) as e:
            raise ACLParserError(
                'Error parsing policy %s:\n%s%s' % (filename, sys.exc_info()[0], sys.exc_info()[1])
            ) from e

        return policy_obj, filename

    policy_obj, filename = _parsePolicy()
    if policy_obj is None:
        return

    platforms = set()
    for header in policy_obj.headers:
        platforms.update(header.platforms)

    acl_obj: aclgenerator.ACLGenerator
    plugin_supervisor.PluginSupervisor.Start()

    def _EmitACL(
        acl_obj: aclgenerator.ACLGenerator,
        acl_suffix: str,
        write_files: typing.List[typing.Tuple[pathlib.Path, str]],
        binary: bool = False,
        source_map: bool = False,
    ):
        if output_directory:
            RenderACL(
                acl_obj, acl_suffix, output_directory, filename, write_files, binary, source_map
            )
            return

        output_file = pathlib.Path(filename).with_suffix(acl_suffix).name
        generated_configs[output_file] = str(acl_obj)

        if source_map and acl_obj.HasSourceMap():
            map_suffix = '.map.json'
            output_file = pathlib.Path(filename).with_suffix(acl_suffix + map_suffix).name
            generated_configs[output_file] = str(acl_obj.GetSourceMap())

    for target in platforms:
        generator = plugin_supervisor.PluginSupervisor.generators.get(target)
        if not generator:
            logging.warning(f"No generator found for target \"{target}\", skipping target.")
            continue

        try:
            # special handling for pcap
            if target == 'pcap':
                acl_obj = generator(copy.deepcopy(policy_obj), exp_info)
                _EmitACL(
                    acl_obj,
                    '-accept' + acl_obj.SUFFIX,
                    write_files,
                    source_map=source_map,
                )
                acl_obj = generator(copy.deepcopy(policy_obj), exp_info, invert=True)
                _EmitACL(
                    acl_obj,
                    '-deny' + acl_obj.SUFFIX,
                    write_files,
                    source_map=source_map,
                )
            else:
                acl_obj = generator(copy.deepcopy(policy_obj), exp_info)
                _EmitACL(acl_obj, acl_obj.SUFFIX, write_files, source_map=source_map)

        except aclgenerator.Error as e:
            raise ACLGeneratorError(
                'Error generating target ACL for %s:\n%s' % (filename, e)
            ) from e


def AclCheck(
    input_policy: policy_builder.PolicyDict,
    definitions: naming.Naming,
    src: str = None,
    dst: str = None,
    sport: str = None,
    dport: str = None,
    proto: str = None,
):
    filename = input_policy.get("filename")
    try:
        check = aclcheck.AclCheck.FromPolicyDict(
            input_policy, definitions, src, dst, sport, dport, proto
        )
        return check.Summarize()
    except (policy.Error, naming.Error) as e:
        raise ACLParserError(
            'Error parsing policy %s:\n%s%s' % (filename, sys.exc_info()[0], sys.exc_info()[1])
        ) from e
