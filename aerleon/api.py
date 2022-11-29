"""Aerleon Python API

"""

from aerleon.lib import naming
from aerleon.lib import policy
from aerleon.lib import policy_builder


def Generate(
    policies, service_names, network_names, write_dir=None, optimize=False, shade_check=False
) -> dict[str, str]:
    generated_configs = {}
    definitions = naming.Naming()
    definitions.ParseServiceList(_BuildNamingLines(service_names, "services"))
    definitions.ParseNetworkList(_BuildNamingLines(network_names, "networks"))

    pols = []
    for input_policy in policies:
        raw_filters = []
        input_filters = input_policy["filters"]
        filename = input_policy.get("filename")
        for filter in input_filters:

            filter_header = filter["header"]
            header_targets = filter_header["targets"]
            raw_filter_header = policy_builder.RawFilterHeader(
                targets=header_targets, kvs=filter_header
            )

            raw_terms = []
            filter_terms = filter["terms"]
            for term in filter_terms:
                raw_term = policy_builder.RawTerm(name=term["name"], kvs=term)
                raw_terms.append(raw_term)

            raw_filters.append(policy_builder.RawFilter(header=raw_filter_header, terms=raw_terms))

        raw_policy = policy_builder.RawPolicy(filename=filename, filters=raw_filters)
        policy_obj = policy.FromBuilder(
            policy_builder.PolicyBuilder(raw_policy, definitions, optimize, shade_check)
        )
        pols.append(policy_obj)

    if write_dir:
        # TODO write to file
        return None
    else:
        return generated_configs


def _BuildNamingLines(data: dict[str, dict], definition_type: str):
    """Convert to Naming line format.

    Arguments:
        data: A dictionary mapping names to item lists. Each item in the item
            list should contain a name OR a protocol/port (if definition_type is
            "services") OR an ip (if definition_type is "networks"). Each item
            may contain a comment.
        definition_type: A string containing either "services" or "networks". This
            should correspond to the type of data present in the 'data' argument.

    Returns:
        A list of strings which can be understood by the Naming constructor.
    """
    # Note: eventually this should get extracted to a NamingBuilder pattern
    # and share with YAML address books

    lines = []
    for name, item_list in data.items():
        if not item_list:
            continue

        found_items = []
        for item in item_list:
            content = None
            comment = item.get("comment")
            if "name" in item:
                content = item['name']
            elif definition_type == "services":
                content = f"{item['port']}/{item['protocol']}"
            elif definition_type == "networks":
                content = f"{item['ip']}"
            else:
                raise TypeError("Unexpected definition type")

            if comment is not None:
                found_items.append(f"{content} # {comment}")
            else:
                found_items.append(content)

        new_lines = []
        new_lines.append(f"{name} = {found_items[0]}")

        for item in found_items[1:]:
            new_lines.append(f"    {found_items[0]}")

        lines.extend(new_lines)
    return lines
