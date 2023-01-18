# Common

This lists contains all the common keys that are used across all generators (with a few highlighted exceptions).

## Term Format

* _action_: The action to take when matched. See Actions section for valid options.
* _comment_: A text comment enclosed in double-quotes.  The comment can extend over multiple lines if desired, until a closing quote is encountered.
* _destination-address_: One or more destination address tokens
* _destination-port_: One or more service definition tokens
* _expiration_: Stop rendering this term after specified date in YYYY-MM-DD format. E.g. 2000-12-31
* _icmp-type_: Specify icmp-type code to match, see [ICMP types](../icmp_types.md) for list of valid arguments (**Not** supported on: **aruba**, **gce**, **k8s**)
* _name_: Name of the term.
* _option_: See platforms supported Options section. (**Not** supported on: **k8s**, **gce**, **windows_advfirewall**, **windows_ipsec**)
* _platform_: one or more target platforms for which this term should ONLY be rendered. (**Not** supported on: **aruba**)
* _platform-exclude_: one or more target platforms for which this term should NEVER be rendered. (**Not** supported on: **aruba**)
* _protocol_: the network protocols this term will match, such as tcp, udp, icmp, or a numeric value.
* _source-address_: one or more source address tokens.
* _source-port_: one or more service definition tokens. (**Note** supported on: **aruba**, **k8s**)

<!--
build_in tokens:
            #'action',
            #'comment',
            #'destination_address',
            'destination_address_exclude',
            #'destination_port',
            #'expiration',
            #'icmp_type',
            'stateless_reply',
            #'name',  # obj attribute, not token
            #'option',
            #'protocol',
            #'platform',
            #'platform_exclude',
            #'source_address',
            'source_address_exclude',
            #'source_port',
            'translated',  # obj attribute, not token
            #'verbatim', -> too many exceptions
-->
