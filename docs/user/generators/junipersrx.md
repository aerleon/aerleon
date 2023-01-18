
# JuniperSRX

> Note: The Juniper SRX generator is currently in beta testing.

## Header Format

```yaml
targets:
    srx: from-zone [zone name] to-zone [zone name] {inet}
```

* _from-zone_: static keyword, followed by user specified zone
* _to-zone_: static keyword, followed by user specified zone
* _inet_: Address family (only IPv4 tested at this time)

## Term Format

* for common keys see [common.md](common.md)

* _destination-exclude_: Exclude one or more address tokens from the specified destination-address
* _destination-zone_: one or more destination zones tokens. Only supported by global policy
* _dscp_except_: Do not match the DSCP number.
* _dscp_match_: Match a DSCP number.
* _dscp_set_: Match a DSCP set.
* _logging_: Specify that these packets should be logged.
  * Based on the input value the resulting logging actions will follow this logic:
    * _action_ is 'accept':
      * _logging_ is 'true': resulting SRX output will be 'log { session-close; }'
      * _logging_ is 'log-both': resulting SRX output will be 'log { session-init; session-close; }'
    * _action_ is 'deny':
      * _logging_ is 'true': resulting SRX output will be 'log { session-init; }'
      * _logging_ is 'log-both': resulting SRX output will be 'log { session-init; session-close; }'
    * See [here](https://kb.juniper.net/InfoCenter/index?page=content&id=KB16506) for explanation.
* _owner_: Owner of the term, used for organizational purposes.
* _source-exclude_: exclude one or more address tokens from the specified source-address.
* _source-zone_: one or more source zones tokens. Only supported by global policy
* _timeout_: specify application timeout. (default 60)
* _verbatim_: this specifies that the text enclosed within quotes should be rendered into the output without interpretation or modification.  This is sometimes used as a temporary workaround while new required features are being added.
* _vpn_: Encapsulate outgoing IP packets and decapsulate incomfing IP packets.

## Sub Tokens

### Actions

* _accept_
* _count_
* _deny_
* _dscp_
* _log_
* _reject_
