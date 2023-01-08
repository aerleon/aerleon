# Service Files

Service files define symbolic names for services, commonly udp/tcp ports. Policy files may reference these names.

```
term accept-ssh-requests {
  source-address:: INTERNAL
  destination-port:: SSH
  protocol:: tcp
  counter:: ssh
  action:: accept
}
```

Service:

```
WHOIS = 43/udp
SSH = 22/tcp
TELNET = 23/tcp
SMTP = 25/tcp
MAIL_SERVICES = SMTP
                ESMTP
                SMTP_SSL
                POP_SSL
...skipped...
```

Users may wish to auto-generate address book files to keep them up to date. JSON and CSV are accepted for this reason.