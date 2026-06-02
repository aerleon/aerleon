
# Aerleon nftables Fork — Spec & Change Log

A working notebook for forking Aerleon to extend its **nftables generator** for Linux/Ubuntu routers. Everything below was prototyped and verified against Aerleon installed from PyPI, except where explicitly marked **not yet implemented** or **spike-quality**.

> Key framing: a **fork** edits the built-in `nftables` generator and the shared parser directly. This is *different* from the earlier plugin approach — and it's actually **cleaner**, because you no longer need the plugin's two workarounds (see §4d).

---

## 1. Goal

Make Aerleon's nftables generator capable of generating real router rulesets. The built-in generator is a **stateful packet filter only** — `type filter`, hooks `input`/`output`, accept/deny. We want to add, in priority order:

1. **forward** hook (the router's core job)
2. **prerouting / postrouting** hooks
3. **named + negative priorities** (`mangle`, `srcnat`, `raw`, …)
4. **reject** action
5. **interface matching** (`iifname`/`oifname`) — needed for real router rules
6. **NAT** (`type nat` + `masquerade`, later `dnat`/`snat`)
7. **MSS clamp** (`tcp option maxseg size set …`)

The end state: publish the fork on GitHub, consume it as a pinned `git+https://…` dependency in other projects (venv or devcontainer), and feed generated `.nft` to routers via Ansible.

---

## 2. Feature status

| Feature | Built-in Aerleon | This fork | Verified in spike | Notes |
|---|:---:|:---:|:---:|---|
| input / output hooks | ✅ | ✅ | ✅ | unchanged |
| forward hook | ❌ | ✅ | ✅ | one-line hook-set change |
| prerouting / postrouting | ❌ | ✅ | ✅ | hook-set change |
| positive priority | ✅ | ✅ | ✅ | |
| named priority (`mangle`/`srcnat`/…) | ❌ | ✅ | ✅ | mapped to numbers |
| negative priority | ❌ (crashes) | ✅ | ✅ | via the **name** (raw `-150` is unparseable) |
| reject action | ❌ | ✅ | ✅ | already in parser `ACTIONS` |
| NAT masquerade (`type nat`) | ❌ | ✅ | ✅ | spike-quality; see §7 |
| NAT dnat / snat | ❌ | ✅ | ✅ | `dnat/snat to <ip>`; literal **or** named target; optional `nat-port` port remap |
| MSS clamp (`tcp-mss`) | ❌ | ✅ | ✅ | new token across 3 files |
| interface match (`iifname`/`oifname`) | ❌ | ✅ | ✅ | from the existing `source-/destination-interface` tokens |
| packet mark | ❌ | ❌ | ❌ | no token; out of scope |

Legend: ✅ done · ❌ not done.

> **Implementation note (post-spike):** every feature above is now implemented
> on the `feature/nftables-ext` branch and covered by regression tests in
> `tests/regression/nftables/nftables_fork_test.py` (assertion tests + full
> `.ref` snapshots that double as `nft -c -f` fixtures). One upstream bug was
> fixed along the way: the verdict-only rule branch emitted `ct state newaccept`
> (missing space) — invalid nft for interface-/NAT-only rules; see §4a-7.

---

## 3. Fork: setup & environment

### 3a. Develop the fork

```bash
git clone https://github.com/<you>/aerleon.git
cd aerleon
# get a real Python 3.10+ (NixOS: do this inside a devshell)
#   nix-shell -p python311
python3 -m venv .venv
source .venv/bin/activate          # NixOS: if a script chokes, call .venv/bin/<tool> directly
pip install -e .                   # EDITABLE: source edits take effect immediately
which aclgen && aclgen --help | head   # sanity: aclgen resolves into .venv
```

`pip install -e .` is the dev install — edit `aerleon/lib/nftables.py` in VS Code and the next `aclgen` run uses it, no reinstall.

**Branch hygiene (makes the "rebase forever" cost manageable + a future PR easy):**
- keep `main` tracking upstream, do all work on a `feature/nftables-ext` branch
- tag releases (`v1.0.0-nft`) so consumers pin deliberately
- `git diff upstream/main` should show *only* your ~25 lines

**NixOS notes:** Aerleon is pure Python, so the venv won't fight Nix. If the venv suddenly can't find Python (after a GC/update), don't debug it — `rm -rf .venv` and recreate.

### 3b. Consume the published fork in other projects

One line in `requirements.txt`, pinned to a **tag** (not `@main`):

```
git+https://github.com/<you>/aerleon.git@v1.0.0-nft
```

- pip clones + builds + installs it into `.venv`/the container. **Nothing lands in your repo** (it's a normal site-packages package, not a vendored role) — your existing `.gitignore` of `.venv/` is enough.
- Works identically in a **devcontainer** — same line, just runs at image-build time instead of script-runtime:
  ```dockerfile
  FROM mcr.microsoft.com/devcontainers/python:3.12
  COPY requirements.txt /tmp/
  RUN pip install --no-cache-dir -r /tmp/requirements.txt
  ```

**⚠️ The one real gotcha: `pip freeze` clobbers the git reference.** `pip freeze > requirements.txt` rewrites the `git+` line to a pinned `==` (often dropping the fork URL entirely → silently installs upstream PyPI Aerleon, losing your changes). Fix: never freeze over the source file.

```bash
pip3 install -r ./requirements.txt
pip3 freeze > ./requirements.lock.txt   # NOT > requirements.txt
```

(Same gotcha in a devcontainer; pin a tag so cached layers don't keep installing an old commit.)

---

## 4. Code changes (by file)

All changes are to the **built-in** generator + shared parser. Line numbers drift, so each is given as "find → change."

### 4a. `aerleon/lib/nftables.py`

**(1) Hooks** — relax the allow-list:
```python
# find:
_SUPPORTED_HOOKS = frozenset(('input', 'output'))
# replace:
_SUPPORTED_HOOKS = frozenset(('prerouting', 'input', 'forward', 'output', 'postrouting'))
```

**(2) Action → verdict map** — add reject + masquerade:
```python
# find:
_ACTIONS = {'accept': 'accept', 'deny': 'drop'}
# replace:
_ACTIONS = {'accept': 'accept', 'deny': 'drop', 'reject': 'reject', 'masquerade': 'masquerade'}
```

**(3) `_BuildTokens`** — allow the new action sub-tokens and the new match/mangle tokens:
```python
# in the 'action' sub-token set, add:
'reject',
'masquerade',
# in supported_tokens, add:
'tcp_mss',
# (when you add interface matching, also add:)
# 'source_interface',
# 'destination_interface',
```

**(4) Named/negative priorities** — add a class attribute and handle it in `_ProcessHeader`:
```python
# class attribute:
PRIORITY_ALIASES = {'raw': -300, 'mangle': -150, 'dstnat': -100,
                    'filter': 0, 'security': 50, 'srcnat': 100}

# in _ProcessHeader, BEFORE the existing isdigit() priority block:
_alias = [self.PRIORITY_ALIASES[x.lower()]
          for x in header_options if x.lower() in self.PRIORITY_ALIASES]
if _alias:
    netfilter_priority = _alias[0]
else:
    # ... existing isdigit() logic unchanged ...
```
> Note: you can only *write* named aliases in policy (the parser rejects a literal `-150`); the negative number appears only in the generated nft, which `nft` accepts fine.

**(5) NAT type-switch** — in `__str__`, replace the base-chain header/preamble block so chains containing a NAT verdict render as `type nat` with `policy accept` and no conntrack preamble:
```python
# find:
                nft_config.append(
                    TabSpacer(
                        8,
                        'type filter hook %s priority %s; policy %s;'
                        % (
                            base_chain_dict[item]['hook'],
                            base_chain_dict[item]['priority'],
                            base_chain_dict[item]['policy'],
                        ),
                    )
                )
                # stateful firewall: allow reply traffic.
                nft_config.append(TabSpacer(8, 'ct state established,related accept'))
# replace:
                _all_rules = []
                for _cc, _rules in base_chain_dict[item]['rules'][item].items():
                    _all_rules.extend(_rules)
                _is_nat = any(
                    (' masquerade' in r) or (' dnat ' in r) or (' snat ' in r)
                    for r in _all_rules
                )
                _ctype = 'nat' if _is_nat else 'filter'
                _policy = 'accept' if _is_nat else base_chain_dict[item]['policy']
                nft_config.append(
                    TabSpacer(
                        8,
                        'type %s hook %s priority %s; policy %s;'
                        % (_ctype, base_chain_dict[item]['hook'],
                           base_chain_dict[item]['priority'], _policy),
                    )
                )
                if not _is_nat:
                    nft_config.append(TabSpacer(8, 'ct state established,related accept'))
```
> Spike shortcut: detection sniffs the rendered rule text. Clean version: tag the chain as NAT during `_TranslatePolicy` instead.

**(6) MSS clamp render** — in `RulesetGenerator`, right after the verdict lookup:
```python
# find:
        verdict = self._ACTIONS[self.term.action[0]]
# add immediately after:
        if getattr(self.term, 'tcp_mss', None):
            _m = self.term.tcp_mss
            verdict = 'tcp flags syn tcp option maxseg size set ' + (
                'rt mtu' if _m in ('pmtu', 'rt-mtu', 'rt_mtu') else str(_m))
```

### 4b. `aerleon/lib/policy.py`

**masquerade action** (reject/count already present):
```python
# find:
ACTIONS = {'accept', 'count', 'deny', 'reject', 'next', 'reject-with-tcp-rst'}
# replace:
ACTIONS = {'accept', 'count', 'deny', 'reject', 'next', 'reject-with-tcp-rst', 'masquerade'}
```

**`tcp-mss` token** (mirrors the existing `ttl` token):
```python
# in class VarType (use any unused value < 256; 71 was free):
TCP_MSS = 71

# in Term.__init__, near self.ttl = None:
self.tcp_mss = None

# in the builder's elif-chain, near `elif obj.var_type is VarType.TTL:`:
elif obj.var_type is VarType.TCP_MSS:
    self.tcp_mss = obj.value
```

### 4c. `aerleon/lib/policy_builder.py`

**`tcp-mss` token** — four entries, each mirroring `ttl`:
```python
# RawTerm TypedDict (near "ttl": int | str):
"tcp-mss": str,

# token-type recognizer map (near 'ttl': TValue.Integer):
'tcp-mss': TValue.WordString,    # WordString so 'pmtu' and integers both parse

# VarType map (near 'ttl': (_CallType.SingleValue, VarType.TTL)):
'tcp-mss': (_CallType.SingleValue, VarType.TCP_MSS),

# allowed term-keys list (near 'ttl',):
'tcp-mss',
```

### 4d. NOT needed in a fork (these were plugin-only workarounds)

When forking you edit the built-in `nftables` target directly, so **delete the plugin** and do **not** carry over:

- `_PLATFORM = "nftables_forward"` → stays the built-in `"nftables"`.
- The `_TranslatePolicy` override that mirrored options onto an `"nftables"` target → unnecessary, because the generator's hardcoded `header.FilterOptions("nftables")` already matches the built-in target name.

Both existed only because the plugin used a *renamed* target. Gone in a fork.

### 4a-7. Verdict-only spacing fix (`GroupExpressions`)

A term with no address and no protocol/port match took the verdict-only branch,
which concatenated options and verdict directly → invalid nft like `ct state
newaccept`. This breaks interface-only and NAT-only rules. Fixed to join with a
single space (dropping empty options); deny-only rules (`drop`, no options) are
unaffected.
```python
# find:
            statement.append(Add(options) + verdict)
# replace:
            statement.append(' '.join(filter(None, [options, verdict])))
```

### 4e. Interface matching — IMPLEMENTED (`iifname`/`oifname`)

The tokens `source-interface` / `destination-interface` already parse. Added
`source_interface`/`destination_interface` to `_BuildTokens` and a
`_InterfaceStatement` that prefixes each rule line:
```python
# in RulesetGenerator, after GroupExpressions:
iface = self._InterfaceStatement(
    self.term.source_interface, self.term.destination_interface)
if iface:
    nftable_rule = [iface + Add(line) for line in nftable_rule]
```

`source-interface 'eth1'` → `iifname "eth1"`, `destination-interface 'eth0'` →
`oifname "eth0"`. This lets masquerade be WAN-scoped (`oifname "wan0" masquerade`)
instead of unconditional. Note: `oifname` is unavailable at the `prerouting`
hook — match inbound dnat rules on `source-interface` (iifname) instead.

### 4f. dnat / snat — IMPLEMENTED (`dnat to`/`snat to`)

Added `dnat`/`snat` to the parser `ACTIONS`, the generator `_ACTIONS` verdict
map and action sub-tokens, and registered `next_ip` as a supported token. The
translation target is resolved from the existing `next-ip` token (named network
only):
```python
# in RulesetGenerator, after the verdict lookup:
if self.term.action[0] in ('dnat', 'snat'):
    if not self.term.next_ip:
        raise TermError('Term %s uses %s but has no next-ip target.'
                        % (self.term.name, self.term.action[0]))
    verdict = '%s to %s' % (verdict, self.term.next_ip[0].network_address)
```

The `__str__` NAT detection already recognised `' dnat '`/`' snat '`, so these
chains render as `type nat … policy accept` automatically.

---

## 5. Repo layout & policy authoring (recap)

```
network-firewall/
├── aerleon/
│   ├── def/                     # EVERY file here is merged
│   │   ├── networks.yaml        # addresses (use `- address:` ; compose with `- name:`)
│   │   └── services.yaml        # ports
│   └── policies/
│       ├── includes/            # shared rule fragments — `terms:` only, no header
│       │   └── common.yaml
│       └── pol/                 # ONE file per host → ONE .nft (named after the file)
│           └── router1.pol.yaml
├── aerleon.yml                  # pins base/def/output dirs so `aclgen` runs flag-free
└── requirements.txt             # git+https://github.com/<you>/aerleon.git@v1.0.0-nft
```

- **`aclgen` only scans `pol/` subdirectories** (`**/pol` glob). Output filename = policy filename.
- **Definitions auto-merge** across all files in `def/`. Compose groups with `values: [ { name: OTHER } ]`.
- **Shared rules** live in `policies/includes/*.yaml` (just `terms:`), pulled into a policy with `- include: includes/foo.yaml` inside a filter's `terms:` list. Position = evaluation order.
- **`aerleon.yml`** (auto-loaded from CWD) pins paths so both CI and manual runs are just `aclgen`:
  ```yaml
  base_directory: ./aerleon/policies
  definitions_directory: ./aerleon/def
  output_directory: ./generated
  recursive: true
  ```

**nftables model reminders:**
- header = `<generator>: <family> <hook> [ACCEPT] [priority]` — e.g. `nftables: mixed forward mangle`.
- family: `inet`=IPv4 (`table ip`), `inet6`=IPv6, `mixed`=dual-stack (`table inet`).
- base chains default to `policy drop`; add **uppercase** `ACCEPT` to flip (lowercase is ignored).
- every term → a regular chain named after it; the base chain `jump`s to each. **Term/chain names must be unique within a file/table** (two terms named `default-deny` in one file → collision).
- the chain `policy drop` already drops unmatched traffic, so an explicit `default-deny` term is redundant.

---

## 6. Example policies (verify each feature)

**Router with SSH-safe input + forward in one file** (one `.nft`, two base chains):
```yaml
filters:
  - header:
      comment: "router1 forward"
      targets: { nftables: inet forward }
    terms:
      - include: includes/common_forward.yaml
      # no explicit default-deny needed; chain policy is drop
  - header:
      comment: "router1 input"
      targets: { nftables: inet input }
    terms:
      - name: allow-ssh
        destination-port: SSH
        protocol: tcp
        action: accept
```

**NAT masquerade** (postrouting):
```yaml
filters:
  - header:
      comment: "masquerade out"
      targets: { nftables: inet postrouting srcnat }
    terms:
      - name: masq-out
        source-address: LAN
        action: masquerade
```
→ renders `type nat hook postrouting priority 100; policy accept;` jumping to a `masquerade` rule.

**MSS clamp** (mangle slot on forward):
```yaml
filters:
  - header:
      comment: "clamp mss"
      targets: { nftables: inet forward mangle }
    terms:
      - name: clamp-mss
        protocol: tcp
        tcp-mss: pmtu          # or a fixed size, e.g. 1460
        action: accept
```
→ renders `… tcp flags syn tcp option maxseg size set rt mtu`.

**reject:**
```yaml
      - name: block-and-tell
        source-address: GUEST
        action: reject
```

**interface matching** (forward in eth1 → out eth0):
```yaml
filters:
  - header:
      comment: "lan to wan"
      targets: { nftables: inet forward }
    terms:
      - name: lan-out
        source-interface: eth1
        destination-interface: eth0
        source-address: LAN
        action: accept
```
→ renders `iifname "eth1" oifname "eth0" ip saddr 192.168.1.0/24 … accept`.

**dnat port-forward** (prerouting; inbound interface = iifname):
```yaml
filters:
  - header:
      comment: "publish https"
      targets: { nftables: inet prerouting dstnat }
    terms:
      - name: dnat-https
        source-interface: wan0
        protocol: tcp
        destination-port: HTTPS
        next-ip: 192.168.1.50   # literal IP, or a named network token
        nat-port: 8080          # OPTIONAL: remap to internal :8080
        action: dnat
```
→ renders `type nat hook prerouting priority -100; policy accept;` with
`iifname "wan0" tcp dport 443 … dnat to 192.168.1.50:8080` (drop `nat-port` for
a plain `dnat to 192.168.1.50`). Use `action: snat` + `next-ip` (+ optional
`nat-port`) in `postrouting` for source NAT.

**Composed networks + shared include** (multi-router, define once):
```yaml
# def/networks.yaml
networks:
  R1_USERS: { values: [ { address: 192.168.1.0/25 } ] }
  R2_USERS: { values: [ { address: 192.168.2.0/25 } ] }
  ALL_USERS: { values: [ { name: R1_USERS }, { name: R2_USERS } ] }
```

---

## 7. Caveats / TODO before production

All seven priority features are now implemented and unit-tested, but a few
rough edges remain before trusting output on a production router:

- **NAT masquerade/dnat/snat are done**, but dnat/snat targets must be a *named*
  network token (`next-ip` resolves names, not literal IPs) and only the first
  address is used (single host, no ranges).
- **Leftover `ct state new`** still appears on masquerade/dnat/snat/mss rules
  (harmless-but-redundant on the SYN clamp, mildly wrong on NAT). Suppress the
  stateful preamble for NAT/mangle terms (the `if 'deny' not in term.action`
  block that adds `ct state new`).
- **NAT detection is string-sniffing** the rendered rules — replace with a
  proper chain tag set during `_TranslatePolicy`.
- **No real `nft` validation done in-repo** — the dev sandbox has no privileged
  `nft`. The snapshot `.ref` fixtures are valid-by-inspection; run `nft -c -f
  <file>.nft` on a real box (or `sudo` locally) before trusting output.
- **Masquerade can now be WAN-scoped** via `destination-interface` (`oifname
  "wan0" masquerade`); it is only unconditional if you omit the interface.
- **Mixed nat+filter base chains share one table** (`filtering_policies`). nft
  allows it, but consider whether you want separate tables.
- **`oifname` is invalid at `prerouting`** — scope inbound dnat rules with
  `source-interface` (iifname), not `destination-interface`.

**The strategic reason to keep this clean:** every change is to **core files**, so this is a fork you must rebase against upstream forever. The sane endgame is an **upstream PR** — with the TODOs above polished (proper tagging, ct-state suppression, dnat/snat, interfaces), the diff is small and mergeable, which *eliminates* the rebase cost and benefits everyone. Until then, weigh the fork against simply hand-writing the handful of NAT/mangle lines per router (or Jinja-from-host_vars), which needs no fork at all.

---

## 8. Verification

```bash
# generate
aclgen      # with aerleon.yml present, or pass --base_directory/--definitions_directory/--output_directory

# validate ON THE TARGET (needs nftables installed)
nft -c -f generated/router1.pol.nft      # syntax check, no apply
sudo nft -f generated/router1.pol.nft    # apply live
```

Deployment context: ship `generated/<host>.nft` to each box and reload via Ansible (`copy` with `validate: "nft -c -f %s"` + a `systemctl reload nftables` handler), or include it from a base `/etc/nftables.conf`. Always keep an SSH-allow rule in the input chain before applying, and prefer a timed-rollback when pushing to remote routers.

---

## 9. Known issues & roadmap (tracked)

Stable IDs for the issues surfaced during the fork review. Status legend:
**Fixed** · **Accepted** (working as intended / won't change) · **Deferred**
(real, not now) · **Planned** (intend to do) · **Future** (someday/maybe).

| ID | Severity | Status | Summary |
| --- | --- | --- | --- |
| A1 | low | Accepted | NAT verdict lives in a regular child chain reached by `jump` from the `type nat` base chain, not inline in the base chain. nft generally allows this; verify once with `nft -c -f`. If it ever rejects, inline the NAT verdict into the base chain. |
| A2 | low | Accepted | All base chains for an address family share one table and there is no dedup of (hook, priority). Two same-hook chains with equal priority are **allowed by nft** but evaluate in undefined order. Pre-existing Aerleon/Capirca behaviour, not fork-introduced. Mitigation: give same-hook chains distinct priorities. |
| A3 | low | Accepted | The generator emits whatever interface tokens you write; `oifname` is invalid at `prerouting`/`input` (output iface unknown pre-routing). Author's responsibility: use `source-interface` (iifname) on ingress hooks, `destination-interface` (oifname) on egress hooks. Could add hook/direction validation later. |
| B1 | low | **Fixed** | `_OptionsHandler` added `ct state new` to every non-`deny` term, including masquerade/dnat/snat/mss — valid nft but a small semantic narrowing on NAT (skips `related`/untracked). Now suppressed for NAT actions and tcp-mss terms. |
| B2 | n/a | Deferred | One shared table (`filtering_policies`) holds filter + nat chains of different types/hooks. Valid and functional; separate tables per type would be cleaner (atomic per-table reloads). Not changing now. |
| C1 | medium | **Fixed** | NAT-type detection string-sniffed the rendered rule text (`' masquerade'`/`' dnat '`/`' snat '`), which also scanned comment lines (false-positive risk). Now the chain is tagged NAT from the actual term action during `_TranslatePolicy`. |
| D1 | — | **Fixed** | dnat/snat target now accepts a **literal IP** as well as a named token. Shared `_ResolveNextIp` in policy.py tries `GetNetAddr` then falls back to `nacaddr.IP` on `UndefinedAddressError`, so all platforms' `next-ip` gained literals (additive). |
| D2 | — | **Fixed** | Port translation via the new `nat-port` token → `dnat/snat to <ip>:<port>` (e.g. expose external :443 to internal :8080). |
| D3 | — | Deferred | dnat/snat to an **address range / pool** (`dnat to a-b`). Very low priority; still first-address/single-host only. |
| D4 | — | Future | Packet mark / `meta mark` — no token; out of scope for now. |
| D5 | — | Future | `counter` on NAT chains, separate logging chains, and other niceties. |

> **Strategic note:** B1 + C1 are exactly the polish the upstream-PR endgame in §7
> needs (proper NAT tagging + no spurious conntrack state). D1–D3 complete the
> NAT feature surface. A1–A3/B2 are accepted trade-offs documented for whoever
> reviews or rebases this fork.
