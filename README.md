# Personal Firewall

`personal_firewall.py` is a compact Python project for learning how firewall
rules map to Windows Defender Firewall and Linux iptables. It stores a
reviewable rule set locally, displays active TCP/UDP socket tables, and only
changes the OS firewall after an explicit `--apply` flag.

It never disables the operating-system firewall, flushes chains, or touches
rules it did not create. The operating-system firewall (Windows Filtering
Platform / netsh or iptables) performs packet filtering; this project safely
manages a small, labelled subset of its rules.

## Requirements

- Python 3.10 or later
- **Windows:** run the enforcing commands from an Administrator PowerShell
  session. Windows Defender Firewall must be available.
- **Linux:** run the enforcing commands as root (for example with `sudo`),
  and install `iptables` with its `comment` match module.

No external Python packages are required.

## Quick start

Create an empty, local rule file:

```powershell
python .\personal_firewall.py init
```

Save an outbound rule that blocks Telnet to any host. This only writes the
local JSON rule definition; it does not affect networking.

```powershell
python .\personal_firewall.py add --label "Block outbound Telnet" --direction out --action block --protocol tcp --port 23 --remote any
python .\personal_firewall.py list
```

Review the command that would run, then enforce it only from an elevated
terminal, replacing `RULE_ID` with the value printed by `add`:

```powershell
python .\personal_firewall.py apply RULE_ID
python .\personal_firewall.py apply RULE_ID --apply
```

Remove the corresponding operating-system rule (the rule definition stays in
the JSON file so it can be re-applied later):

```powershell
python .\personal_firewall.py remove RULE_ID --apply
```

Delete a local rule definition after removing its OS rule:

```powershell
python .\personal_firewall.py delete RULE_ID
```

## Monitoring connections

Show the OS connection table once:

```powershell
python .\personal_firewall.py monitor
```

Refresh it every five seconds:

```powershell
python .\personal_firewall.py monitor --interval 5
```

The monitor intentionally reports socket metadata (addresses, ports, states,
and process IDs where the OS exposes them), not packet payloads.

## Rule model and scope

| Field | Meaning |
| --- | --- |
| `--direction in` | Incoming traffic; `--port` is the local destination port. |
| `--direction out` | Outgoing traffic; `--port` is the remote destination port. |
| `--action` | `allow` maps to ACCEPT/allow; `block` maps to DROP/block. |
| `--protocol` | `tcp`, `udp`, or `any`; a port requires TCP or UDP. |
| `--remote` | An IPv4/IPv6 address, CIDR range, or `any`. |

Rules are appended by iptables. Their real effect depends on rule order and
other local policy; in particular, an earlier firewall rule can win. On
Windows, rules are created with names such as `PersonalFirewall-a1b2c3d4` and
the supplied label as the description. On Linux, rules are tagged with
`personal-firewall:<id>`. Explicit IPv6 CIDRs use `ip6tables`; an `any`
address rule targets the IPv4 `iptables` table, so add a separate IPv6 CIDR
rule when you need IPv6 coverage.

## Safe operating practice

- Start with `apply` without `--apply` and inspect the emitted command.
- Test blocks against a noncritical service first; avoid remotely blocking the
  management connection you depend on.
- Back up or understand existing firewall policy before deploying on a server.
- This is an educational/local-management tool. Production firewall policy
  benefits from centralized configuration, auditing, and platform-native
  policy management.
