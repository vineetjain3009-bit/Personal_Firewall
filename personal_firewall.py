#!/usr/bin/env python3
"""A small, explicit-rule personal firewall manager.

The program keeps its own rule definitions in a JSON file.  It never changes
the operating system firewall unless a command includes ``--apply``.  On
Windows it manages only rules named ``PersonalFirewall-*`` through netsh; on
Linux it adds/removes matching iptables rules tagged ``personal-firewall``.

This is designed as a learning tool and an administrator-operated firewall
front end, not as a replacement for a kernel packet-filtering engine.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import platform
import re
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence


DEFAULT_RULE_FILE = Path("personal_firewall_rules.json")
RULE_PREFIX = "PersonalFirewall-"
COMMENT_TAG = "personal-firewall"


class FirewallError(RuntimeError):
    """An invalid rule or a failed operating-system firewall operation."""


@dataclass(frozen=True)
class Rule:
    """A deliberate, narrow network filtering rule.

    ``port`` means the local listening port for inbound rules and the remote
    destination port for outbound rules.  ``remote`` accepts an IP address,
    CIDR range, or ``any``.
    """

    id: str
    label: str
    direction: str
    action: str
    protocol: str
    port: str
    remote: str


def validate_port(value: str) -> str:
    if value.lower() == "any":
        return "any"
    try:
        port = int(value)
    except ValueError as exc:
        raise FirewallError("port must be an integer from 1 to 65535, or 'any'") from exc
    if not 1 <= port <= 65535:
        raise FirewallError("port must be between 1 and 65535")
    return str(port)


def validate_remote(value: str) -> str:
    if value.lower() == "any":
        return "any"
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise FirewallError("remote must be an IP address, CIDR range, or 'any'") from exc


def rule_from_dict(raw: dict) -> Rule:
    required = {"id", "label", "direction", "action", "protocol", "port", "remote"}
    if not required.issubset(raw):
        raise FirewallError("rule file contains an incomplete rule")
    rule = Rule(**{key: raw[key] for key in required})
    if rule.direction not in {"in", "out"} or rule.action not in {"allow", "block"}:
        raise FirewallError("rule file contains an invalid direction or action")
    if rule.protocol not in {"tcp", "udp", "any"}:
        raise FirewallError("rule file contains an invalid protocol")
    validate_port(rule.port)
    validate_remote(rule.remote)
    if rule.protocol == "any" and rule.port != "any":
        raise FirewallError("a port can only be used with tcp or udp")
    return rule


def load_rules(path: Path) -> list[Rule]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise FirewallError("rule file must contain a JSON list")
        return [rule_from_dict(item) for item in data]
    except json.JSONDecodeError as exc:
        raise FirewallError(f"cannot read {path}: invalid JSON") from exc


def save_rules(path: Path, rules: Sequence[Rule]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps([asdict(rule) for rule in rules], indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def command_text(command: Sequence[str]) -> str:
    return subprocess.list2cmdline(list(command)) if platform.system() == "Windows" else " ".join(command)


def windows_command(rule: Rule, *, delete: bool = False) -> list[str]:
    name = RULE_PREFIX + rule.id
    if delete:
        return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]

    command = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={name}",
        f"dir={rule.direction}",
        f"action={rule.action}",
        f"protocol={rule.protocol.upper()}",
        "profile=any",
        f"description={rule.label}",
    ]
    if rule.port != "any":
        command.append(f"localport={rule.port}" if rule.direction == "in" else f"remoteport={rule.port}")
    if rule.remote != "any":
        command.append(f"remoteip={rule.remote}")
    return command


def linux_command(rule: Rule, *, delete: bool = False) -> list[str]:
    # iptables and ip6tables are separate rule tables.  An explicit IPv6 CIDR
    # therefore selects ip6tables; an "any" rule targets the IPv4 table.
    binary = "iptables"
    if rule.remote != "any" and ipaddress.ip_network(rule.remote).version == 6:
        binary = "ip6tables"
    chain = "INPUT" if rule.direction == "in" else "OUTPUT"
    command = [binary, "-D" if delete else "-A", chain]
    if rule.protocol != "any":
        command.extend(["-p", rule.protocol])
    if rule.remote != "any":
        command.extend(["-s" if rule.direction == "in" else "-d", rule.remote])
    if rule.port != "any":
        command.extend(["--dport", rule.port])
    command.extend(["-m", "comment", "--comment", f"{COMMENT_TAG}:{rule.id}"])
    command.extend(["-j", "ACCEPT" if rule.action == "allow" else "DROP"])
    return command


def os_command(rule: Rule, *, delete: bool = False) -> list[str]:
    system = platform.system()
    if system == "Windows":
        return windows_command(rule, delete=delete)
    if system == "Linux":
        command = linux_command(rule, delete=delete)
        if not shutil.which(command[0]):
            raise FirewallError(f"{command[0]} was not found; install it or use a Windows host")
        return command
    raise FirewallError(f"{system} is not supported (use Windows or Linux)")


def apply_rule(rule: Rule, *, delete: bool, apply: bool) -> None:
    command = os_command(rule, delete=delete)
    state = "Would run" if not apply else "Running"
    print(f"{state}: {command_text(command)}")
    if not apply:
        return
    try:
        completed = subprocess.run(command, check=False, text=True, capture_output=True)
    except OSError as exc:
        raise FirewallError(f"could not start firewall command: {exc}") from exc
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()
        raise FirewallError(f"firewall command failed ({completed.returncode}): {detail}")
    print("Operating-system firewall rule updated.")


def print_rules(rules: Sequence[Rule]) -> None:
    if not rules:
        print("No saved rules. Use 'add' to create one.")
        return
    print(f"{'ID':8}  {'DIR':3}  {'ACTION':5}  {'PROTO':5}  {'PORT':5}  {'REMOTE':18}  LABEL")
    for rule in rules:
        print(f"{rule.id:8}  {rule.direction:3}  {rule.action:5}  {rule.protocol:5}  {rule.port:5}  {rule.remote:18}  {rule.label}")


def monitor_once() -> None:
    """Show the OS connection table; this observes sockets, not packet payloads."""
    if platform.system() == "Windows":
        command = ["netstat", "-ano"]
    elif shutil.which("ss"):
        command = ["ss", "-tuna"]
    else:
        command = ["netstat", "-tuna"]
    try:
        output = subprocess.run(command, check=True, text=True, capture_output=True).stdout.rstrip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise FirewallError(f"could not read the connection table: {exc}") from exc
    print(time.strftime("%Y-%m-%d %H:%M:%S"))
    print(output)


def safe_label(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 80 or not re.fullmatch(r"[A-Za-z0-9 ._:-]+", value):
        raise FirewallError("label must be 1-80 letters, digits, spaces, or . _ : -")
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Explicit, dry-run-by-default personal firewall manager. Administrator privileges are required with --apply."
    )
    result.add_argument("--rules", type=Path, default=DEFAULT_RULE_FILE, help=f"JSON rule file (default: {DEFAULT_RULE_FILE})")
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create an empty rule file")
    add = sub.add_parser("add", help="save a rule without changing the OS firewall")
    add.add_argument("--label", required=True)
    add.add_argument("--direction", choices=["in", "out"], required=True)
    add.add_argument("--action", choices=["allow", "block"], required=True)
    add.add_argument("--protocol", choices=["tcp", "udp", "any"], required=True)
    add.add_argument("--port", default="any")
    add.add_argument("--remote", default="any")
    sub.add_parser("list", help="list saved rules")
    apply = sub.add_parser("apply", help="apply one saved rule to the OS firewall")
    apply.add_argument("id")
    apply.add_argument("--apply", action="store_true", help="actually run the administrator firewall command")
    sync = sub.add_parser("sync", help="apply every saved rule")
    sync.add_argument("--apply", action="store_true", help="actually run administrator firewall commands")
    remove = sub.add_parser("remove", help="remove one managed operating-system rule")
    remove.add_argument("id")
    remove.add_argument("--apply", action="store_true", help="actually run the administrator firewall command")
    delete = sub.add_parser("delete", help="delete a rule from the local rule file")
    delete.add_argument("id")
    monitor = sub.add_parser("monitor", help="display active TCP/UDP sockets")
    monitor.add_argument("--interval", type=float, default=0, help="seconds between snapshots; 0 displays once")
    return result


def find_rule(rules: Sequence[Rule], rule_id: str) -> Rule:
    for rule in rules:
        if rule.id == rule_id:
            return rule
    raise FirewallError(f"no rule with id {rule_id!r}")


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "init":
            if args.rules.exists():
                raise FirewallError(f"{args.rules} already exists; refusing to overwrite it")
            save_rules(args.rules, [])
            print(f"Created {args.rules}")
            return 0
        if args.command == "monitor":
            while True:
                monitor_once()
                if args.interval <= 0:
                    return 0
                time.sleep(args.interval)

        rules = load_rules(args.rules)
        if args.command == "list":
            print_rules(rules)
        elif args.command == "add":
            port = validate_port(args.port)
            if args.protocol == "any" and port != "any":
                raise FirewallError("--port requires --protocol tcp or udp")
            rule = Rule(
                id=uuid.uuid4().hex[:8], label=safe_label(args.label), direction=args.direction,
                action=args.action, protocol=args.protocol, port=port, remote=validate_remote(args.remote),
            )
            save_rules(args.rules, [*rules, rule])
            print(f"Saved rule {rule.id}. Use 'apply {rule.id} --apply' to enforce it.")
        elif args.command == "apply":
            apply_rule(find_rule(rules, args.id), delete=False, apply=args.apply)
        elif args.command == "sync":
            for rule in rules:
                apply_rule(rule, delete=False, apply=args.apply)
        elif args.command == "remove":
            apply_rule(find_rule(rules, args.id), delete=True, apply=args.apply)
        elif args.command == "delete":
            find_rule(rules, args.id)
            save_rules(args.rules, [rule for rule in rules if rule.id != args.id])
            print(
                f"Deleted {args.id} from {args.rules}. This does not remove an already-applied OS rule; "
                "remove it before deleting its local definition."
            )
    except FirewallError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
