import tempfile
import unittest
from pathlib import Path

import personal_firewall as firewall


class PersonalFirewallTests(unittest.TestCase):
    def setUp(self):
        self.rule = firewall.Rule(
            id="a1b2c3d4",
            label="Block test service",
            direction="out",
            action="block",
            protocol="tcp",
            port="23",
            remote="203.0.113.0/24",
        )

    def test_windows_outbound_command_uses_remote_port(self):
        command = firewall.windows_command(self.rule)
        self.assertIn("dir=out", command)
        self.assertIn("remoteport=23", command)
        self.assertIn("remoteip=203.0.113.0/24", command)
        self.assertNotIn("localport=23", command)

    def test_linux_inbound_command_uses_source_address(self):
        inbound = firewall.Rule(
            id="a1b2c3d4", label="Block test service", direction="in", action="block",
            protocol="udp", port="53", remote="198.51.100.9/32",
        )
        command = firewall.linux_command(inbound)
        self.assertEqual(command[:3], ["iptables", "-A", "INPUT"])
        self.assertIn("-s", command)
        self.assertIn("198.51.100.9/32", command)
        self.assertIn("--dport", command)
        self.assertIn("DROP", command)

    def test_linux_ipv6_rule_uses_ip6tables(self):
        ipv6_rule = firewall.Rule(
            id="a1b2c3d4", label="Block IPv6 test", direction="out", action="block",
            protocol="tcp", port="443", remote="2001:db8::/32",
        )
        self.assertEqual(firewall.linux_command(ipv6_rule)[0], "ip6tables")

    def test_rules_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            firewall.save_rules(path, [self.rule])
            self.assertEqual(firewall.load_rules(path), [self.rule])

    def test_port_requires_specific_transport(self):
        with self.assertRaises(firewall.FirewallError):
            firewall.rule_from_dict({
                "id": "a1b2c3d4", "label": "invalid", "direction": "in", "action": "block",
                "protocol": "any", "port": "80", "remote": "any",
            })


if __name__ == "__main__":
    unittest.main()
