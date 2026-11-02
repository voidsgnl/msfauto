import unittest
from ipaddress import ip_address

from msfauto.scope import ScopeError, build_policy


class ScopePolicyTests(unittest.TestCase):
    def test_policy_permits_only_configured_network_and_ports(self) -> None:
        policy = build_policy(["192.168.56.0/24"], "22,445")

        self.assertTrue(policy.permits_address(ip_address("192.168.56.10")))
        self.assertFalse(policy.permits_address(ip_address("192.168.57.10")))
        self.assertTrue(policy.permits_port(445))
        self.assertFalse(policy.permits_port(80))

    def test_invalid_target_is_rejected(self) -> None:
        with self.assertRaisesRegex(ScopeError, "Invalid target"):
            build_policy(["not-an-ip"])

    def test_invalid_port_is_rejected(self) -> None:
        with self.assertRaisesRegex(ScopeError, "between 1 and 65535"):
            build_policy(["127.0.0.1"], "70000")
