import sqlite3
import tempfile
import unittest
from pathlib import Path

from msfauto.discovery import DiscoveryError, parse_nmap_xml
from msfauto.scope import build_policy
from msfauto.storage import WorkspaceStore

NMAP_XML = "<nmaprun>\n  <host>\n    <status state=\"up\"/>\n    <address addr=\"192.168.56.10\" addrtype=\"ipv4\"/>\n    <hostnames><hostname name=\"lab-host\"/></hostnames>\n    <ports>\n      <port protocol=\"tcp\" portid=\"22\">\n        <state state=\"open\"/>\n        <service name=\"ssh\" product=\"OpenSSH\" version=\"9.6p1\" method=\"probed\" conf=\"10\" extrainfo=\"Ubuntu 2ubuntu2\">\n          <cpe>cpe:/a:openbsd:openssh:9.6p1</cpe>\n        </service>\n      </port>\n      <port protocol=\"tcp\" portid=\"80\">\n        <state state=\"open\"/>\n        <service name=\"http\"/>\n      </port>\n    </ports>\n  </host>\n</nmaprun>\n"


class DiscoveryTests(unittest.TestCase):
    def test_parser_normalizes_and_filters_ports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.xml"
            path.write_text(NMAP_XML, encoding="utf-8")
            hosts = parse_nmap_xml(path, build_policy(["192.168.56.0/24"], "22"))

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].hostname, "lab-host")
        service = hosts[0].services[0]
        self.assertEqual(service.name, "ssh")
        self.assertEqual(service.product, "OpenSSH")
        self.assertEqual(service.version, "9.6p1")
        self.assertEqual(service.method, "probed")
        self.assertEqual(service.confidence, 10)
        self.assertEqual(service.extra_info, "Ubuntu 2ubuntu2")
        self.assertEqual(service.cpes, ("cpe:/a:openbsd:openssh:9.6p1",))
        self.assertEqual(service.source, "nmap")
        self.assertTrue(service.observed_at)
        self.assertEqual(len(hosts[0].services), 1)

    def test_parser_rejects_out_of_scope_result(self) -> None:
        xml = NMAP_XML.replace("192.168.56.10", "192.168.57.10")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.xml"
            path.write_text(xml, encoding="utf-8")
            with self.assertRaisesRegex(DiscoveryError, "outside"):
                parse_nmap_xml(path, build_policy(["192.168.56.0/24"]))

    def test_storage_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            scan_path = Path(directory) / "scan.xml"
            scan_path.write_text(NMAP_XML, encoding="utf-8")
            store = WorkspaceStore(path)
            hosts = parse_nmap_xml(scan_path, build_policy(["192.168.56.0/24"]))
            store.save_hosts("lab", hosts)
            restored = store.get_hosts("lab")
            self.assertEqual(restored[0].address, hosts[0].address)
            self.assertEqual(restored[0].services[0], hosts[0].services[0])

    def test_parser_rejects_invalid_service_confidence(self) -> None:
        xml = NMAP_XML.replace('conf="10"', 'conf="eleven"')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.xml"
            path.write_text(xml, encoding="utf-8")
            with self.assertRaisesRegex(DiscoveryError, "invalid service confidence"):
                parse_nmap_xml(path, build_policy(["192.168.56.0/24"]))

    def test_storage_migrates_legacy_service_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.sqlite3"
            with sqlite3.connect(path) as connection:
                connection.execute("""
                    CREATE TABLE discovery_hosts (
                        workspace TEXT NOT NULL, address TEXT NOT NULL,
                        status TEXT NOT NULL, hostname TEXT NOT NULL,
                        UNIQUE(workspace, address)
                    )
                """)
                connection.execute("""
                    CREATE TABLE discovery_services (
                        workspace TEXT NOT NULL, address TEXT NOT NULL,
                        port INTEGER NOT NULL, protocol TEXT NOT NULL,
                        state TEXT NOT NULL, name TEXT NOT NULL,
                        product TEXT NOT NULL, version TEXT NOT NULL,
                        UNIQUE(workspace, address, port, protocol)
                    )
                """)
                connection.execute(
                    "INSERT INTO discovery_hosts VALUES (?, ?, ?, ?)",
                    ("lab", "192.168.56.10", "up", "legacy-host"),
                )
                connection.execute(
                    "INSERT INTO discovery_services VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    ("lab", "192.168.56.10", 22, "tcp", "open", "ssh", "OpenSSH", "8.0"),
                )

            store = WorkspaceStore(path)
            restored = store.get_hosts("lab")
            self.assertEqual(restored[0].services[0].product, "OpenSSH")
            self.assertEqual(restored[0].services[0].method, "unknown")
            self.assertEqual(restored[0].services[0].confidence, 0)
            self.assertEqual(restored[0].services[0].cpes, ())
