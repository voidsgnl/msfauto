import tempfile
import unittest
from pathlib import Path

from msfauto.discovery import DiscoveryError, parse_nmap_xml
from msfauto.scope import build_policy
from msfauto.storage import WorkspaceStore

NMAP_XML = """\
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.56.10" addrtype="ipv4"/>
    <hostnames><hostname name="lab-host"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class DiscoveryTests(unittest.TestCase):
    def test_parser_normalizes_and_filters_ports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.xml"
            path.write_text(NMAP_XML, encoding="utf-8")
            hosts = parse_nmap_xml(path, build_policy(["192.168.56.0/24"], "22"))

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].hostname, "lab-host")
        self.assertEqual(hosts[0].services[0].name, "ssh")
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
