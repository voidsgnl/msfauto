import ipaddress
import socket
import ssl
import struct
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from msfauto.enumeration import enumerate_services
from msfauto.enumeration.http_fingerprint import fingerprint_http_html
from msfauto.enumeration.models import ServiceObservation
from msfauto.enumeration.runner import (
    _error_attributes,
    _ftp_probe,
    _http_probe,
    _smb_probe,
    _smtp_probe,
    _ssh_probe,
    _tls_probe,
)
from msfauto.scope import build_policy
from msfauto.storage import WorkspaceStore
from msfauto.storage.models import Host, Service


class _HTTPHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Server", "MSFAuto-Test")
        self.send_header("X-Test", "enumeration")
        self.end_headers()

    def do_GET(self):
        body = (
            b"<!doctype html><html><head><title>OWASP Juice Shop</title>"
            b'<meta name="generator" content="Angular">'
            b'<script src="/runtime.js"></script><script src="/main.js"></script>'
            b"</head><body><app-root ng-version='18.0'></app-root></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class EnumerationTests(unittest.TestCase):
    def test_error_attributes_preserve_bounded_diagnostic_detail(self):
        attributes = _error_attributes(ConnectionRefusedError("connection refused"))
        self.assertEqual(attributes["error_type"], "ConnectionRefusedError")
        self.assertEqual(attributes["error"], "connection refused")
        self.assertLessEqual(len(attributes["error"]), 160)

    def test_http_probe_records_status_and_bounded_headers(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _HTTPHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            service = Service(server.server_port, "tcp", "open", name="http")
            observations = _http_probe("lab", "127.0.0.1", service, 1.0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)
        self.assertEqual(observations[0].status, "completed")
        self.assertEqual(observations[0].attributes["method"], "HEAD")
        self.assertEqual(observations[0].attributes["status_code"], 200)
        self.assertIn("server", observations[0].attributes["headers"])
        app = next(item for item in observations if item.kind == "http_application_response")
        self.assertEqual(app.attributes["title"], "OWASP Juice Shop")
        names = [item["name"] for item in app.attributes["technologies"]]
        self.assertIn("OWASP Juice Shop", names)
        self.assertIn("Angular", names)

    def test_html_fingerprint_extracts_title_metadata_and_technology_evidence(self):
        result = fingerprint_http_html(
            {"content-type": "text/html", "server": "nginx"},
            b'<html><head><title>Example</title><meta name="generator" content="CMS"></head>'
            b'<body><div id="root" data-reactroot></div><script src="/assets/jquery.min.js"></script></body></html>',
            truncated=False,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["title"], "Example")
        self.assertEqual(result["meta"]["generator"], "CMS")
        names = [item["name"] for item in result["technologies"]]
        self.assertIn("React", names)
        self.assertIn("jQuery", names)

    def test_non_html_response_is_not_fingerprinted_as_an_application(self):
        self.assertIsNone(fingerprint_http_html(
            {"content-type": "application/json"}, b'{"ok":true}', truncated=False
        ))

    def test_html_fingerprint_marks_body_truncation(self):
        result = fingerprint_http_html(
            {"content-type": "text/html"}, b"<html><title>Partial</title>", truncated=True
        )
        self.assertTrue(result["truncated"])

    def test_unknown_tcp_service_is_identified_as_http_by_bounded_probe(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _HTTPHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        service = Service(
            server.server_port, "tcp", "open", name="ppp?", method="probed",
            confidence=3,
        )
        host = Host(
            address=ipaddress.ip_address("127.0.0.1"),
            status="up",
            services=(service,),
        )
        try:
            results = enumerate_services(
                "lab", (host,), build_policy(["127.0.0.1"], str(server.server_port)),
                timeout=1.0,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)
        observation = next(item for item in results if item.protocol == "http")
        self.assertEqual(observation.protocol, "http")
        self.assertEqual(observation.status, "completed")
        self.assertEqual(observation.attributes["status_code"], 200)
        self.assertEqual(observation.attributes["detected_by"], "active_http_probe")
        self.assertEqual(observation.attributes["nmap_fingerprint"]["name"], "ppp?")
        self.assertEqual(observation.attributes["nmap_fingerprint"]["confidence"], 3)
        self.assertTrue(any(item.kind == "http_application_response" for item in results))

    def test_unknown_tcp_service_with_non_http_response_is_not_classified(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve():
            conn, _ = listener.accept()
            with conn:
                conn.recv(1024)
                conn.sendall(b"not an HTTP response\r\n")
            listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        host = Host(
            address=ipaddress.ip_address("127.0.0.1"),
            status="up",
            services=(Service(port, "tcp", "open", name="unknown"),),
        )
        try:
            results = enumerate_services(
                "lab", (host,), build_policy(["127.0.0.1"], str(port)), timeout=1.0
            )
        finally:
            thread.join(timeout=1)
            listener.close()
        self.assertEqual(results, ())

    def test_ssh_probe_records_server_banner(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve():
            conn, _ = listener.accept()
            with conn:
                conn.sendall(b"SSH-2.0-OpenSSH_9.8\r\n")
            listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            service = Service(port, "tcp", "open", name="ssh")
            observations = _ssh_probe("lab", "127.0.0.1", service, 1.0)
        finally:
            thread.join(timeout=1)
        self.assertEqual(observations[0].status, "completed")
        self.assertEqual(observations[0].attributes["banner"], "SSH-2.0-OpenSSH_9.8")

    def test_smtp_probe_records_greeting_and_ehlo_capabilities(self):
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve():
            conn, _ = listener.accept()
            with conn:
                conn.sendall(b"220 test.example ESMTP ready\r\n")
                data = conn.recv(2048)
                self.assertTrue(data.upper().startswith(b"EHLO "))
                conn.sendall(
                    b"250-test.example\r\n"
                    b"250-SIZE 10485760\r\n"
                    b"250-STARTTLS\r\n"
                    b"250-AUTH PLAIN LOGIN\r\n"
                    b"250 HELP\r\n"
                )
                conn.recv(1024)
                conn.sendall(b"221 Bye\r\n")
            listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            service = Service(port, "tcp", "open", name="smtp")
            observations = _smtp_probe("lab", "127.0.0.1", service, 1.0)
        finally:
            thread.join(timeout=1)
            listener.close()
        self.assertEqual(observations[0].status, "completed")
        attrs = observations[0].attributes
        self.assertEqual(attrs["greeting_code"], 220)
        self.assertTrue(attrs["supports_starttls"])
        self.assertEqual(attrs["auth_mechanisms"], ["PLAIN", "LOGIN"])
        self.assertIn("size", attrs["capabilities"])

    def test_enumeration_respects_address_port_and_service_fingerprint(self):
        host = Host(
            address=ipaddress.ip_address("127.0.0.1"),
            status="up",
            services=(
                Service(8080, "tcp", "open", name="http"),
                Service(22, "tcp", "open", name="ssh"),
                Service(9000, "tcp", "open", name="unknown"),
                Service(8081, "tcp", "closed", name="http"),
            ),
        )
        policy = build_policy(["127.0.0.1"], "8080,22")
        with patch("msfauto.enumeration.runner._http_probe", return_value=()) as http_probe, patch(
            "msfauto.enumeration.runner._ssh_probe", return_value=()
        ) as ssh_probe:
            results = enumerate_services("lab", (host,), policy)
        self.assertEqual(results, ())
        http_probe.assert_called_once()
        ssh_probe.assert_called_once()

    def test_out_of_scope_host_is_never_probed(self):
        host = Host(
            address=__import__("ipaddress").ip_address("192.0.2.10"),
            status="up",
            services=(Service(80, "tcp", "open", name="http"),),
        )
        with patch("msfauto.enumeration.runner._http_probe") as probe:
            self.assertEqual(
                enumerate_services("lab", (host,), build_policy(["127.0.0.1"])),
                (),
            )
        probe.assert_not_called()


    def test_observations_round_trip_through_workspace_store(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "workspace.sqlite3")
            observation = ServiceObservation(
                observation_id="observation-1",
                workspace="lab",
                target="127.0.0.1",
                port=443,
                transport="tcp",
                protocol="tls",
                kind="tls_response",
                status="completed",
                attributes={"tls_version": "TLSv1.3", "cipher": "TEST"},
                confidence=8,
                observed_at="2026-11-03T00:00:00+00:00",
            )
            store.save_service_observations((observation,))
            self.assertEqual(store.get_service_observations("lab"), (observation,))
            self.assertEqual(
                store.get_service_observations("another-workspace"), ()
            )

    def test_tls_probe_records_certificate_and_handshake_metadata(self):
        fixture_dir = Path(__file__).parents[1] / "fixtures"
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            fixture_dir / "tls-cert.pem",
            fixture_dir / "tls-key.pem",
        )
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve():
            conn, _ = listener.accept()
            with conn, context.wrap_socket(conn, server_side=True):
                pass
            listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            service = Service(port, "tcp", "open", name="ldaps", tunnel="ssl")
            observations = _tls_probe("lab", "127.0.0.1", service, 1.0)
        finally:
            thread.join(timeout=1)
            listener.close()

        self.assertEqual(observations[0].status, "completed")
        attributes = observations[0].attributes
        self.assertTrue(attributes["certificate_present"])
        self.assertEqual(len(attributes["certificate_sha256"]), 64)
        self.assertGreater(attributes["certificate_size"], 0)
        self.assertIn(attributes["tls_version"], {"TLSv1.2", "TLSv1.3"})
        self.assertTrue(attributes["cipher"])
        self.assertIn("session_reused", attributes)

    def test_tls_wrapped_non_http_service_is_not_misclassified_as_http(self):
        service = Service(636, "tcp", "open", name="ldaps", tunnel="ssl")
        host = Host(
            address=ipaddress.ip_address("127.0.0.1"),
            status="up",
            services=(service,),
        )
        policy = build_policy(["127.0.0.1"], "636")
        with patch(
            "msfauto.enumeration.runner._tls_probe", return_value=()
        ) as tls_probe, patch(
            "msfauto.enumeration.runner._http_probe"
        ) as http_probe:
            enumerate_services("lab", (host,), policy)
        tls_probe.assert_called_once()
        http_probe.assert_not_called()

    def test_ftp_probe_records_greeting_and_features(self):
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve():
            conn, _ = listener.accept()
            with conn:
                conn.sendall(b"220 Test FTP ready\r\n")
                command = conn.recv(1024)
                if command.upper().startswith(b"FEAT"):
                    conn.sendall(
                        b"211-Features\r\n UTF8\r\n SIZE\r\n211 End\r\n"
                    )
            listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            service = Service(port, "tcp", "open", name="ftp")
            observations = _ftp_probe("lab", "127.0.0.1", service, 1.0)
        finally:
            thread.join(timeout=1)
            listener.close()
        self.assertEqual(observations[0].status, "completed")
        self.assertIn("220 Test FTP ready", observations[0].attributes["welcome"])
        self.assertEqual(observations[0].attributes["features"], ["UTF8", "SIZE"])

    def test_smb_probe_negotiates_without_authentication(self):
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve():
            conn, _ = listener.accept()
            with conn:
                prefix = conn.recv(4)
                request_size = int.from_bytes(prefix[1:], "big")
                remaining = request_size
                while remaining:
                    chunk = conn.recv(remaining)
                    if not chunk:
                        break
                    remaining -= len(chunk)
                response = bytearray(128)
                response[0:4] = b"\xfeSMB"
                struct.pack_into("<H", response, 4, 64)
                struct.pack_into("<I", response, 8, 0)
                struct.pack_into("<H", response, 12, 0)
                struct.pack_into("<H", response, 64, 65)
                struct.pack_into("<H", response, 66, 1)
                struct.pack_into("<H", response, 68, 0x0300)
                response[72:88] = bytes.fromhex(
                    "00112233445566778899aabbccddeeff"
                )
                struct.pack_into("<IIII", response, 88, 0, 65536, 65536, 65536)
                conn.sendall(b"\x00" + len(response).to_bytes(3, "big") + response)
            listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            service = Service(port, "tcp", "open", name="microsoft-ds")
            observations = _smb_probe("lab", "127.0.0.1", service, 1.0)
        finally:
            thread.join(timeout=1)
            listener.close()
        self.assertEqual(observations[0].status, "completed")
        self.assertEqual(observations[0].attributes["dialect"], "0x0300")
        self.assertEqual(observations[0].attributes["max_read_size"], 65536)

    def test_invalid_worker_count_is_rejected(self):
        with self.assertRaises(ValueError):
            enumerate_services("lab", (), build_policy(["127.0.0.1"]), max_workers=99)
