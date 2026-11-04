import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from msfauto.enumeration.web_mapper import map_web_application


class _MapperHandler(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        type(self).requests.append(("GET", self.path))
        if self.path == "/redirect":
            body = b'<html><a href="/must-not-crawl">redirect body</a></html>'
            self.send_response(302)
            self.send_header("Location", "/destination")
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/":
            body = (
                b'<html><a href="/inside?item=1">inside</a>'
                b'<a href="/redirect">redirect</a>'
                b'<a href="https://outside.example/secret">outside</a>'
                b'<a href="/logout">logout</a>'
                b'<form action="/submit" method="POST">'
                b'<input name="username" required><input name="password" type="password">'
                b'</form></html>'
            )
        else:
            body = b"<html><title>Inside</title></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        type(self).requests.append(("POST", self.path))
        self.send_response(500)
        self.end_headers()

    def log_message(self, *_args):
        pass


class WebMapperTests(unittest.TestCase):
    def setUp(self):
        _MapperHandler.requests = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _MapperHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1)

    def test_maps_same_origin_routes_query_parameters_and_form_metadata(self):
        results = map_web_application(
            "lab", "127.0.0.1", self.server.server_port, "http",
            max_pages=5, max_depth=2, max_requests=5,
        )
        completed = [item for item in results if item.status == "completed"]
        self.assertEqual(len(completed), 3)
        root = next(item for item in completed if item.attributes["path"] == "/")
        form = root.attributes["forms"][0]
        self.assertEqual(form["method"], "POST")
        self.assertEqual(form["action"], f"http://127.0.0.1:{self.server.server_port}/submit")
        self.assertEqual(
            [field["name"] for field in form["fields"]],
            ["username", "password"],
        )
        inside = next(item for item in completed if item.attributes["path"] == "/inside")
        self.assertEqual(inside.attributes["query_parameters"], ["item"])
        redirect = next(item for item in completed if item.attributes["path"] == "/redirect")
        self.assertTrue(redirect.attributes["redirect"])
        self.assertEqual(redirect.attributes["redirect_location"], "/destination")
        self.assertTrue(all(item.attributes["request_method"] == "GET" for item in results))
        self.assertFalse(any(method == "POST" for method, _ in _MapperHandler.requests))
        self.assertFalse(any(path == "/logout" for _, path in _MapperHandler.requests))
        self.assertFalse(any(path == "/must-not-crawl" for _, path in _MapperHandler.requests))
        self.assertFalse(any(path == "/destination" for _, path in _MapperHandler.requests))

    def test_rejects_invalid_hostnames_before_building_http_headers(self):
        with self.assertRaises(ValueError):
            map_web_application(
                "lab", "127.0.0.1", self.server.server_port, "http",
                hostname="bad.example\\r\\nX-Injected: yes",
            )

    def test_rejects_limits_above_hard_caps(self):
        with self.assertRaises(ValueError):
            map_web_application(
                "lab", "127.0.0.1", self.server.server_port, "http",
                max_requests=MAX_REQUESTS_PLUS_ONE,
            )


MAX_REQUESTS_PLUS_ONE = 13


if __name__ == "__main__":
    unittest.main()
