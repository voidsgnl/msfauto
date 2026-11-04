from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit, urlunsplit
from uuid import uuid4

from .models import ServiceObservation

USER_AGENT = "MSFAuto/0.1"
MAX_PAGES = 12
MAX_DEPTH = 2
MAX_REQUESTS = 12
MAX_RESPONSE_BYTES = 256 * 1024
MAX_LINKS_PER_PAGE = 64
MAX_FORMS_PER_PAGE = 24
MAX_FIELDS_PER_FORM = 32
DEFAULT_TIMEOUT = 3.0
_SKIP_PATH_PARTS = {
    "logout", "log-out", "signout", "sign-out", "delete", "remove",
    "destroy", "unsubscribe",
}


@dataclass(frozen=True)
class WebOrigin:
    scheme: str
    hostname: str
    port: int
    connect_address: str

    @property
    def authority(self) -> str:
        default = 443 if self.scheme == "https" else 80
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        return host if self.port == default else f"{host}:{self.port}"

    @property
    def root_url(self) -> str:
        return f"{self.scheme}://{self.authority}/"


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, object]] = []
        self._form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.casefold(): value or "" for key, value in attrs}
        tag = tag.casefold()
        if tag == "a" and values.get("href") and len(self.links) < MAX_LINKS_PER_PAGE:
            self.links.append(values["href"][:2048])
        elif tag == "form" and len(self.forms) < MAX_FORMS_PER_PAGE:
            self._form = {
                "action": values.get("action", ""),
                "method": (values.get("method") or "get").upper()[:12],
                "enctype": values.get("enctype", "")[:128],
                "fields": [],
            }
            self.forms.append(self._form)
        elif tag in {"input", "select", "textarea", "button"} and self._form is not None:
            fields = self._form["fields"]
            if isinstance(fields, list) and len(fields) < MAX_FIELDS_PER_FORM:
                fields.append({
                    "name": values.get("name", "")[:128],
                    "type": values.get("type", tag)[:32],
                    "required": "required" in values,
                })

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "form":
            self._form = None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, origin: WebOrigin, timeout: float) -> None:
        context = ssl._create_unverified_context()
        super().__init__(origin.connect_address, origin.port, timeout=timeout, context=context)
        self._server_hostname = origin.hostname

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self._server_hostname)


def _canonical_url(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    return urlunsplit((parts.scheme.casefold(), parts.netloc.casefold(), path, parts.query, ""))


def _same_origin(url: str, origin: WebOrigin) -> bool:
    parts = urlsplit(url)
    try:
        port = parts.port or (443 if parts.scheme.casefold() == "https" else 80)
    except ValueError:
        return False
    return (
        parts.scheme.casefold() == origin.scheme
        and (parts.hostname or "").casefold() == origin.hostname.casefold()
        and port == origin.port
        and parts.username is None
        and parts.password is None
    )


def _skip_path(url: str) -> bool:
    parts = urlsplit(url)
    segments = {segment.casefold() for segment in parts.path.split("/") if segment}
    return bool(segments & _SKIP_PATH_PARTS)


def _request(origin: WebOrigin, url: str, timeout: float) -> tuple[int, dict[str, str], bytes]:
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    connection: http.client.HTTPConnection
    if origin.scheme == "https":
        connection = _PinnedHTTPSConnection(origin, timeout)
    else:
        connection = http.client.HTTPConnection(origin.connect_address, origin.port, timeout=timeout)
    try:
        connection.request(
            "GET", path,
            headers={"Host": origin.authority, "User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
        )
        response = connection.getresponse()
        headers: dict[str, str] = {}
        for key, value in response.getheaders()[:32]:
            headers[key.casefold()] = value[:512]
        body = response.read(MAX_RESPONSE_BYTES + 1)
        return response.status, headers, body[:MAX_RESPONSE_BYTES]
    finally:
        connection.close()


def map_web_application(
    workspace: str,
    target: str,
    port: int,
    scheme: str,
    *,
    hostname: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_pages: int = MAX_PAGES,
    max_depth: int = MAX_DEPTH,
    max_requests: int = MAX_REQUESTS,
) -> tuple[ServiceObservation, ...]:
    """Inventory same-origin GET routes and form metadata without submitting forms."""
    if scheme not in {"http", "https"}:
        raise ValueError("Web mapping supports only HTTP and HTTPS.")
    if not 1 <= port <= 65535 or timeout <= 0:
        raise ValueError("A valid port and positive timeout are required.")
    if not 1 <= max_pages <= MAX_PAGES or not 0 <= max_depth <= MAX_DEPTH:
        raise ValueError("Web mapping limits exceed the supported safety budget.")
    if not 1 <= max_requests <= MAX_REQUESTS:
        raise ValueError("Web mapping request budget exceeds the supported limit.")
    address = str(ipaddress.ip_address(target))
    host = (hostname or address).strip().rstrip(".").casefold()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Invalid web hostname.") from exc
        labels = host.split(".")
        if (
            not host
            or len(host) > 253
            or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels
            )
        ):
            raise ValueError("Invalid web hostname.")
    origin = WebOrigin(scheme, host, port, address)
    queue = deque([(origin.root_url, 0)])
    visited: set[str] = set()
    observations: list[ServiceObservation] = []
    requests_made = 0

    while queue and requests_made < max_requests and len(visited) < max_pages:
        current, depth = queue.popleft()
        current = _canonical_url(current)
        if current in visited or not _same_origin(current, origin) or _skip_path(current):
            continue
        visited.add(current)
        requests_made += 1
        try:
            status, headers, body = _request(origin, current, timeout)
            content_type = headers.get("content-type", "").casefold()
            parser = _PageParser()
            is_redirect = 300 <= status < 400
            if (
                not is_redirect
                and ("text/html" in content_type or "application/xhtml+xml" in content_type)
                and body
            ):
                parser.feed(body.decode("utf-8", errors="replace"))
                parser.close()
            forms: list[dict[str, object]] = []
            for form in parser.forms:
                action = urljoin(current, str(form.get("action") or current))
                if not _same_origin(action, origin):
                    continue
                forms.append({
                    **form,
                    "action": _canonical_url(action),
                })
            query_parameters = sorted({
                key[:128] for key, _ in parse_qsl(urlsplit(current).query, keep_blank_values=True)
            })
            attributes: dict[str, object] = {
                "url": current,
                "path": urlsplit(current).path or "/",
                "status_code": status,
                "redirect": is_redirect,
                "redirect_location": headers.get("location", "")[:2048],
                "content_type": content_type[:160],
                "response_bytes": len(body),
                "truncated": len(body) >= MAX_RESPONSE_BYTES,
                "depth": depth,
                "query_parameters": query_parameters,
                "forms": forms,
                "links_discovered": len(parser.links),
                "request_method": "GET",
                "form_submission_performed": False,
            }
            observations.append(ServiceObservation(
                observation_id=uuid4().hex,
                workspace=workspace,
                target=address,
                port=port,
                transport="tcp",
                protocol=scheme,
                kind="web_surface",
                status="completed",
                attributes=attributes,
                source="msfauto:web-mapper",
                confidence=8,
            ))
            if (
                not is_redirect
                and depth < max_depth
                and ("text/html" in content_type or "application/xhtml+xml" in content_type)
            ):
                for link in parser.links:
                    candidate = _canonical_url(urljoin(current, link))
                    if _same_origin(candidate, origin) and not _skip_path(candidate):
                        if candidate not in visited and len(queue) + len(visited) < max_pages:
                            queue.append((candidate, depth + 1))
        except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError, ValueError) as exc:
            observations.append(ServiceObservation(
                observation_id=uuid4().hex,
                workspace=workspace,
                target=address,
                port=port,
                transport="tcp",
                protocol=scheme,
                kind="web_surface",
                status="failed",
                attributes={
                    "url": current,
                    "depth": depth,
                    "error_type": type(exc).__name__,
                    "error": " ".join(str(exc).split())[:160],
                    "request_method": "GET",
                },
                source="msfauto:web-mapper",
                confidence=0,
            ))
    return tuple(observations)
