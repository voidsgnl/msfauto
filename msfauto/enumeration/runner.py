from __future__ import annotations

import ftplib
import hashlib
import http.client
import socket
import ssl
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from uuid import uuid4

from ..storage.models import Host, ScopePolicy, Service
from .models import ServiceObservation
from .http_fingerprint import MAX_HTML_BYTES, fingerprint_http_html

DEFAULT_TIMEOUT = 3.0
MAX_WORKERS = 8
MAX_HEADERS = 32
MAX_VALUE_LENGTH = 512
MAX_BANNER_LENGTH = 255


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _observation(
    workspace: str,
    target: str,
    service: Service,
    protocol: str,
    status: str,
    attributes: dict[str, object],
    confidence: int = 7,
) -> ServiceObservation:
    return ServiceObservation(
        observation_id=uuid4().hex,
        workspace=workspace,
        target=target,
        port=service.port,
        transport=service.protocol,
        protocol=protocol,
        kind=f"{protocol}_response",
        status=status,
        attributes=attributes,
        confidence=confidence if status in {"completed", "partial"} else 0,
        observed_at=_now(),
    )


def _is_http(service: Service) -> bool:
    label = f"{service.name} {service.product}".lower()
    return service.protocol.lower() == "tcp" and "http" in label


def _is_tls(service: Service) -> bool:
    tls_ports = {443, 465, 636, 853, 989, 990, 992, 993, 995, 5061, 8443}
    return service.protocol.lower() == "tcp" and (
        service.tunnel.lower() == "ssl" or service.port in tls_ports
    )


def _is_ssh(service: Service) -> bool:
    label = f"{service.name} {service.product}".lower()
    return service.protocol.lower() == "tcp" and "ssh" in label


def _is_ftp(service: Service) -> bool:
    label = f"{service.name} {service.product}".lower()
    return service.protocol.lower() == "tcp" and service.port != 20 and (
        "ftp" in label or service.port == 21
    )


def _is_smb(service: Service) -> bool:
    label = f"{service.name} {service.product}".lower()
    return service.protocol.lower() == "tcp" and (
        "smb" in label or service.port == 445
    )


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("SMB peer closed the connection")
        data.extend(chunk)
    return bytes(data)


def _smb_probe(
    workspace: str, target: str, service: Service, timeout: float
) -> tuple[ServiceObservation, ...]:
    # SMB2 NEGOTIATE only: no session setup, credentials, or file operations.
    header = struct.pack(
        "<4sHHHHHHIIQIIQ16s",
        b"\xfeSMB", 64, 0, 0, 0, 0, 1, 0, 0, 0, 0xFEFF, 0, 0,
        bytes(16),
    )
    body = struct.pack(
        "<HHHHI16sIHH",
        36, 3, 1, 0, 0, bytes.fromhex("00112233445566778899aabbccddeeff"),
        0, 0, 0,
    )
    request = header + body + struct.pack("<HHH", 0x0202, 0x0210, 0x0300)
    framed = b"\x00" + len(request).to_bytes(3, "big") + request
    try:
        with socket.create_connection((target, service.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(framed)
            prefix = _recv_exact(sock, 4)
            if prefix[0] != 0:
                raise ValueError("Unexpected SMB transport framing")
            length = int.from_bytes(prefix[1:], "big")
            if length < 128 or length > 65536:
                raise ValueError("SMB response length is outside accepted bounds")
            response = _recv_exact(sock, length)
        if response[:4] != b"\xfeSMB" or len(response) < 128:
            raise ValueError("Peer did not return a valid SMB2 negotiate response")
        status_code = struct.unpack_from("<I", response, 8)[0]
        command = struct.unpack_from("<H", response, 12)[0]
        structure_size = struct.unpack_from("<H", response, 64)[0]
        if command != 0 or structure_size != 65:
            raise ValueError("Unexpected SMB2 response command or structure")
        security_mode, dialect = struct.unpack_from("<HH", response, 66)
        server_guid = response[72:88].hex()
        capabilities, max_transact, max_read, max_write = struct.unpack_from(
            "<IIII", response, 88
        )
        attributes: dict[str, object] = {
            "status_code": status_code,
            "dialect": f"0x{dialect:04x}",
            "security_mode": security_mode,
            "server_guid": server_guid,
            "capabilities": capabilities,
            "max_transact_size": max_transact,
            "max_read_size": max_read,
            "max_write_size": max_write,
        }
        success = status_code == 0
        return (
            _observation(
                workspace, target, service, "smb",
                "completed" if success else "partial", attributes,
                confidence=9 if success else 3,
            ),
        )
    except (OSError, TimeoutError, ConnectionError, ValueError, struct.error) as exc:
        return (
            _observation(
                workspace, target, service, "smb", "failed",
                {"error_type": type(exc).__name__},
            ),
        )


def _tls_probe(
    workspace: str, target: str, service: Service, timeout: float
) -> tuple[ServiceObservation, ...]:
    """Inspect a TLS endpoint without sending application-layer requests."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(
            (target, service.port), timeout=timeout
        ) as raw_socket:
            raw_socket.settimeout(timeout)
            with context.wrap_socket(
                raw_socket, server_hostname=target
            ) as tls_socket:
                cipher = tls_socket.cipher()
                certificate = tls_socket.getpeercert(binary_form=True) or b""
                attributes: dict[str, object] = {
                    "tls_version": tls_socket.version() or "",
                    "cipher": cipher[0] if cipher else "",
                    "cipher_protocol": cipher[1] if cipher else "",
                    "cipher_bits": cipher[2] if cipher else 0,
                    "certificate_present": bool(certificate),
                    "certificate_sha256": (
                        hashlib.sha256(certificate).hexdigest()
                        if certificate else ""
                    ),
                    "certificate_size": len(certificate),
                    "alpn_protocol": tls_socket.selected_alpn_protocol() or "",
                    "compression": tls_socket.compression() or "",
                    "session_reused": tls_socket.session_reused,
                }
        return (
            _observation(
                workspace, target, service, "tls", "completed", attributes,
                confidence=9 if attributes["certificate_present"] else 5,
            ),
        )
    except (OSError, ssl.SSLError, TimeoutError, ValueError) as exc:
        return (
            _observation(
                workspace, target, service, "tls", "failed",
                {"error_type": type(exc).__name__},
            ),
        )


def _ftp_probe(
    workspace: str, target: str, service: Service, timeout: float
) -> tuple[ServiceObservation, ...]:
    client = ftplib.FTP()
    try:
        welcome = client.connect(target, service.port, timeout=timeout)
        attributes: dict[str, object] = {
            "welcome": (welcome or "")[:MAX_VALUE_LENGTH],
            "features": [],
        }
        try:
            response = client.sendcmd("FEAT")
            lines = response.splitlines()
            attributes["features"] = [
                line.strip()[:MAX_VALUE_LENGTH]
                for line in lines[1:-1][:32]
            ]
        except ftplib.error_perm as exc:
            # FEAT is optional; a valid greeting is still useful evidence.
            attributes["feat_status"] = str(exc)[:MAX_VALUE_LENGTH]
        return (
            _observation(
                workspace, target, service, "ftp", "completed", attributes,
                confidence=8 if attributes["features"] else 6,
            ),
        )
    except (OSError, EOFError, ftplib.Error, TimeoutError) as exc:
        return (
            _observation(
                workspace, target, service, "ftp", "failed",
                {"error_type": type(exc).__name__},
            ),
        )
    finally:
        try:
            client.close()
        except OSError:
            pass


def _http_probe(
    workspace: str,
    target: str,
    service: Service,
    timeout: float,
    *,
    unidentified_service: bool = False,
) -> tuple[ServiceObservation, ...]:
    secure = service.name.lower() == "https" or service.tunnel.lower() == "ssl"
    if secure:
        context = ssl._create_unverified_context()
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            target, service.port, timeout=timeout, context=context
        )
        protocol = "https"
    else:
        connection = http.client.HTTPConnection(target, service.port, timeout=timeout)
        protocol = "http"

    try:
        connection.request("HEAD", "/", headers={"User-Agent": "MSFAuto/0.1"})
        response = connection.getresponse()
        headers = {
            key.lower(): value[:MAX_VALUE_LENGTH]
            for key, value in response.getheaders()[:MAX_HEADERS]
        }
        if unidentified_service and (
            response.version not in {10, 11} or not 100 <= response.status <= 599
        ):
            return ()
        attributes: dict[str, object] = {
            "status_code": response.status,
            "reason": (response.reason or "")[:MAX_VALUE_LENGTH],
            "http_version": f"HTTP/{response.version // 10}.{response.version % 10}",
            "headers": headers,
            "method": "HEAD",
            "path": "/",
            "detected_by": (
                "active_http_probe" if unidentified_service
                else "nmap_service_fingerprint"
            ),
            "nmap_fingerprint": {
                "name": service.name,
                "product": service.product,
                "version": service.version,
                "method": service.method,
                "confidence": service.confidence,
                "tunnel": service.tunnel,
            },
        }
        observations = [
            _observation(workspace, target, service, protocol, "completed", attributes)
        ]
        # Fetch a small HTML prefix only when the endpoint advertises HTML.
        # Redirects are not followed; the observed origin remains unambiguous.
        response.read()
        connection.request(
            "GET", "/", headers={
                "User-Agent": "MSFAuto/0.1",
                "Range": f"bytes=0-{MAX_HTML_BYTES - 1}",
            },
        )
        page = connection.getresponse()
        page_headers = {
            key.lower(): value[:MAX_VALUE_LENGTH]
            for key, value in page.getheaders()[:MAX_HEADERS]
        }
        if page.status < 300 or page.status >= 400:
            body = page.read(MAX_HTML_BYTES + 1)
            truncated = len(body) > MAX_HTML_BYTES
            page_fingerprint = fingerprint_http_html(
                page_headers, body[:MAX_HTML_BYTES], truncated=truncated
            )
            if page_fingerprint is not None:
                observations.append(
                    _observation(
                        workspace, target, service, "http_application",
                        "completed", {
                            **page_fingerprint,
                            "status_code": page.status,
                            "headers": page_headers,
                            "detected_by": "bounded_html_fingerprint",
                            "nmap_fingerprint": attributes["nmap_fingerprint"],
                        },
                        confidence=8 if page_fingerprint["title"] else 5,
                    )
                )
        if secure and isinstance(connection, http.client.HTTPSConnection):
            tls_socket = connection.sock
            if tls_socket is not None:
                cipher = tls_socket.cipher()
                certificate = tls_socket.getpeercert(binary_form=True) or b""
                tls_attributes: dict[str, object] = {
                    "tls_version": tls_socket.version() or "",
                    "cipher": cipher[0] if cipher else "",
                    "cipher_bits": cipher[2] if cipher else 0,
                    "certificate_sha256": hashlib.sha256(certificate).hexdigest()
                    if certificate else "",
                    "certificate_size": len(certificate),
                }
                observations.append(
                    _observation(
                        workspace, target, service, "tls", "completed",
                        tls_attributes, confidence=8,
                    )
                )
        return tuple(observations)
    except (OSError, http.client.HTTPException, ssl.SSLError, TimeoutError) as exc:
        if unidentified_service:
            # An unknown TCP service is only classified as HTTP after a valid
            # HTTP response. A non-HTTP response is not an enumeration failure.
            return ()
        return (
            _observation(
                workspace, target, service, protocol, "failed",
                {"error_type": type(exc).__name__},
            ),
        )
    finally:
        connection.close()


def _ssh_probe(
    workspace: str, target: str, service: Service, timeout: float
) -> tuple[ServiceObservation, ...]:
    try:
        with socket.create_connection((target, service.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = bytearray()
            while len(banner) < MAX_BANNER_LENGTH and b"\n" not in banner:
                chunk = sock.recv(min(64, MAX_BANNER_LENGTH - len(banner)))
                if not chunk:
                    break
                banner.extend(chunk)
        line = bytes(banner).split(b"\n", 1)[0].rstrip(b"\r")
        value = line.decode("ascii", errors="replace")[:MAX_BANNER_LENGTH]
        valid = value.startswith("SSH-")
        return (
            _observation(
                workspace, target, service, "ssh",
                "completed" if valid else "partial",
                {"banner": value, "banner_valid": valid},
                confidence=9 if valid else 2,
            ),
        )
    except (OSError, TimeoutError) as exc:
        return (
            _observation(
                workspace, target, service, "ssh", "failed",
                {"error_type": type(exc).__name__},
            ),
        )


def enumerate_services(
    workspace: str,
    hosts: tuple[Host, ...],
    policy: ScopePolicy,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = MAX_WORKERS,
) -> tuple[ServiceObservation, ...]:
    """Enumerate recognized open TCP services within the saved target/port scope."""
    if timeout <= 0:
        raise ValueError("Enumeration timeout must be greater than zero.")
    if not 1 <= max_workers <= MAX_WORKERS:
        raise ValueError(f"Enumeration workers must be between 1 and {MAX_WORKERS}.")

    tasks: list[tuple[str, str, Service]] = []
    for host in hosts:
        if host.status != "up" or not policy.permits_address(host.address):
            continue
        for service in host.services:
            if service.state != "open" or not policy.permits_port(service.port):
                continue
            if _is_http(service):
                tasks.append(("http", str(host.address), service))
            elif _is_ssh(service):
                tasks.append(("ssh", str(host.address), service))
            elif _is_ftp(service):
                tasks.append(("ftp", str(host.address), service))
            elif _is_smb(service):
                tasks.append(("smb", str(host.address), service))
            elif _is_tls(service):
                tasks.append(("tls", str(host.address), service))
            elif service.protocol.lower() == "tcp" and not service.tunnel:
                # Nmap can return an unknown service label even when the port
                # speaks HTTP. Try one bounded HEAD request before giving up.
                tasks.append(("http_candidate", str(host.address), service))

    results: list[ServiceObservation] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for kind, target, service in tasks:
            if kind == "http_candidate":
                futures.append(
                    executor.submit(
                        _http_probe,
                        workspace,
                        target,
                        service,
                        timeout,
                        unidentified_service=True,
                    )
                )
                continue
            probe = {
                "http": _http_probe,
                "ssh": _ssh_probe,
                "ftp": _ftp_probe,
                "smb": _smb_probe,
                "tls": _tls_probe,
            }[kind]
            futures.append(executor.submit(probe, workspace, target, service, timeout))
        for future in as_completed(futures):
            try:
                results.extend(future.result())
            except Exception as exc:  # noqa: BLE001 - isolate unexpected adapter failures per service
                # The adapter contract normally converts network errors to observations.
                # This fallback preserves workflow progress if an unexpected adapter error occurs.
                task_index = futures.index(future)
                kind, target, service = tasks[task_index]
                results.append(
                    _observation(
                        workspace, target, service, kind, "failed",
                        {"error_type": type(exc).__name__},
                    )
                )
    return tuple(sorted(results, key=lambda item: (
        item.target, item.port, item.protocol, item.kind
    )))
