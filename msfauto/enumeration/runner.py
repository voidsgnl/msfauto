from __future__ import annotations

import hashlib
import http.client
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from uuid import uuid4

from ..storage.models import Host, ScopePolicy, Service
from .models import ServiceObservation

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
    return service.protocol.lower() == "tcp" and (
        "http" in label or service.tunnel.lower() == "ssl"
    )


def _is_ssh(service: Service) -> bool:
    label = f"{service.name} {service.product}".lower()
    return service.protocol.lower() == "tcp" and "ssh" in label


def _http_probe(
    workspace: str, target: str, service: Service, timeout: float
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
        attributes: dict[str, object] = {
            "status_code": response.status,
            "reason": (response.reason or "")[:MAX_VALUE_LENGTH],
            "headers": headers,
            "method": "HEAD",
            "path": "/",
        }
        observations = [
            _observation(workspace, target, service, protocol, "completed", attributes)
        ]
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

    results: list[ServiceObservation] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for kind, target, service in tasks:
            probe = _http_probe if kind == "http" else _ssh_probe
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
