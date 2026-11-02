from __future__ import annotations

import re


MAX_ADAPTER_OUTPUT_BYTES = 256_000

_SECRET_NAMES = (
    r"password|passwd|pwd|token|secret|api[_-]?key|authorization|"
    r"proxy-authorization|cookie|set-cookie|credential"
)
_QUOTED_SECRET = re.compile(
    rf"""(?i)(["']?(?:{_SECRET_NAMES})["']?\s*[:=]\s*)(["'])(.*?)\2"""
)
_UNQUOTED_SECRET = re.compile(
    rf"""(?i)(\b(?:{_SECRET_NAMES})\b\s*[:=]\s*)([^\s,;}}]+)"""
)
_BEARER = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]+")


class AdapterOutputError(ValueError):
    """Raised when adapter output is invalid or exceeds the capture limit."""


def sanitize_adapter_output(output: str) -> str:
    """Bound and redact common secret-bearing values in textual adapter output."""
    if not isinstance(output, str):
        raise AdapterOutputError("Adapter output must be text.")
    try:
        size = len(output.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise AdapterOutputError("Adapter output is not valid UTF-8 text.") from exc
    if size > MAX_ADAPTER_OUTPUT_BYTES:
        raise AdapterOutputError(
            f"Adapter output exceeds the {MAX_ADAPTER_OUTPUT_BYTES}-byte capture limit."
        )
    sanitized = _QUOTED_SECRET.sub(r"\1\2[REDACTED]\2", output)
    sanitized = _UNQUOTED_SECRET.sub(r"\1[REDACTED]", sanitized)
    return _BEARER.sub(r"\1[REDACTED]", sanitized)
