from __future__ import annotations

from html.parser import HTMLParser

MAX_HTML_BYTES = 64 * 1024
MAX_HTML_ITEMS = 24
MAX_TEXT_LENGTH = 512


class _FingerprintParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.in_title = False
        self.meta: dict[str, str] = {}
        self.resources: list[str] = []
        self.markers: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "meta":
            name = (values.get("name") or values.get("property") or "").lower()
            content = values.get("content", "").strip()
            if name in {"generator", "description", "application-name", "og:site_name"} and content:
                self.meta[name] = content[:MAX_TEXT_LENGTH]
        if tag.lower() == "script":
            source = values.get("src", "")
            if source:
                self.resources.append(source[:MAX_TEXT_LENGTH])
            if "ng-version" in values:
                self.markers.add("angular:ng-version")
            if "data-reactroot" in values:
                self.markers.add("react:data-reactroot")
        if tag.lower() == "link":
            href = values.get("href", "")
            rel = values.get("rel", "").lower()
            if href and any(token in rel for token in ("stylesheet", "manifest", "icon")):
                self.resources.append(href[:MAX_TEXT_LENGTH])
        for key in ("ng-app", "ng-version", "data-reactroot", "data-v-app", "x-data"):
            if key in values:
                self.markers.add(f"html:{key}")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title and data.strip():
            self.title_parts.append(data.strip())


def fingerprint_http_html(headers: dict[str, str], body: bytes, *, truncated: bool) -> dict[str, object] | None:
    """Extract bounded, evidence-backed application hints from an HTML response."""
    content_type = headers.get("content-type", "").lower()
    if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
        return None
    text = body.decode("utf-8", errors="replace")
    parser = _FingerprintParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception as exc:  # noqa: BLE001 - malformed HTML must not fail service enumeration
        parser.markers.add(f"parse_error:{type(exc).__name__}")

    title = " ".join(parser.title_parts).strip()[:MAX_TEXT_LENGTH]
    technologies: list[dict[str, object]] = []

    def add(name: str, evidence: str, confidence: int) -> None:
        if not any(item["name"] == name for item in technologies):
            technologies.append({"name": name, "confidence": confidence, "evidence": evidence[:MAX_TEXT_LENGTH]})

    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if server:
        add("server:" + server[:128], "HTTP Server header", 6)
    if powered_by:
        add("runtime:" + powered_by[:128], "X-Powered-By header", 7)

    source_text = " ".join(parser.resources).lower()
    markers = parser.markers
    if "__next_data__" in text.lower() or any("_next/" in item for item in parser.resources):
        add("Next.js", "Next.js document or asset marker", 9)
    if "angular:ng-version" in markers or "html:ng-version" in markers or "html:ng-app" in markers:
        add("Angular", "Angular DOM marker", 9)
    if "react:data-reactroot" in markers or "data-reactroot" in text.lower():
        add("React", "React DOM marker", 8)
    if "data-v-app" in markers or "vue" in source_text:
        add("Vue.js", "Vue DOM or asset marker", 7)
    if "jquery" in source_text:
        add("jQuery", "jQuery asset reference", 8)
    if "bootstrap" in source_text:
        add("Bootstrap", "Bootstrap asset reference", 8)
    if title.lower() == "owasp juice shop":
        add("OWASP Juice Shop", "Exact HTML title", 10)

    return {
        "title": title,
        "meta": dict(list(parser.meta.items())[:12]),
        "technologies": technologies[:16],
        "resources": parser.resources[:MAX_HTML_ITEMS],
        "body_bytes": len(body),
        "truncated": truncated,
        "content_type": content_type[:MAX_TEXT_LENGTH],
    }
