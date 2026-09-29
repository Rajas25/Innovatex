"""Input validation, output encoding and static XSS analysis."""
from __future__ import annotations

import html
import re
from typing import Any

# ─── Output encoding ─────────────────────────────────────────────────────
_ENTITIES = {
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#x27;", "/": "&#x2F;",
    "`": "&#x60;", "=": "&#x3D;",
}


def escape_html(value: Any) -> str:
    """HTML-escape for text and quoted-attribute contexts."""
    if value is None:
        return ""
    return re.sub(r"[&<>\"'/`=]", lambda m: _ENTITIES[m.group(0)], str(value))


def encode_url_component(value: Any) -> str:
    from urllib.parse import quote
    return quote(str(value if value is not None else ""), safe="")


# ─── Static XSS analysis ─────────────────────────────────────────────────
_XSS_PATTERNS: list[tuple[str, str, re.Pattern[str], int]] = [
    ("script_tag",    "Inline <script> tag",              re.compile(r"<\s*script[\s>]", re.I), 40),
    ("event_handler", "Inline event handler (on*=)",      re.compile(r"\son[a-z]+\s*=", re.I), 30),
    ("js_uri",        "javascript: URI",                  re.compile(r"javascript\s*:", re.I), 30),
    ("data_html",     "data:text/html URI",               re.compile(r"data\s*:\s*text/html", re.I), 25),
    ("svg_onload",    "<svg> with onload",                re.compile(r"<\s*svg[^>]*onload", re.I), 30),
    ("iframe",        "<iframe> element",                 re.compile(r"<\s*iframe", re.I), 25),
    ("object_embed",  "<object>/<embed> element",         re.compile(r"<\s*(object|embed)", re.I), 20),
    ("srcdoc",        "srcdoc attribute",                 re.compile(r"srcdoc\s*=", re.I), 20),
    ("css_expression","CSS expression()",                 re.compile(r"expression\s*\(", re.I), 25),
    ("template",      "Template-literal break-out ${...}", re.compile(r"\$\{[^}]*\}"), 15),
    ("img_onerror",   "<img> with onerror",               re.compile(r"<\s*img[^>]*onerror", re.I), 30),
    ("entity_enc",    "Entity-encoded angle bracket",     re.compile(r"&lt;\s*script|&#x?0*3c;", re.I), 10),
]


def analyse_xss(value: Any) -> dict[str, Any]:
    text = "" if value is None else str(value)
    matches: list[dict[str, Any]] = []
    score = 0

    for pid, label, pattern, weight in _XSS_PATTERNS:
        if pattern.search(text):
            matches.append({"id": pid, "label": label, "weight": weight})
            score += weight

    if len(text) > 200:
        score += 5

    score = min(score, 100)
    verdict = "malicious" if score >= 30 else "suspicious" if score > 0 else "clean"

    return {"score": score, "matches": matches, "verdict": verdict}


# ─── Allowlist HTML sanitiser (teaching implementation) ──────────────────
_ALLOWED_TAGS = frozenset({
    "b", "strong", "i", "em", "u", "s", "p", "br", "hr",
    "ul", "ol", "li", "blockquote", "code", "pre",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "table", "thead", "tbody", "tr", "th", "td",
    "a", "span", "div", "small", "sub", "sup",
})
_ALLOWED_ATTRS = frozenset({"href", "title", "target", "rel", "class"})
_VOID_TAGS = frozenset({"br", "hr", "img", "input", "meta", "link"})

# Pre-strip these tags and their bodies.
_DROP_WITH_BODY = re.compile(
    r"<\s*(script|style|iframe|object|embed|applet|frame|frameset|svg|math)[\s\S]*?"
    r"<\s*/\s*\1\s*>",
    re.I,
)
_DROP_SELF_CLOSING = re.compile(
    r"<\s*(iframe|object|embed|applet|frame|frameset|svg|math)[^>]*/?>",
    re.I,
)
_TAG_RE = re.compile(r"<\/?([a-zA-Z][a-zA-Z0-9-]*)((?:\s+[^>]*)?)\/?>")
_ATTR_RE = re.compile(
    r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'>]+)))?"
)


def sanitize_html(dirty: Any) -> str:
    """
    Minimal allowlist sanitiser.

    ⚠️  This is a *teaching* implementation. Production code must use a
    vetted library (bleach / DOMPurify / nh3), because hand-rolled sanitisers
    are routinely bypassed via mutation-XSS and parser-differential attacks.
    """
    if not dirty:
        return ""
    text = str(dirty)
    text = _DROP_WITH_BODY.sub("", text)
    text = _DROP_SELF_CLOSING.sub("", text)

    def _rebuild(match: re.Match[str]) -> str:
        raw_tag = match.group(1)
        tag = raw_tag.lower()
        if tag not in _ALLOWED_TAGS:
            return ""

        is_closing = match.group(0).startswith("</")
        if is_closing:
            return f"</{tag}>"

        raw_attrs = match.group(2) or ""
        attrs: list[str] = []
        for m in _ATTR_RE.finditer(raw_attrs):
            name = m.group(1).lower()
            value = m.group(2) or m.group(3) or m.group(4) or ""
            if name not in _ALLOWED_ATTRS or name.startswith("on"):
                continue
            if name == "href":
                lowered = value.strip().lower()
                if lowered.startswith(("javascript:", "data:", "vbscript:")):
                    continue
            attrs.append(f'{name}="{escape_html(value)}"')

        if tag == "a":
            if not any(a.startswith("rel=") for a in attrs):
                attrs.append('rel="noopener noreferrer nofollow"')
            if not any(a.startswith("target=") for a in attrs):
                attrs.append('target="_blank"')

        attr_string = (" " + " ".join(attrs)) if attrs else ""
        return f"<{tag}{attr_string}>" if tag not in _VOID_TAGS else f"<{tag}{attr_string}>"

    return _TAG_RE.sub(_rebuild, text)


# ─── Field validators ────────────────────────────────────────────────────
def valid_email(value: Any) -> bool:
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]{2,}", str(value or "").strip()))


def valid_url(value: Any) -> bool:
    from urllib.parse import urlparse
    try:
        parsed = urlparse(str(value))
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def strong_password(value: Any) -> tuple[bool, str]:
    text = str(value or "")
    if len(text) < 12:
        return False, "Password must be at least 12 characters"
    if len(text) > 128:
        return False, "Password must be 128 characters or fewer"
    if not re.search(r"[a-z]", text):
        return False, "Password must include a lowercase letter"
    if not re.search(r"[A-Z]", text):
        return False, "Password must include an uppercase letter"
    if not re.search(r"[0-9]", text):
        return False, "Password must include a digit"
    if not re.search(r"[^A-Za-z0-9]", text):
        return False, "Password must include a symbol"
    breached = ("password", "qwerty", "letmein", "welcome", "admin123", "iloveyou")
    if any(b in text.lower() for b in breached):
        return False, "Password appears in known-breach corpora"
    return True, ""