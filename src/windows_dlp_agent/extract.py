"""Extract the user's AI prompt text from an intercepted request (spec §4.4).

DLP must only inspect *AI prompt* traffic, never arbitrary web requests: the
proxy MITMs every connection, so scanning every POST body would false-positive
on Cloudflare challenges, telemetry, OAuth blobs, etc. and break the web
(observed live). So extraction is gated to *recognized AI destinations* — each
known host maps to its own extractor, and an unrecognized host returns None
(not scanned). Shadow-AI hosts are opted in explicitly via register_service /
register_extractor; a host registered without a bespoke extractor gets the
generic JSON string sweep. Mappings are updatable at runtime (§4.4).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable
from urllib.parse import parse_qs, urlsplit

__all__ = [
    "AiRequest",
    "extract_prompt",
    "service_for_host",
    "register_service",
    "register_extractor",
]


@dataclass
class AiRequest:
    host: str
    path: str
    body: bytes

    def json(self) -> object | None:
        if not self.body:
            return None
        try:
            return json.loads(self.body)
        except (ValueError, UnicodeDecodeError):
            return None


# host substring -> service name (§4.4 known AI domains)
_KNOWN_SERVICES: dict[str, str] = {
    "chatgpt.com": "ChatGPT",
    "chat.openai.com": "ChatGPT",
    "gemini.google.com": "Gemini",
    "claude.ai": "Claude",
}


def service_for_host(host: str) -> str | None:
    host = host.lower()
    for needle, name in _KNOWN_SERVICES.items():
        if needle in host:
            return name
    return None


def _walk_strings(node: object, out: list[str]) -> None:
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            _walk_strings(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_strings(v, out)


def _extract_chatgpt(req: AiRequest) -> str | None:
    """ChatGPT: POST .../backend-api/(f/)conversation.

    Current web payload (verified against live traffic):
        {"action":"next","messages":[{"author":{"role":"user"},
          "content":{"content_type":"text","parts":["<prompt>"]}, ...}], ...}
    parts[] is usually strings; multimodal/voice turns can mix in dicts like
    {"content_type":"audio_transcription","text":"..."} — pull their text too.
    """
    if "conversation" not in req.path:
        return None
    data = req.json()
    if not isinstance(data, dict):
        return None
    parts: list[str] = []
    for msg in data.get("messages", []) or []:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if isinstance(content, dict):
            for p in content.get("parts", []) or []:
                if isinstance(p, str):
                    parts.append(p)
                elif isinstance(p, dict):
                    text = p.get("text") or p.get("content")
                    if isinstance(text, str):
                        parts.append(text)
        elif isinstance(content, str):
            parts.append(content)
    return "\n".join(parts) if parts else None


def _extract_claude(req: AiRequest) -> str | None:
    """Claude.ai: completion payload — prompt / messages content."""
    if "completion" not in req.path and "messages" not in req.path:
        return None
    data = req.json()
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("prompt"), str):
        return data["prompt"]
    parts: list[str] = []
    for msg in data.get("messages", []) or []:
        if isinstance(msg, dict):
            c = msg.get("content")
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, list):
                _walk_strings(c, parts)
    return "\n".join(parts) if parts else None


def _walk_nested_json_strings(node: object, out: list[str]) -> None:
    """Like _walk_strings but transparently descends into JSON-in-string values,
    which is how Gemini's batchexecute nests the prompt."""
    if isinstance(node, str):
        stripped = node.strip()
        if stripped[:1] in "[{":
            try:
                _walk_nested_json_strings(json.loads(node), out)
                return
            except ValueError:
                pass
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            _walk_nested_json_strings(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_nested_json_strings(v, out)


def _extract_gemini(req: AiRequest) -> str | None:
    """Gemini: POST .../batchexecute, prompt buried in the f.req field."""
    if "batchexecute" not in req.path:
        return None
    try:
        text = req.body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    freq = parse_qs(text).get("f.req", [None])[0]
    if not freq:
        return None
    strings: list[str] = []
    _walk_nested_json_strings(freq, strings)
    meaningful = [s for s in strings if len(s) >= 2]
    return "\n".join(meaningful) if meaningful else None


def _extract_generic(req: AiRequest) -> str | None:
    """Fallback (§4.4): concatenate the largest string values in a JSON body,
    else treat the whole decoded body as text."""
    data = req.json()
    if data is not None:
        strings: list[str] = []
        _walk_strings(data, strings)
        # Keep the substantial ones; join so DLP sees all candidate content.
        meaningful = [s for s in strings if len(s) >= 2]
        if meaningful:
            return "\n".join(meaningful)
    try:
        text = req.body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text or None


Extractor = Callable[["AiRequest"], "str | None"]

# host substring -> extractor. Only these hosts are ever inspected; a match's
# extractor returning None means "not a prompt request on this AI host" (e.g. a
# challenge/telemetry endpoint) and the request is passed through unscanned.
_SERVICE_EXTRACTORS: list[tuple[str, Extractor]] = [
    ("chatgpt.com", _extract_chatgpt),
    ("chat.openai.com", _extract_chatgpt),
    ("claude.ai", _extract_claude),
    ("gemini.google.com", _extract_gemini),
]


def register_service(host_substring: str, name: str, extractor: Extractor | None = None) -> None:
    """Register an AI destination to inspect (§4.4 updatable map).

    `name` is the display name (for toasts/audit). `extractor` parses its prompt;
    omit it to use the generic JSON string sweep for a shadow-AI host.
    """
    hs = host_substring.lower()
    _KNOWN_SERVICES[hs] = name
    _SERVICE_EXTRACTORS.insert(0, (hs, extractor or _extract_generic))


def register_extractor(host_substring: str, extractor: Extractor) -> None:
    """Attach a bespoke extractor to an (already or newly) recognized AI host."""
    _SERVICE_EXTRACTORS.insert(0, (host_substring.lower(), extractor))


def extract_prompt(host: str, path: str, body: bytes) -> str | None:
    """Prompt text for DLP, or None if this request must not be scanned.

    Only recognized AI destinations are inspected (see module docstring). An
    unrecognized host — Cloudflare challenges, Google/telemetry, any normal
    site — returns None and is never swept, so DLP can't false-positive on and
    block ordinary web traffic.
    """
    req = AiRequest(host=host, path=path, body=body)
    hl = host.lower()
    for needle, extractor in _SERVICE_EXTRACTORS:
        if needle in hl:
            try:
                return extractor(req) or None
            except (KeyError, TypeError, ValueError):
                return None
    return None


def host_from_url(url: str) -> str:
    """Host from an absolute URL or an authority; strips any port."""
    if "//" not in url:
        url = "//" + url
    netloc = urlsplit(url).netloc or url
    return netloc.rsplit("@", 1)[-1].split(":", 1)[0]
