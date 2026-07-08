"""Extract the user's AI prompt text from an intercepted request (spec §4.4).

Per-service extractors know each site's request shape; a generic fallback
(largest string values in any JSON body) covers shadow-AI and unknown sites so
DLP still runs on something meaningful. Endpoint/field mappings are meant to be
updatable (§4.4).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

__all__ = ["AiRequest", "extract_prompt", "service_for_host"]


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
    """ChatGPT: POST .../backend-api/(f/)conversation, messages[].content.parts[]."""
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


# Ordered service-specific extractors; generic is applied last.
_EXTRACTORS: list[Callable[[AiRequest], "str | None"]] = [
    _extract_chatgpt,
    _extract_claude,
]


def extract_prompt(host: str, path: str, body: bytes) -> str | None:
    """Best-effort prompt text for DLP. Returns None if nothing extractable."""
    req = AiRequest(host=host, path=path, body=body)
    for extractor in _EXTRACTORS:
        try:
            text = extractor(req)
        except (KeyError, TypeError, ValueError):
            text = None
        if text:
            return text
    return _extract_generic(req)


def host_from_url(url: str) -> str:
    """Host from an absolute URL or an authority; strips any port."""
    if "//" not in url:
        url = "//" + url
    netloc = urlsplit(url).netloc or url
    return netloc.rsplit("@", 1)[-1].split(":", 1)[0]
