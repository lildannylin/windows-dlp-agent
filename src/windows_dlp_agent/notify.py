"""Windows toast notifications on DLP hits (spec §5).

The prompt is presented by the agent as a system toast — never injected into
the browser page. Off Windows (or when the toast library is missing) this
degrades to a recorded no-op so the proxy and tests stay portable.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Protocol

__all__ = ["Notifier", "ToastNotifier", "RecordingNotifier", "get_notifier", "build_message"]


def build_message(categories: list[str], service: str | None, action: str) -> tuple[str, str]:
    """(title, body) for a hit — matches §5 wording: type + blocked service."""
    kinds = "、".join(categories) if categories else "敏感資料"
    dest = service or "AI 服務"
    if action == "block":
        title = "DLP 已阻擋"
        body = f"偵測到 {kinds}，已阻擋送往 {dest}"
    elif action == "warn":
        title = "DLP 警告"
        body = f"偵測到 {kinds}，送往 {dest} 前需確認"
    elif action == "redact":
        title = "DLP 已遮蔽"
        body = f"已將 {kinds} 遮蔽後送往 {dest}"
    else:
        title = "DLP"
        body = f"{kinds} → {dest}"
    return title, body


class Notifier(Protocol):
    def notify(self, title: str, body: str) -> None: ...


@dataclass
class RecordingNotifier:
    """No-op notifier that records messages — used off-Windows and in tests."""

    messages: list[tuple[str, str]] = field(default_factory=list)

    def notify(self, title: str, body: str) -> None:
        self.messages.append((title, body))


class ToastNotifier:
    """Real Windows toast via `windows-toasts` (lazy-imported)."""

    def __init__(self, app_name: str = "Windows DLP Agent"):
        from windows_toasts import Toast, WindowsToaster  # type: ignore

        self._Toast = Toast
        self._toaster = WindowsToaster(app_name)

    def notify(self, title: str, body: str) -> None:
        toast = self._Toast()
        toast.text_fields = [title, body]
        self._toaster.show_toast(toast)


def get_notifier(app_name: str = "Windows DLP Agent") -> Notifier:
    """Real toaster on Windows if available; otherwise a recording no-op."""
    if sys.platform == "win32":
        try:
            return ToastNotifier(app_name)
        except Exception:  # noqa: BLE001 -- missing lib / COM init: degrade gracefully
            pass
    return RecordingNotifier()
