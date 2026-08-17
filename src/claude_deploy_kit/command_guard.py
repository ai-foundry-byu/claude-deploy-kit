"""CommandGuard: a deny-hook for destructive shell payloads. This mirrors a
PreToolUse deny-hook that fires even when an agent runs under skip-permissions,
so a hardened fleet cannot be talked into wiping a disk or force-pushing over main."""
from __future__ import annotations

import re

from .types import Action, Decision

#: Patterns that are refused regardless of context. Deliberately conservative and
#: readable; extend per deployment. Each entry is (name, regex).
DEFAULT_DENY = (
    ("rm-rf-root", r"\brm\s+(-[a-zA-Z]*\s+)*-?[a-zA-Z]*[rf][a-zA-Z]*\s+(-[a-zA-Z]*\s+)*(/|~|\$HOME|\*)(\s|$)"),
    ("rm-rf", r"\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*r[a-zA-Z]*f|\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*f[a-zA-Z]*r"),
    ("git-force-push", r"\bgit\s+push\b.*(--force\b|\s-f\b)"),
    ("git-hard-reset", r"\bgit\s+reset\s+--hard\b"),
    ("drop-table", r"(?i)\bdrop\s+(table|database|schema)\b"),
    ("truncate-table", r"(?i)\btruncate\s+table\b"),
    ("delete-no-where", r"(?i)\bdelete\s+from\s+\w+\s*;?\s*$"),  # DELETE with no WHERE
    ("dd-disk", r"\bdd\b.*\bof=/dev/"),
    ("mkfs", r"\bmkfs(\.\w+)?\b"),
    ("fork-bomb", r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;"),
    ("chmod-777-root", r"\bchmod\s+(-R\s+)?777\s+(/|~)"),
    ("curl-pipe-sh", r"\bcurl\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b"),
    ("shutdown", r"\b(shutdown|reboot|halt|poweroff)\b"),
)

#: kinds the guard inspects; others pass through untouched.
SHELL_KINDS = frozenset({"shell", "bash", "command", "exec"})


class CommandGuard:
    def __init__(self, deny_patterns: list[tuple[str, str]] | None = None,
                 kinds: frozenset[str] = SHELL_KINDS):
        self.kinds = kinds
        self._rules = [(name, re.compile(rx)) for name, rx in (deny_patterns or DEFAULT_DENY)]

    def evaluate(self, action: Action) -> Decision:
        if action.kind not in self.kinds:
            return Decision(True, "command_guard", "not a shell action; not inspected")
        for name, rx in self._rules:
            if rx.search(action.payload):
                return Decision(False, "command_guard",
                                f"blocked destructive command pattern '{name}'", "block")
        return Decision(True, "command_guard", "no destructive pattern matched")
