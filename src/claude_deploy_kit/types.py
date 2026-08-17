"""Core value types shared across every gate. Keeping these immutable and tiny is
deliberate: a gate can never mutate the action it is judging, and a Decision is a
plain record you can serialize straight into an audit log."""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Callable


@dataclass(frozen=True)
class Action:
    """Something an agent wants to do, before it is allowed to happen.

    reversible=False means the action cannot be undone (send an email, charge a card,
    drop a table); the deployment treats those as approval-required by default.
    """
    kind: str
    payload: str
    metadata: dict = field(default_factory=dict)
    reversible: bool = False

    def redacted(self, redactor: "Redactor") -> "Action":
        return replace(self, payload=redactor.scrub(self.payload),
                       metadata={k: redactor.scrub(str(v)) for k, v in self.metadata.items()})


@dataclass(frozen=True)
class Decision:
    """One gate's verdict on one action."""
    allowed: bool
    gate: str
    reason: str
    severity: str = "info"  # info | warn | block

    def as_dict(self) -> dict:
        return {"allowed": self.allowed, "gate": self.gate,
                "reason": self.reason, "severity": self.severity}


@dataclass(frozen=True)
class Result:
    """The outcome of running an action through the full deployment."""
    executed: bool
    output: str
    decisions: tuple[Decision, ...]
    approval_required: bool = False
    approved: bool = False

    @property
    def blocked_by(self) -> tuple[str, ...]:
        return tuple(d.gate for d in self.decisions if not d.allowed)


class Redactor:
    """Scrubs secret-looking substrings before anything is written to a log.

    Enterprise audit logs are a classic secret-leak vector: a command that embeds
    a token gets recorded verbatim. The redactor is applied to every audited field.
    """

    #: patterns that look like credentials regardless of surrounding key name
    DEFAULT_PATTERNS = (
        r"sk-ant-[A-Za-z0-9_\-]{8,}",              # Anthropic keys
        r"sk-[A-Za-z0-9]{20,}",                    # generic provider keys
        r"AKIA[0-9A-Z]{16}",                       # AWS access key id
        r"ghp_[A-Za-z0-9]{20,}",                   # GitHub PAT
        r"xox[baprs]-[A-Za-z0-9\-]{10,}",          # Slack tokens
        r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",  # JWTs
    )

    #: key names whose value should always be masked (case-insensitive)
    DEFAULT_KEY_HINTS = ("password", "passwd", "secret", "token", "api_key",
                         "apikey", "authorization", "private_key")

    def __init__(self, patterns: tuple[str, ...] | None = None,
                 key_hints: tuple[str, ...] | None = None, mask: str = "[REDACTED]"):
        self.mask = mask
        self._regexes = [re.compile(p) for p in (patterns or self.DEFAULT_PATTERNS)]
        self._key_hints = tuple(h.lower() for h in (key_hints or self.DEFAULT_KEY_HINTS))
        # matches key="value" / key: value / key=value for hinted keys
        hint_group = "|".join(re.escape(h) for h in self._key_hints)
        self._kv_regex = re.compile(
            rf'(?i)\b({hint_group})\b\s*[=:]\s*["\']?([^\s"\',;]+)')

    def scrub(self, text: str) -> str:
        if not text:
            return text
        out = text
        # mask key=value pairs for hinted key names, keeping the key visible
        out = self._kv_regex.sub(lambda m: f"{m.group(1)}={self.mask}", out)
        # mask anything that looks like a raw credential
        for rx in self._regexes:
            out = rx.sub(self.mask, out)
        return out


#: A scorer maps an action's payload to a 0-100 quality score.
Scorer = Callable[[str], float]
#: An approver decides whether an approval-required action may proceed.
Approver = Callable[[Action], bool]
#: An executor actually performs an allowed action and returns its output.
Executor = Callable[[Action], str]
