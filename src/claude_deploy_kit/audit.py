"""AuditLog: append-only, structured (JSONL), redaction-aware record of every action
and the decisions each gate made. This is the artifact a security review asks for:
who tried to do what, which gate allowed or blocked it, and whether it executed."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from .types import Action, Decision, Redactor


class AuditLog:
    def __init__(self, path: str, redactor: Redactor | None = None, clock=None):
        self.path = path
        self.redactor = redactor or Redactor()
        # injectable clock keeps tests deterministic; defaults to real UTC time.
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)

    def record(self, action: Action, decisions: list[Decision],
               executed: bool, approved: bool = False) -> dict:
        safe = action.redacted(self.redactor)
        entry = {
            "ts": self._clock().isoformat(),
            "action": {"kind": safe.kind, "payload": safe.payload,
                       "metadata": safe.metadata, "reversible": action.reversible},
            "decisions": [d.as_dict() for d in decisions],
            "executed": executed,
            "approved": approved,
            "blocked_by": [d.gate for d in decisions if not d.allowed],
        }
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return entry

    def entries(self) -> list[dict]:
        """Read the log back (for review / assertions)."""
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out
