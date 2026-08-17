"""PolicyGate: the single chokepoint every outbound or irreversible action passes
through. In the production org this generalizes from, exactly one component decides
"may this leave the box", which is what makes the blast radius auditable."""
from __future__ import annotations

from .types import Action, Approver, Decision

ALLOW = "allow"
DENY = "deny"
REQUIRE_APPROVAL = "require_approval"
_VALID = {ALLOW, DENY, REQUIRE_APPROVAL}


class PolicyGate:
    """Config-driven allow / deny / require_approval per Action.kind.

    policy = {
        "shell": "require_approval",
        "http_post": "allow",
        "db_write": "require_approval",
        "*": "deny",            # default for any kind not listed (defaults to deny)
    }

    An irreversible action (Action.reversible is False) is escalated to at least
    require_approval even if the policy says allow: you can always tighten, never
    silently loosen, an irreversible action.
    """

    def __init__(self, policy: dict, approver: Approver | None = None):
        bad = {k: v for k, v in policy.items() if v not in _VALID}
        if bad:
            raise ValueError(f"invalid policy verdicts {bad}; must be one of {_VALID}")
        self.policy = dict(policy)
        self.approver = approver

    def _verdict_for(self, action: Action) -> str:
        return self.policy.get(action.kind, self.policy.get("*", DENY))

    def evaluate(self, action: Action) -> Decision:
        verdict = self._verdict_for(action)

        if verdict == DENY:
            return Decision(False, "policy", f"kind '{action.kind}' denied by policy", "block")

        # Irreversible actions can never be a silent allow.
        if not action.reversible and verdict == ALLOW:
            verdict = REQUIRE_APPROVAL

        if verdict == ALLOW:
            return Decision(True, "policy", f"kind '{action.kind}' allowed by policy")

        # require_approval
        if self.approver is None:
            return Decision(False, "policy",
                            f"kind '{action.kind}' requires approval but no approver is configured",
                            "block")
        if self.approver(action):
            return Decision(True, "policy", f"kind '{action.kind}' approved", "warn")
        return Decision(False, "policy", f"kind '{action.kind}' approval denied", "block")
