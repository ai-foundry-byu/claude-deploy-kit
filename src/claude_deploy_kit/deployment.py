"""Deployment: the facade that wires the gates into one guarded action() call.

Every gate runs in order. The first block stops execution. If all gates allow,
the injected executor performs the action. Either way the attempt is audited, so
the log is a complete record of what was tried, not only what succeeded."""
from __future__ import annotations

from .audit import AuditLog
from .types import Action, Decision, Executor, Result


class Deployment:
    def __init__(self, gates: list, audit: AuditLog, executor: Executor):
        if not gates:
            raise ValueError("a Deployment needs at least one gate")
        for g in gates:
            if not hasattr(g, "evaluate"):
                raise TypeError(f"gate {g!r} must have an evaluate(action) -> Decision method")
        if not callable(executor):
            raise TypeError("executor must be callable: (action) -> str")
        self.gates = list(gates)
        self.audit = audit
        self.executor = executor

    def act(self, action: Action) -> Result:
        decisions: list[Decision] = []
        approval_required = False
        approved = False

        for gate in self.gates:
            decision = gate.evaluate(action)
            decisions.append(decision)
            # a warn-level allow from the policy gate means approval was granted
            if decision.gate == "policy" and decision.allowed and decision.severity == "warn":
                approval_required, approved = True, True
            if not decision.allowed:
                # a policy block on an approval-required action records the intent
                if decision.gate == "policy" and "approval" in decision.reason:
                    approval_required = True
                self.audit.record(action, decisions, executed=False, approved=approved)
                return Result(False, "", tuple(decisions),
                              approval_required=approval_required, approved=approved)

        # all gates allowed -> execute
        try:
            output = self.executor(action)
            executed = True
        except Exception as e:
            decisions.append(Decision(False, "executor",
                                      f"executor raised {type(e).__name__}: {e}", "block"))
            self.audit.record(action, decisions, executed=False, approved=approved)
            return Result(False, "", tuple(decisions),
                          approval_required=approval_required, approved=approved)

        self.audit.record(action, decisions, executed=True, approved=approved)
        return Result(True, output, tuple(decisions),
                      approval_required=approval_required, approved=approved)
