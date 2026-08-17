"""A runnable example: an agent whose every action is driven through the full stack.

    python examples/guarded_agent.py

It uses a fake executor and a deterministic scorer so it runs offline. In a real
deployment you swap the scorer for mcp-judge and the executor for your tool runner;
nothing else about the wiring changes."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from claude_deploy_kit import (  # noqa: E402
    Action, AuditLog, CommandGuard, Deployment, EvalGate, PolicyGate,
)


def fake_executor(action: Action) -> str:
    return f"[executed {action.kind}] {action.payload}"


def length_scorer(payload: str) -> float:
    # stand-in for a calibrated judge: score a draft by a trivial heuristic
    return min(100.0, 60.0 + len(payload))


def build_deployment(audit_path: str) -> Deployment:
    policy = {
        "shell": "allow",          # shell still passes the CommandGuard below
        "llm_output": "allow",     # still passes the EvalGate below
        "send_email": "allow",     # irreversible -> auto-escalated to approval
        "*": "deny",
    }
    approver = lambda action: action.metadata.get("approved") is True  # noqa: E731
    gates = [
        PolicyGate(policy, approver=approver),
        CommandGuard(),
        EvalGate(scorer=length_scorer, threshold=70),
    ]
    return Deployment(gates=gates, audit=AuditLog(audit_path), executor=fake_executor)


def main() -> None:
    audit_path = str(Path(tempfile.mkdtemp()) / "audit.jsonl")
    dep = build_deployment(audit_path)

    attempts = [
        Action("shell", "ls -la", reversible=True),                       # allowed
        Action("shell", "rm -rf /", reversible=True),                     # blocked: CommandGuard
        Action("llm_output", "This is a sufficiently long, good answer.", reversible=True),  # allowed
        Action("llm_output", "no", reversible=True),                      # blocked: EvalGate (too short)
        Action("send_email", "quarterly report", reversible=False),       # blocked: needs approval
        Action("send_email", "quarterly report", reversible=False,
               metadata={"approved": True}),                             # allowed: approval granted
        Action("db_write", "insert ...", reversible=True),                # blocked: policy default deny
    ]

    for a in attempts:
        res = dep.act(a)
        status = "EXECUTED" if res.executed else f"BLOCKED by {', '.join(res.blocked_by) or 'approval'}"
        print(f"{a.kind:<12} {status}")

    print(f"\nAudit trail ({audit_path}):")
    for e in AuditLog(audit_path).entries():
        print(f"  {e['action']['kind']:<12} executed={e['executed']} approved={e['approved']}"
              f" blocked_by={e['blocked_by']}")


if __name__ == "__main__":
    main()
