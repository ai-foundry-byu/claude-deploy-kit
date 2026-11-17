# claude-deploy-kit

**Working controls for deploying Claude agents in an enterprise safely: a single policy chokepoint, a command deny-hook, an eval gate, an audit log, and pluggable secrets. Generalized from a real production multi-agent org.**

Standing up a frontier-model agent inside a customer's environment means answering the same questions every time: who approves an irreversible action, what stops a destructive command, how do we know the output is good enough to ship, where do secrets live, and what is the audit trail. This kit answers each one with code you can read in an afternoon, and a test suite that proves it behaves.

It is not a greenfield toy. These are the controls the author actually runs across a ~38-agent production organization, extracted and generalized. No employer's name or proprietary code, no fabricated benchmarks: every number in the repo is produced by the included tests.

## The five controls

| Control | What it does |
|---|---|
| **PolicyGate** | The single chokepoint for every outbound or irreversible action. Config-driven `allow` / `deny` / `require_approval` per action kind, defaulting to deny. An irreversible action can never be a silent allow, it is always escalated to approval. |
| **CommandGuard** | A deny-hook that blocks destructive shell payloads (`rm -rf /`, `git push --force`, `DROP TABLE`, `curl \| sh`, `dd of=/dev/...`) even when the agent runs under skip-permissions. |
| **EvalGate** | An output must clear a calibrated judge before it is accepted. Pluggable scorer (wire [mcp-judge](https://github.com/ai-foundry-byu/mcp-judge) in production). Fails closed: a broken judge blocks, it does not wave output through. |
| **AuditLog** | Append-only JSONL of every attempt and each gate's decision, with a redactor that masks credentials before they are ever written. |
| **SecretsProvider** | One-method contract (`get(name)`) so the backend swaps from env to AWS Secrets Manager to Vault without touching agent code. Values never render in a repr or a log. |

`Deployment` wires them into one guarded call: run every gate in order, audit the attempt, and execute only if all gates allow (or approval is granted).

## Quickstart

```python
from claude_deploy_kit import Action, Deployment, PolicyGate, CommandGuard, EvalGate, AuditLog

dep = Deployment(
    gates=[
        PolicyGate({"shell": "allow", "send_email": "allow", "*": "deny"},
                   approver=lambda a: ask_a_human(a)),   # SSO-backed approval in prod
        CommandGuard(),                                   # blocks destructive commands
        EvalGate(scorer=mcp_judge_score, threshold=85),   # output must clear the bar
    ],
    audit=AuditLog("audit.jsonl"),
    executor=my_tool_runner,                              # actually performs the action
)

result = dep.act(Action("shell", "ls -la", reversible=True))
print(result.executed, result.blocked_by)
```

Run the end-to-end example (offline, no key needed):

```bash
python examples/guarded_agent.py
```

## Install and test

```bash
pip install -e ".[dev]"
pytest -q          # 39 tests, no network: judge, approver, and executor are injected
```

## Enterprise integration

[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) covers the decisions the code does not make for you: workload identity and SSO-backed approval, secrets backends, data residency (Bedrock / Vertex / direct API), network isolation, and shipping the audit log to a SIEM.

## Why this exists

An Applied AI Architect or Forward-Deployed Engineer is judged on whether they can make frontier models safe and useful inside someone else's environment. This is a small, honest demonstration of that discipline: the boring, load-bearing controls, shown as working code rather than described in a deck.

## License

MIT. Author: JD Davenport.
