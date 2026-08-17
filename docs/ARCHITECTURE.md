# Deploying Claude agents in an enterprise: the integration questions, answered

This kit is the code half of an enterprise Claude deployment. This doc is the other
half: the integration decisions a Forward-Deployed Engineer has to make on the first
day inside a customer's environment. Each section maps to a real control point, and
where the kit has a seam for it, the seam is named.

## 1. Identity and access (who is the agent, who approves)

- **Agent identity.** Give each agent a distinct workload identity (an IAM role on
  AWS, a workload identity on GCP, an app registration on Azure AD), never a shared
  human key. The agent assumes the role; the role is scoped to exactly the resources
  its tools touch.
- **Human approval.** The `PolicyGate` approver callback is the integration point for
  SSO-backed approval. In production the approver posts to an approval channel
  (Slack/Teams/PagerDuty) that authenticates the approver through the customer's IdP
  and returns their decision. Irreversible actions are auto-escalated to this path.
- **Least privilege by kind.** Policy is keyed on `Action.kind`, so "read" tools can
  be `allow` while "write" and "send" tools are `require_approval`, with a default of
  `deny` for anything unlisted.

## 2. Secrets and credentials

- The `SecretsProvider` contract is one method, `get(name)`, so the backend is a
  deployment choice, not a code change:
  - **AWS Secrets Manager**: `get` calls `secretsmanager:GetSecretValue` under the
    agent's assumed role; rotation is handled by AWS.
  - **HashiCorp Vault**: `get` reads a KV path with a short-lived token from the
    Vault agent sidecar.
  - **Environment (default `EnvSecrets`)**: for local and CI; the process environment
    is populated by the platform (e.g. injected by the orchestrator), never committed.
- Secrets never reach a log: `SecretsProvider.__repr__` hides values, and the
  `AuditLog` runs every field through the `Redactor` (provider keys, AWS keys, GitHub
  PATs, Slack tokens, JWTs, and `password=/token=` key-value pairs are masked).

## 3. Data residency and privacy

- **Model endpoint choice controls where data flows.** The kit is endpoint-agnostic;
  point the executor's model client at whichever satisfies the customer's residency
  requirement:
  - **Amazon Bedrock** (Claude) keeps inference inside the customer's AWS region and
    VPC via a VPC endpoint (PrivateLink), with no data leaving the account boundary.
  - **Google Vertex AI** (Claude) does the equivalent inside a GCP region.
  - **Anthropic API direct** for teams without a residency constraint, optionally with
    zero-data-retention terms.
- **Prompt/response minimization.** Redact PII before it enters a prompt; the same
  `Redactor` used for the audit log can be applied to tool inputs.

## 4. Network isolation

- Run agents in a private subnet with no public egress; reach the model endpoint over
  a VPC endpoint / Private Service Connect and reach customer systems over private
  links only. The `CommandGuard` blocks `curl | sh` style egress-and-execute patterns
  as defense in depth even when network policy should already prevent them.

## 5. Output quality gate

- `EvalGate` puts a measurable bar between generation and shipping. Wire the scorer to
  a calibrated LLM-as-judge (the author's `mcp-judge` is the reference) so a low-quality
  or off-policy output is blocked, logged, and never reaches the customer. The gate
  fails closed: a broken judge blocks rather than waves the output through.

## 6. Auditability and incident response

- Every attempt (allowed or blocked) is one JSONL line: timestamp, action, each gate's
  decision, whether it executed, whether it was approved. That is the artifact a
  security review and an incident retro both need. Ship the log to the customer's SIEM
  (CloudWatch, Chronicle, Splunk) for retention and alerting.

## Deployment shapes

| Shape | When | Notes |
|---|---|---|
| Sidecar in the customer's cluster | strict residency, existing k8s | agent + Vault sidecar in a private namespace |
| Serverless (Lambda/Cloud Run) | bursty, stateless tools | assumed role per invocation; secrets from the platform |
| Dedicated VM in customer VPC | legacy networks, long-running fleets | hardened image, deny-hook on by default |

The controls are the same in all three; only the substrate changes. That is the point
of keeping them in one small, portable library.
