"""claude-deploy-kit: opinionated, working controls for deploying Claude agents in
an enterprise safely. Generalized from a real production multi-agent org.

    from claude_deploy_kit import (
        Action, Deployment, PolicyGate, CommandGuard, EvalGate, AuditLog, EnvSecrets,
    )
"""
from .audit import AuditLog
from .command_guard import CommandGuard
from .deployment import Deployment
from .eval_gate import EvalGate
from .policy import PolicyGate
from .secrets import EnvSecrets, SecretsProvider, StaticSecrets
from .types import Action, Decision, Redactor, Result

__version__ = "0.1.0"

__all__ = [
    "Action", "Decision", "Result", "Redactor",
    "PolicyGate", "CommandGuard", "EvalGate", "AuditLog",
    "SecretsProvider", "EnvSecrets", "StaticSecrets",
    "Deployment", "__version__",
]
