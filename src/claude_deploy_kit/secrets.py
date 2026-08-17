"""SecretsProvider: pluggable secret retrieval that never leaks a value through a
repr, str, or log line. The default reads from the environment; AWS Secrets Manager
and HashiCorp Vault providers are documented in docs/ARCHITECTURE.md and follow the
same one-method contract so a deployment swaps backends without touching agent code."""
from __future__ import annotations

import os
from abc import ABC, abstractmethod


class SecretsProvider(ABC):
    """One method: get(name) -> value. Implementations must never render a secret
    in __repr__/__str__ so an accidental log of the provider is safe."""

    @abstractmethod
    def get(self, name: str) -> str:  # pragma: no cover - interface
        ...

    def __repr__(self) -> str:
        return f"<{type(self).__name__} (values hidden)>"

    __str__ = __repr__


class EnvSecrets(SecretsProvider):
    """Reads secrets from environment variables, with an optional name prefix so a
    deployment can namespace its secrets (e.g. prefix='ACME_')."""

    def __init__(self, prefix: str = ""):
        self.prefix = prefix

    def get(self, name: str) -> str:
        key = f"{self.prefix}{name}"
        try:
            return os.environ[key]
        except KeyError:
            raise KeyError(f"secret '{key}' not set in environment") from None


class StaticSecrets(SecretsProvider):
    """In-memory provider for tests and local runs. Values are held privately and
    are not exposed via repr."""

    def __init__(self, values: dict[str, str]):
        self.__values = dict(values)

    def get(self, name: str) -> str:
        try:
            return self.__values[name]
        except KeyError:
            raise KeyError(f"secret '{name}' not provided") from None
