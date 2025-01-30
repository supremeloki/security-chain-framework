from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class ChainError(Exception):
    pass


class AuthenticationError(ChainError):
    pass


class AuthorizationError(ChainError):
    pass


class PolicyViolationError(ChainError):
    pass


class AuditUnavailableError(ChainError):
    pass


@dataclass(frozen=True)
class Principal:
    subject: str
    level: int = 5

    def __post_init__(self) -> None:
        if not 1 <= self.level <= 5:
            raise ChainError("level must be within 1..5")


@dataclass(frozen=True)
class Request:
    request_id: str
    resource: str
    action: str
    credentials: dict[str, str] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    stage: str
    reason: str
    principal: Principal | None = None

    @property
    def denied(self) -> bool:
        return not self.allowed


class ChainStage:
    name: str = "stage"

    def evaluate(self, request: Request, decision: Decision) -> Decision: ...
