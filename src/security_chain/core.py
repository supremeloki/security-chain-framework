from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field
from typing import Sequence

from .contracts import (
    AuthenticationError,
    AuthorizationError,
    ChainError,
    ChainStage,
    Decision,
    PolicyViolationError,
    Principal,
    Request,
)

SESSION_TTL_SECONDS = 3600


class CredentialStore:
    def __init__(self) -> None:
        self._secrets: dict[str, bytes] = {}
        self._levels: dict[str, int] = {}

    def register(self, subject: str, secret: str, level: int) -> None:
        salted = hashlib.pbkdf2_hmac("sha256", secret.encode(), subject.encode(), 100_000)
        self._secrets[subject] = salted
        self._levels[subject] = level

    def verify(self, subject: str, secret: str) -> Principal | None:
        expected = self._secrets.get(subject)
        if expected is None:
            return None
        candidate = hashlib.pbkdf2_hmac("sha256", secret.encode(), subject.encode(), 100_000)
        if not hmac.compare_digest(expected, candidate):
            return None
        return Principal(subject=subject, level=self._levels.get(subject, 5))


class SessionManager:
    def __init__(self, ttl_seconds: int = SESSION_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._sessions: dict[str, tuple[str, float]] = {}

    def open(self, token: str, subject: str) -> None:
        self._sessions[token] = (subject, time.monotonic() + self._ttl)

    def resolve(self, token: str) -> str | None:
        entry = self._sessions.get(token)
        if entry is None:
            return None
        subject, expires_at = entry
        if time.monotonic() >= expires_at:
            del self._sessions[token]
            return None
        return subject

    def close(self, token: str) -> bool:
        return self._sessions.pop(token, None) is not None

    def active_count(self) -> int:
        now = time.monotonic()
        expired = [t for t, (_, exp) in self._sessions.items() if now >= exp]
        for token in expired:
            del self._sessions[token]
        return len(self._sessions)


@dataclass
class AuthStage:
    name = "auth"
    store: CredentialStore = field(default_factory=CredentialStore)
    sessions: SessionManager = field(default_factory=SessionManager)

    def evaluate(self, request: Request, _prior: Decision) -> Decision:
        session_token = request.credentials.get("session")
        if session_token:
            subject = self.sessions.resolve(session_token)
            if subject:
                level = self.store._levels.get(subject, 5)
                return Decision(allowed=True, stage=self.name,
                                reason="valid session",
                                principal=Principal(subject, level))
        subject_name = request.credentials.get("subject", "")
        secret = request.credentials.get("secret", "")
        principal = self.store.verify(subject_name, secret)
        if principal is None:
            return Decision(allowed=False, stage=self.name, reason="invalid credentials")
        return Decision(allowed=True, stage=self.name, reason="authenticated",
                        principal=principal)


class RbacStage:
    name = "rbac"

    def __init__(self, role_grants: dict[int, set[tuple[str, str]]] | None = None) -> None:
        self._grants = role_grants or {
            1: {("*", "*")},
            2: {("data", "read"), ("data", "write")},
            3: {("reports", "read"), ("reports", "create")},
            4: {("reports", "read")},
        }

    def evaluate(self, request: Request, prior: Decision) -> Decision:
        if prior.denied or prior.principal is None:
            return prior
        level = prior.principal.level
        needed = (request.resource, request.action)
        grants = self._grants.get(level, set())
        for granted_resource, granted_action in grants:
            resource_ok = granted_resource == "*" or granted_resource == request.resource
            action_ok = granted_action == "*" or granted_action == request.action
            if resource_ok and action_ok:
                return Decision(allowed=True, stage=self.name, reason="grant matched",
                                principal=prior.principal)
        return Decision(allowed=False, stage=self.name,
                        reason=f"level {level} lacks {needed}",
                        principal=prior.principal)


class RateLimitStage:
    name = "rate_limit"

    def __init__(self, max_per_minute: int = 60) -> None:
        self._max = max_per_minute
        self._windows: dict[str, list[float]] = {}

    def evaluate(self, request: Request, prior: Decision) -> Decision:
        subject = prior.principal.subject if prior.principal else request.credentials.get("subject", "")
        now = time.monotonic()
        window = [t for t in self._windows.get(subject, []) if now - t < 60.0]
        if len(window) >= self._max:
            self._windows[subject] = window
            return Decision(allowed=False, stage=self.name,
                            reason=f"rate limit {self._max}/min exceeded",
                            principal=prior.principal)
        window.append(now)
        self._windows[subject] = window
        return Decision(allowed=True, stage=self.name, reason="within rate budget",
                        principal=prior.principal)


class PolicyEngineStage:
    name = "policy"

    def __init__(self, forbidden_payload_keys: set[str] | None = None) -> None:
        self._forbidden = forbidden_payload_keys or {"raw_password", "secret_key"}

    def evaluate(self, request: Request, prior: Decision) -> Decision:
        if prior.denied:
            return prior
        leaked = sorted(set(request.payload) & self._forbidden)
        if leaked:
            return Decision(allowed=False, stage=self.name,
                            reason=f"forbidden payload keys: {leaked}")
        return Decision(allowed=True, stage=self.name, reason="policy clean")


class SecurityChain:
    def __init__(self, stages: Sequence[ChainStage]) -> None:
        if not stages:
            raise ChainError("chain requires at least one stage")
        names = [stage.name for stage in stages]
        if len(names) != len(set(names)):
            raise ChainError(f"duplicate stage names: {names}")
        self._stages = stages

    @property
    def stage_names(self) -> tuple[str, ...]:
        return tuple(stage.name for stage in self._stages)

    def enforce(self, request: Request) -> Decision:
        ordered = sorted(
            self._stages,
            key=lambda s: {"rate_limit": 0, "auth": 1}.get(s.name, 2),
        )
        decision = Decision(allowed=True, stage="entry", reason="chain start")
        for stage in ordered:
            decision = stage.evaluate(request, decision)
            if decision.principal is not None and decision.allowed:
                final = decision
            if decision.denied:
                return decision
        return Decision(
            allowed=decision.allowed,
            stage=decision.stage,
            reason=decision.reason,
            principal=getattr(locals().get("final"), "principal", None),
        )
