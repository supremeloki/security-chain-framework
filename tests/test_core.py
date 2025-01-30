import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from security_chain import (
    AuthStage,
    ChainError,
    CredentialStore,
    Decision,
    PolicyEngineStage,
    RbacStage,
    RateLimitStage,
    Request,
    SecurityChain,
    SessionManager,
)


@pytest.fixture
def store():
    creds = CredentialStore()
    creds.register("admin_user", "s3cret!", level=1)
    creds.register("basic_user", "hunter2", level=4)
    return creds


def build_chain(store: CredentialStore) -> SecurityChain:
    return SecurityChain([
        RateLimitStage(max_per_minute=100),
        AuthStage(store=store),
        RbacStage(),
        PolicyEngineStage(),
    ])


def admin_request(**overrides):
    base = dict(request_id="r1", resource="reports", action="read",
                credentials={"subject": "admin_user", "secret": "s3cret!"})
    base.update(overrides)
    return Request(**base)


def test_valid_credentials_pass_full_chain(store):
    decision = build_chain(store).enforce(admin_request())
    assert decision.allowed
    assert decision.principal.level == 1


def test_bad_password_denied_at_auth(store):
    request = admin_request(credentials={"subject": "admin_user", "secret": "wrong"})
    decision = build_chain(store).enforce(request)
    assert decision.denied
    assert decision.stage == "auth"


def test_unknown_subject_denied(store):
    request = admin_request(credentials={"subject": "ghost", "secret": "x"})
    decision = build_chain(store).enforce(request)
    assert decision.denied


def test_level_ceiling_blocks_write(store):
    request = admin_request(
        credentials={"subject": "basic_user", "secret": "hunter2"},
        resource="data", action="write",
    )
    decision = build_chain(store).enforce(request)
    assert decision.denied
    assert decision.stage == "rbac"


def test_admin_wildcard_allows_everything(store):
    chain = build_chain(store)
    for resource, action in [("data", "write"), ("anything", "delete")]:
        request = admin_request(resource=resource, action=action)
        assert chain.enforce(request).allowed


def test_rate_limit_trips_after_burst():
    store = CredentialStore()
    store.register("burst_user", "pw123456", level=3)
    limiter = RateLimitStage(max_per_minute=3)
    auth = AuthStage(store=store)
    chain = SecurityChain([limiter, auth])
    request = Request(request_id="r", resource="data", action="read",
                      credentials={"subject": "burst_user", "secret": "pw123456"})
    allowed_count = 0
    denied_stages = []
    for _ in range(5):
        decision = chain.enforce(request)
        if decision.allowed:
            allowed_count += 1
        else:
            denied_stages.append(decision.stage)
    assert allowed_count == 3
    assert "rate_limit" in denied_stages


def test_policy_blocks_forbidden_keys(store):
    request = admin_request(payload={"raw_password": "oops"})
    decision = build_chain(store).enforce(request)
    assert decision.denied
    assert decision.stage == "policy"


def test_session_flow_avoids_reauth(store):
    auth = AuthStage(store=store)
    sessions = auth.sessions
    sessions.open("tok-1", "admin_user")
    request = Request(request_id="r2", resource="reports", action="read",
                      credentials={"session": "tok-1"})
    decision = auth.evaluate(request, Decision(True, "entry", "start"))
    assert decision.allowed


def test_expired_session_rejected(store, monkeypatch):
    auth = AuthStage(store=store)
    sessions = SessionManager(ttl_seconds=10)
    auth.sessions = sessions
    sessions.open("tok-x", "admin_user")
    real_mono = __import__("time").monotonic
    monkeypatch.setattr(__import__("time"), "monotonic", lambda: real_mono() + 20)
    assert sessions.resolve("tok-x") is None


def test_duplicate_stage_names_rejected(store):
    with pytest.raises(ChainError):
        SecurityChain([RateLimitStage(), RateLimitStage()])


def test_empty_chain_rejected():
    with pytest.raises(ChainError):
        SecurityChain([])


def test_invalid_principal_level_rejected():
    from security_chain import Principal

    with pytest.raises(ChainError):
        Principal(subject="weird", level=9)


def test_credential_hashing_is_salted_per_subject():
    creds = CredentialStore()
    creds.register("alice", "same-pass", level=3)
    creds.register("bob", "same-pass", level=3)
    assert creds._secrets["alice"] != creds._secrets["bob"]
