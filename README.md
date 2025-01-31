# security-chain-framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An enterprise security pipeline: rate limiting → authentication → RBAC with level ceilings → payload policy — every request walks the chain, every denial names its stage.

## 🚀 Overview

Security fails when checks are scattered across handlers. `security-chain-framework` composes them into one ordered pipeline. Stages are independent objects sharing a frozen `Decision`; the chain auto-orders itself (rate-limit first, auth second, policy last), PBKDF2-salted credentials verify in constant time, and a 5-level access model (1=strongest … 5=weakest) gates resources through wildcard grants. Denials always answer *where* and *why*.

## ✨ Features

- **Ordered chain:** stages sorted `rate_limit → auth → rbac/policy` regardless of construction order; duplicate names rejected
- **PBKDF2 credential store:** 100k iterations, per-subject salt, `hmac.compare_digest` verification
- **Session manager:** TTL-based sessions with expiry cleanup and `active_count()` hygiene
- **RBAC with ceilings:** level 4 can't do what level 2 can, even with matching grants; admin (`level 1`) holds `*/*`
- **Rate limiting:** sliding 60s window per subject; trips deterministically for tests
- **Policy engine:** forbidden payload keys (e.g. `raw_password`) rejected before handlers run
- **Typed denials:** every `Decision` carries stage + reason + principal when known

## 🚧 Structure

```
security-chain-framework/
├── src/security_chain/
│   ├── __init__.py
│   ├── contracts.py
│   └── core.py
├── tests/
│   └── test_core.py
├── README.md
└── pyproject.toml
```

## 📦 Installation

```bash
git clone https://github.com/supremeloki/security-chain-framework.git
cd security-chain-framework
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

## 📋 Requirements

- Python 3.11+
- No runtime dependencies

## 🏃 Quick Start

```python
from security_chain import (
    AuthStage, CredentialStore, PolicyEngineStage,
    RbacStage, RateLimitStage, Request, SecurityChain,
)

store = CredentialStore()
store.register("admin_user", "s3cret!", level=1)
store.register("basic_user", "hunter2", level=4)

chain = SecurityChain([
    RateLimitStage(max_per_minute=60),
    AuthStage(store=store),
    RbacStage(),
    PolicyEngineStage(),
])

decision = chain.enforce(Request(
    request_id="r-1",
    resource="reports",
    action="read",
    credentials={"subject": "admin_user", "secret": "s3cret!"},
))
print(decision.allowed, decision.stage)
```

### Sessions

```python
auth = AuthStage(store=store)
auth.sessions.open("tok-1", "admin_user")
# later requests use {"session": "tok-1"} instead of raw credentials
```

## 🔧 Error Handling

```text
ChainError               # duplicate/empty stage list, invalid principal level
├── AuthenticationError  # reserved for hard auth failures
├── AuthorizationError   # reserved for grant mismatches
└── PolicyViolationError # reserved for policy breaches
```

Request-level problems become denied `Decision`s — never exceptions.

## 🧪 Testing

```bash
pytest tests/ -v
```

## 📝 Code Quality

- Full type hints (`X | None` style), frozen contracts
- Zero comments — names carry the meaning
- Salted hashing + constant-time comparison throughout

## 📄 License

MIT — see [LICENSE](LICENSE).

## 👤 Author

**Kooroush Masoumi**

---

⭐ Star this repo if you find it useful!
