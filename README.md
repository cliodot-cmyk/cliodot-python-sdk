# Cliodot Python SDK

Python SDK for Cliodot runtime Apps and Surface capabilities. This initial Apps-focused implementation intentionally excludes workflow builders and connector builders.

## Install and test

```bash
pip install .
pip install '.[test]'
pytest
```

## Configure an App client

```python
import os
from cliodot import IdentityAppClient

identity = IdentityAppClient(
    base_url=os.environ["CLIODOT_BASE_URL"],
    app_id="identity_payroll",
    api_key=os.environ["IDENTITY_APP_API_KEY"],
    environment="prod",
)
token = identity.authenticate("identity_hrms", scopes=["employees:read"])
```

Clients accept `api_key` (or `app_api_key`), optional `app_secret`, `environment`, and an optional `httpx.Client` for testing. Keep credentials in environment variables.

## Apps included

- Auth: user records, TOTP MFA, recovery codes, OTP provider and magic-link operations.
- OAuth: app connection, exchange and connection lifecycle.
- Identity: service-to-service authenticate, verify, refresh, revoke and JWKS.
- Memory: store, get, update, delete, find and search.
- Commercial: usage checks/consumption, customers, subscriptions, credits and wallet basics.
- Events: publish, subscribe, unsubscribe and SSE listen URL/consumer.
- Provider Services: catalog, types artifact and execution.
- Surface capabilities: catalog-driven dynamic operation calls.
- Webhook helpers: HMAC signature generation and verification.

## Scope and compatibility

The API follows the Node SDK's runtime route families (`/auth`, `/oauth`, `/identity`, `/memory`, `/commercial`, `/event`, and `/provider`). Python method names use snake_case. This is an initial port of app-facing runtime APIs; compare the exact endpoint contracts against your deployed Cliodot version before production use. No workflow or connector builders are included.
