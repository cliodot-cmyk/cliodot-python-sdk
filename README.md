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

- **Auth**: Create or update app-user records and manage sign-in protection, including TOTP multi-factor authentication, recovery codes, email/SMS one-time passcodes, and magic links.
- **OAuth**: Start app connections, poll for connection completion, exchange authorization results, and inspect, sync, refresh, revoke, or delete connections.
- **Identity**: Authenticate one Cliodot app to another for trusted service-to-service access; verify access tokens, refresh or revoke tokens, inspect the current identity, and retrieve public signing keys (JWKS).
- **Memory**: Store records, store multiple records at once, retrieve and update data, delete records, and find or search for matching information.
- **Commercial**: Check and record usage, inspect account state and customer subscriptions, review credits, top up credits, and list or create customer wallets.
- **Events**: Publish named events with payloads, subscribe or unsubscribe, and receive live event updates through Server-Sent Events (SSE).
- **Provider Services**: Browse the available provider-operation catalog and data types, then execute a selected service with the required inputs.
- **Surface capabilities**: Load the Surface capability catalog and invoke supported operations dynamically, such as retrieving a user through `surface.users.get(id)`.
- **Webhook helpers**: Generate and verify HMAC webhook signatures, including timestamped signatures.

## Scope and compatibility

The API follows the Node SDK's runtime route families (`/auth`, `/oauth`, `/identity`, `/memory`, `/commercial`, `/event`, and `/provider`). Python method names use snake_case. This is an initial port of app-facing runtime APIs; compare the exact endpoint contracts against your deployed Cliodot version before production use. No workflow or connector builders are included.
