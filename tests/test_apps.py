import hashlib, hmac, time
import httpx
import pytest
from cliodot import AuthAppClient, CliodotError, IdentityAppClient, MemoryAppClient, Surface, verify_webhook_signature, verify_timestamped_signature

def test_memory_store_uses_runtime_route_and_app_headers():
    seen={}
    def handler(req):
        seen["url"]=str(req.url); seen["json"]=req.read().decode(); seen["auth"]=req.headers.get("Authorization"); seen["app"]=req.headers.get("x-cliodot-app-id")
        return httpx.Response(200,json={"ok":True,"id":"item-1"})
    c=MemoryAppClient(base_url="https://api.example.test",app_id="memory-a",api_key="key",client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert c.store(collection="notes",id="item-1",content={"x":1})["id"]=="item-1"
    assert seen["url"].endswith("/memory/v1/store") and seen["auth"]=="Bearer key" and seen["app"]=="memory-a"
    assert '"collection": "notes"' in seen["json"]

def test_auth_rejects_blank_external_user_id():
    c=AuthAppClient(base_url="https://api.example.test",app_id="auth-a",client=httpx.Client(transport=httpx.MockTransport(lambda r:httpx.Response(200,json={}))))
    with pytest.raises(CliodotError,match="external_user_id is required"): c.mfa_status(" ")

def test_api_errors_are_structured():
    c=IdentityAppClient(base_url="https://api.example.test",app_id="identity-a",client=httpx.Client(transport=httpx.MockTransport(lambda r:httpx.Response(403,json={"message":"forbidden","code":"NO_ACCESS"}))))
    with pytest.raises(CliodotError) as e: c.me()
    assert e.value.status_code==403 and e.value.code=="NO_ACCESS"

def test_webhook_signatures():
    body='{"event":"invoice.paid"}'; sig=hmac.new(b"secret",body.encode(),hashlib.sha256).hexdigest()
    assert verify_webhook_signature(body,sig,"secret") and not verify_webhook_signature(body,"bad","secret")
    stamp=str(int(time.time())); tsig=hmac.new(b"secret",f"{stamp}.{body}".encode(),hashlib.sha256).hexdigest()
    assert verify_timestamped_signature(body,{"x-cliodot-timestamp":stamp,"x-cliodot-signature":tsig},"secret")

def test_surface_dynamic_capability_lookup():
    def handler(req):
        if req.url.path.endswith("/sdk/surface"): return httpx.Response(200,json={"surface":{"version":1,"ops":[{"op":"get","sdk_path":["users"],"method":"GET","endpoint_path":"/users/{id}","path_params":["id"],"body":False}]}})
        return httpx.Response(200,json={"data":{"id":"user-1"}})
    s=Surface(base_url="https://gateway.example.test",client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert s.users.get("user-1")=={"data":{"id":"user-1"}}

def test_commercial_client_exposes_node_sdk_method_surface():
    from cliodot import CommercialAppClient
    c = CommercialAppClient(
        base_url="https://api.example.test",
        app_id="commercial-a",
        client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"ok": True}))),
    )
    expected = [
        "check", "consume", "state", "list_customers", "get_customer",
        "create_customer", "update_customer", "get_customer_subscription",
        "list_credits", "topup_credits", "list_wallets", "create_wallet",
        "update_wallet", "get_wallet", "list_accounts", "open_account",
        "update_account", "get_account", "list_entries", "list_transactions",
        "get_transaction", "credit", "debit", "transfer", "reverse_transaction",
        "settle_transaction", "void_transaction", "list_holds", "hold",
        "capture_hold", "release_hold", "list_units", "create_unit", "exchange",
        "list_cards", "add_card", "update_card", "remove_card", "set_default_card",
        "list_features", "get_feature", "list_plans", "get_plan",
        "list_subscriptions", "get_subscription", "list_invoices", "get_invoice",
        "create_subscription", "subscribe", "update_pending_subscription",
        "change_plan", "entitlement_topup", "charge_usage", "renew_subscription",
        "renew", "list_events", "list_usage_events", "list_event_types",
        "list_payment_methods", "initiate_payment", "confirm_payment", "quote",
        "preview_discount", "list_discounts", "list_tax_rates", "list_addons",
        "assign_seat", "unassign_seat", "issue_license", "validate_license",
        "revoke_license", "analytics", "analytics_charts", "ledger_analytics",
        "ledger_analytics_charts",
    ]
    missing = [name for name in expected if not callable(getattr(c, name, None))]
    assert not missing, f"Commercial methods missing: {missing}"
    c._http.close()
