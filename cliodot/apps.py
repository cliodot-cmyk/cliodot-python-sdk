"""Cliodot runtime Apps and Surface capabilities. No workflow/connector builders."""
from __future__ import annotations
from typing import Any, Mapping
from urllib.parse import urlencode
import hashlib, hmac, json, time, secrets
import httpx
from .client import AppClient, CliodotError, _segment

class AuthAppClient(AppClient):
    """Manage app users and sign-in security with TOTP MFA, recovery codes, email/SMS one-time passcodes, and magic links."""
    def __init__(self, *, base_url: str, app_id: str, **kw):
        super().__init__(base_url=base_url,app_id=app_id,**kw); self.root=self.base_url+"/auth"
    def _user(self, uid):
        if not uid or not uid.strip(): raise CliodotError("external_user_id is required")
        return f"/apps/{_segment(self.app_id or '')}/users/{_segment(uid.strip())}"
    def upsert_user(self, external_user_id, *, profile: Mapping[str,Any] | None=None, **fields):
        return self._request("PUT",self._user(external_user_id),json={**(profile or {}),**fields},base_url=self.root)
    def mfa_status(self, external_user_id): return self._request("GET",self._user(external_user_id)+"/mfa/status",base_url=self.root)
    def totp_enroll(self, external_user_id, **payload): return self._request("POST",self._user(external_user_id)+"/mfa/totp/enroll",json=payload,base_url=self.root)
    def totp_confirm(self, external_user_id, code): return self._request("POST",self._user(external_user_id)+"/mfa/totp/confirm",json={"code":code},base_url=self.root)
    def totp_verify(self, external_user_id, code): return self._request("POST",self._user(external_user_id)+"/mfa/totp/verify",json={"code":code},base_url=self.root)
    def totp_disable(self, external_user_id): return self._request("POST",self._user(external_user_id)+"/mfa/totp/disable",base_url=self.root)
    def totp_reset(self, external_user_id, **payload): return self._request("POST",self._user(external_user_id)+"/mfa/totp/reset",json=payload,base_url=self.root)
    def recovery_codes(self, external_user_id): return self._request("POST",self._user(external_user_id)+"/mfa/recovery-codes",base_url=self.root)
    def verify_recovery_code(self, external_user_id, code): return self._request("POST",self._user(external_user_id)+"/mfa/recovery-codes/verify",json={"code":code},base_url=self.root)
    def otp_provider(self, external_user_id, provider, **payload):
        if provider not in ("email_otp","sms_otp"): raise CliodotError("provider must be email_otp or sms_otp")
        return self._request("POST",self._user(external_user_id)+f"/providers/{provider}",json=payload,base_url=self.root)
    def magic_link(self, external_user_id, **payload): return self._request("POST",self._user(external_user_id)+"/providers/magic_link",json=payload,base_url=self.root)
    def magic_link_verify(self, token): return self._request("POST",f"/apps/{_segment(self.app_id or '')}/magic-link/verify",json={"token":token},base_url=self.root)

class OAuthAppClient(AppClient):
    """Start app connections, exchange authorization results, and inspect, sync, refresh, revoke, or remove connections."""
    def __init__(self, *, base_url: str, app_id: str, **kw): super().__init__(base_url=base_url,app_id=app_id,**kw); self.root=self.base_url+"/oauth"
    def connect_start(self, **payload): return self._request("POST",f"/apps/{_segment(self.app_id or '')}/connect",json=payload,base_url=self.root)
    def connect_poll(self, **payload): return self._request("POST",f"/apps/{_segment(self.app_id or '')}/connect/poll",json=payload,base_url=self.root)
    def exchange(self, **payload): return self._request("POST","/v1/token/exchange",json=payload,base_url=self.root)
    def connection(self, connection_id): return self._request("GET",f"/v1/connections/{_segment(connection_id)}",base_url=self.root)
    def connection_token(self, connection_id): return self._request("GET",f"/v1/connections/{_segment(connection_id)}/token",base_url=self.root)
    def sync(self, connection_id, **payload): return self._request("POST",f"/v1/connections/{_segment(connection_id)}/sync",json=payload,base_url=self.root)
    def refresh(self, connection_id, **payload): return self._request("POST",f"/v1/connections/{_segment(connection_id)}/refresh",json=payload,base_url=self.root)
    def revoke(self, connection_id, **payload): return self._request("POST",f"/v1/connections/{_segment(connection_id)}/revoke",json=payload,base_url=self.root)
    def delete_connection(self, connection_id): return self._request("DELETE",f"/v1/connections/{_segment(connection_id)}",base_url=self.root)

class IdentityAppClient(AppClient):
    """Authenticate one Cliodot app to another for trusted service-to-service calls; verify, refresh, or revoke tokens and retrieve public signing keys."""
    def __init__(self, *, base_url: str, app_id: str, **kw): super().__init__(base_url=base_url,app_id=app_id,**kw); self.root=self.base_url+"/identity"
    def me(self): return self._request("GET","/v1/me",base_url=self.root)
    def authenticate(self, target_app_id, **payload): return self._request("POST","/v1/authenticate",json={"target_app_id":target_app_id,**payload},base_url=self.root)
    def verify(self, access_token, *, target_app_id=None, **payload):
        path=f"/v1/apps/{_segment(target_app_id)}/verify" if target_app_id else "/v1/verify"
        return self._request("POST",path,json={"access_token":access_token,**payload},base_url=self.root)
    def refresh(self, refresh_token, **payload): return self._request("POST","/v1/token/refresh",json={"refresh_token":refresh_token,**payload},base_url=self.root)
    def revoke(self, token, **payload): return self._request("POST","/v1/token/revoke",json={"token":token,**payload},base_url=self.root)
    def jwks(self, app_id): return self._request("GET",f"/v1/apps/{_segment(app_id)}/jwks.json",base_url=self.root)

class MemoryAppClient(AppClient):
    """Store and organize app data, retrieve records, update or delete them, and find matching items with filters or search."""
    def __init__(self, *, base_url: str, app_id: str, **kw): super().__init__(base_url=base_url,app_id=app_id,**kw); self.root=self.base_url+"/memory"
    def store(self, **payload): return self._request("POST","/v1/store",json=payload,base_url=self.root)
    def store_many(self, **payload): return self._request("POST","/v1/store-many",json=payload,base_url=self.root)
    def get(self, **payload): return self._request("POST","/v1/get",json=payload,base_url=self.root)
    def update(self, **payload): return self._request("POST","/v1/update",json=payload,base_url=self.root)
    def delete(self, **payload): return self._request("POST","/v1/delete",json=payload,base_url=self.root)
    def find(self, **payload): return self._request("POST","/v1/find",json=payload,base_url=self.root)
    def search(self, **payload): return self._request("POST","/v1/search",json=payload,base_url=self.root)

class CommercialAppClient(AppClient):
    """Python equivalent of the Node SDK's CommercialAppClient API surface."""
    def __init__(self, *, base_url: str, app_id: str, **kw):
        super().__init__(base_url=base_url, app_id=app_id, **kw)
        self.root = self.base_url + "/commercial"

    def request(self, method, path, *, data=None, params=None):
        return self._request(method, path, json=data, params=params, base_url=self.root)

    def check(self, **payload): return self.request("POST", "/v1/check", data=payload)
    def consume(self, **payload): return self.request("POST", "/v1/consume", data=payload)
    def state(self, **params): return self.request("GET", "/v1/state", params=params)
    def list_customers(self, **params): return self.request("GET", "/v1/customers", params=params)
    def customers(self, **params): return self.list_customers(**params)
    def get_customer(self, customer_id): return self.request("GET", f"/v1/customers/{_segment(customer_id)}")
    def customer(self, customer_id): return self.get_customer(customer_id)
    def create_customer(self, **payload): return self.request("POST", "/v1/customers", data=payload)
    def update_customer(self, customer_id, **payload): return self.request("PATCH", f"/v1/customers/{_segment(customer_id)}", data=payload)
    def get_customer_subscription(self, customer_id): return self.request("GET", f"/v1/customers/{_segment(customer_id)}/subscription")
    def subscription(self, customer_id): return self.get_customer_subscription(customer_id)
    def list_credits(self, customer_id, **params): return self.request("GET", f"/v1/customers/{_segment(customer_id)}/credits", params=params)
    def credits(self, customer_id, **params): return self.list_credits(customer_id, **params)
    def topup_credits(self, customer_id, **payload): return self.request("POST", f"/v1/customers/{_segment(customer_id)}/credits/topup", data=payload)

    def list_wallets(self, customer_id, **params): return self.request("GET", f"/v1/customers/{_segment(customer_id)}/wallets", params=params)
    def wallets(self, customer_id, **params): return self.list_wallets(customer_id, **params)
    def create_wallet(self, customer_id, **payload): return self.request("POST", f"/v1/customers/{_segment(customer_id)}/wallets", data=payload)
    def update_wallet(self, customer_id, wallet_id, **payload): return self.request("PATCH", f"/v1/customers/{_segment(customer_id)}/wallets/{_segment(wallet_id)}", data=payload)
    def get_wallet(self, customer_id, wallet_id): return self.request("GET", f"/v1/customers/{_segment(customer_id)}/wallets/{_segment(wallet_id)}")

    def list_accounts(self, customer_id, wallet_id, **params): return self.request("GET", f"/v1/customers/{_segment(customer_id)}/wallets/{_segment(wallet_id)}/accounts", params=params)
    def open_account(self, customer_id, wallet_id, **payload): return self.request("POST", f"/v1/customers/{_segment(customer_id)}/wallets/{_segment(wallet_id)}/accounts", data=payload)
    def update_account(self, account_id, **payload): return self.request("PATCH", f"/v1/accounts/{_segment(account_id)}", data=payload)
    def get_account(self, account_id, **params): return self.request("GET", f"/v1/accounts/{_segment(account_id)}", params=params)
    def list_entries(self, customer_id, wallet_id, **params): return self.request("GET", f"/v1/customers/{_segment(customer_id)}/wallets/{_segment(wallet_id)}/entries", params=params)
    def list_transactions(self, customer_id, wallet_id, **params): return self.request("GET", f"/v1/customers/{_segment(customer_id)}/wallets/{_segment(wallet_id)}/transactions", params=params)
    def get_transaction(self, transaction_id): return self.request("GET", f"/v1/transactions/{_segment(transaction_id)}")
    def credit(self, customer_id, wallet_id, **payload): return self.request("POST", f"/v1/customers/{_segment(customer_id)}/wallets/{_segment(wallet_id)}/credit", data=payload)
    def debit(self, customer_id, wallet_id, **payload): return self.request("POST", f"/v1/customers/{_segment(customer_id)}/wallets/{_segment(wallet_id)}/debit", data=payload)
    def transfer(self, customer_id, wallet_id, **payload): return self.request("POST", f"/v1/customers/{_segment(customer_id)}/wallets/{_segment(wallet_id)}/transfer", data=payload)
    def reverse_transaction(self, transaction_id, **payload): return self.request("POST", f"/v1/transactions/{_segment(transaction_id)}/reverse", data=payload)
    def settle_transaction(self, transaction_id, **payload): return self.request("POST", f"/v1/transactions/{_segment(transaction_id)}/settle", data=payload)
    def void_transaction(self, transaction_id, **payload): return self.request("POST", f"/v1/transactions/{_segment(transaction_id)}/void", data=payload)
    def list_holds(self, customer_id, wallet_id, **params): return self.request("GET", f"/v1/customers/{_segment(customer_id)}/wallets/{_segment(wallet_id)}/holds", params=params)
    def hold(self, customer_id, wallet_id, **payload): return self.request("POST", f"/v1/customers/{_segment(customer_id)}/wallets/{_segment(wallet_id)}/holds", data=payload)
    def capture_hold(self, customer_id, wallet_id, hold_id, **payload): return self.request("POST", f"/v1/customers/{_segment(customer_id)}/wallets/{_segment(wallet_id)}/holds/{_segment(hold_id)}/capture", data=payload)
    def release_hold(self, customer_id, wallet_id, hold_id, **payload): return self.request("POST", f"/v1/customers/{_segment(customer_id)}/wallets/{_segment(wallet_id)}/holds/{_segment(hold_id)}/release", data=payload)

    def list_units(self): return self.request("GET", "/v1/units")
    def units(self): return self.list_units()
    def create_unit(self, **payload): return self.request("POST", "/v1/units", data=payload)
    def exchange(self, customer_id, wallet_id, **payload): return self.request("POST", f"/v1/customers/{_segment(customer_id)}/wallets/{_segment(wallet_id)}/exchange", data=payload)

    def list_cards(self, customer_id, **params): return self.request("GET", f"/v1/customers/{_segment(customer_id)}/cards", params=params)
    def add_card(self, customer_id, **payload): return self.request("POST", f"/v1/customers/{_segment(customer_id)}/cards", data=payload)
    def update_card(self, customer_id, card_id, **payload): return self.request("PATCH", f"/v1/customers/{_segment(customer_id)}/cards/{_segment(card_id)}", data=payload)
    def remove_card(self, customer_id, card_id): return self.request("DELETE", f"/v1/customers/{_segment(customer_id)}/cards/{_segment(card_id)}")
    def set_default_card(self, customer_id, card_id, **payload): return self.request("POST", f"/v1/customers/{_segment(customer_id)}/cards/{_segment(card_id)}/default", data=payload)

    def list_features(self, **params): return self.request("GET", "/v1/features", params=params)
    def get_feature(self, feature_id): return self.request("GET", f"/v1/features/{_segment(feature_id)}")
    def list_plans(self, **params): return self.request("GET", "/v1/plans", params=params)
    def get_plan(self, plan_id): return self.request("GET", f"/v1/plans/{_segment(plan_id)}")
    def list_subscriptions(self, **params): return self.request("GET", "/v1/subscriptions", params=params)
    def get_subscription(self, subscription_id): return self.request("GET", f"/v1/subscriptions/{_segment(subscription_id)}")
    def list_invoices(self, **params): return self.request("GET", "/v1/invoices", params=params)
    def get_invoice(self, invoice_id): return self.request("GET", f"/v1/invoices/{_segment(invoice_id)}")
    def create_subscription(self, **payload): return self.request("POST", "/v1/subscriptions", data=payload)
    def subscribe(self, **payload): return self.create_subscription(**payload)
    def update_pending_subscription(self, subscription_id, **payload): return self.request("PATCH", f"/v1/subscriptions/{_segment(subscription_id)}/pending", data=payload)
    def change_plan(self, subscription_id, **payload): return self.request("POST", f"/v1/subscriptions/{_segment(subscription_id)}/change-plan", data=payload)
    def entitlement_topup(self, subscription_id, **payload): return self.request("POST", f"/v1/subscriptions/{_segment(subscription_id)}/entitlement-topup", data=payload)
    def charge_usage(self, subscription_id, **payload): return self.request("POST", f"/v1/subscriptions/{_segment(subscription_id)}/charge-usage", data=payload)
    def renew_subscription(self, subscription_id, **payload): return self.request("POST", f"/v1/subscriptions/{_segment(subscription_id)}/renew", data=payload)
    def renew(self, subscription_id, **payload): return self.renew_subscription(subscription_id, **payload)
    def update_subscription_status(self, subscription_id, status, **payload): return self.request("PATCH", f"/v1/subscriptions/{_segment(subscription_id)}/status", data={"status":status,**payload})
    def archive_subscription(self, subscription_id, **payload): return self.request("POST", f"/v1/subscriptions/{_segment(subscription_id)}/archive", data=payload)

    def list_events(self, **params): return self.request("GET", "/v1/events", params=params)
    def list_usage_events(self, **params): return self.request("GET", "/v1/usage-events", params=params)
    def list_event_types(self): return self.request("GET", "/v1/event-types")
    def list_payment_methods(self): return self.request("GET", "/v1/payment-methods")
    def initiate_payment(self, **payload): return self.request("POST", "/v1/payments/initiate", data=payload)
    def confirm_payment(self, **payload): return self.request("POST", "/v1/payments/confirm", data=payload)
    def quote(self, **payload): return self.request("POST", "/v1/pricing/quote", data=payload)
    def preview_discount(self, **payload): return self.request("POST", "/v1/discounts/preview", data=payload)
    def list_discounts(self, **params): return self.request("GET", "/v1/discounts", params=params)
    def list_tax_rates(self, **params): return self.request("GET", "/v1/tax-rates", params=params)
    def list_addons(self, **params): return self.request("GET", "/v1/addons", params=params)
    def assign_seat(self, **payload): return self.request("POST", "/v1/seats/assign", data=payload)
    def unassign_seat(self, **payload): return self.request("POST", "/v1/seats/unassign", data=payload)
    def issue_license(self, **payload): return self.request("POST", "/v1/licenses/issue", data=payload)
    def validate_license(self, **payload): return self.request("POST", "/v1/licenses/validate", data=payload)
    def revoke_license(self, license_id): return self.request("POST", f"/v1/licenses/{_segment(license_id)}/revoke")
    def analytics(self, **params): return self.request("GET", "/v1/analytics", params=params)
    def analytics_charts(self, **params): return self.request("GET", "/v1/analytics/charts", params=params)
    def ledger_analytics(self, **params): return self.request("GET", "/v1/ledger/analytics", params=params)
    def ledger_analytics_charts(self, **params): return self.request("GET", "/v1/ledger/analytics/charts", params=params)

class ProviderServicesClient(AppClient):
    """Discover available provider operations and data types, then execute a selected service with its required inputs."""
    def __init__(self, *, base_url: str, app_id: str, **kw): super().__init__(base_url=base_url,app_id=app_id,**kw); self.root=self.base_url+"/provider"
    def execute(self, **payload): return self._request("POST","/v1/execute",json=payload,base_url=self.root)
    def catalog(self): return self._request("GET","/v1/catalog",base_url=self.root)
    def download_types(self): return self._request("GET","/v1/types",base_url=self.root)

class Events(AppClient):
    """Publish events for other apps to consume, subscribe to event names, manage subscriptions, and receive live updates over Server-Sent Events (SSE)."""
    def __init__(self, *, base_url: str, app_id: str, instance_id: str | None=None, **kw):
        super().__init__(base_url=base_url,app_id=app_id,**kw)
        if not self.app_id: raise CliodotError("Events requires app_id")
        self.root=self.base_url+"/event"; self.instance_id=instance_id or self.app_id
    def publish(self, event, payload, **options):
        if not event or not event.strip(): raise CliodotError("event is required")
        return self._request("POST","/v1/publish",json={"event":event.strip(),"payload":payload,**options},base_url=self.root)
    def subscribe(self, events, *, name=None):
        if not events: raise CliodotError("events is required")
        body={"events":[str(x).strip() for x in events if str(x).strip()],"instance_id":self.instance_id}
        if name and name.strip(): body["name"]=name.strip()
        return self._request("POST","/v1/subscribe",json=body,base_url=self.root)
    def unsubscribe(self, subscription_id): return self._request("DELETE",f"/v1/subscribe/{_segment(subscription_id)}",base_url=self.root)
    def listen_url(self, *, events=None, subscription_id=None):
        token=self.api_key or self.app_secret
        if not token: raise CliodotError("Events credentials required (api_key/app_secret)")
        p={"app_id":self.app_id,"access_token":token,"instance_id":self.instance_id}
        if subscription_id: p["subscription_id"]=subscription_id
        elif events: p["events"]=",".join(events)
        return f"{self.root}/v1/listen?{urlencode(p)}"
    def listen(self, handler, *, events=None, subscription_id=None, timeout=None):
        if not subscription_id and not events: raise CliodotError("listen requires events or subscription_id")
        params={"instance_id":self.instance_id}
        if subscription_id: params["subscription_id"]=subscription_id
        else: params["events"]=",".join(events)
        headers={**self._headers(),"Accept":"text/event-stream"}
        with self._http.stream("GET",self.root+"/v1/listen",params=params,headers=headers,timeout=timeout) as resp:
            if resp.is_error: raise CliodotError("Event stream failed",status_code=resp.status_code)
            for line in resp.iter_lines():
                if line.startswith("data:"):
                    try: handler(json.loads(line[5:].strip()))
                    except json.JSONDecodeError: continue

class Surface:
    """Discover the capabilities exposed by a Cliodot Surface and call supported operations through a catalog-driven, dynamic SDK interface."""
    def __init__(self, *, base_url: str, slug=None, api_key=None, jwt=None, api_key_header="X-API-Key", environment=None, version="1.2.1", timeout=60.0, client=None):
        if not base_url.strip(): raise CliodotError("Surface requires base_url")
        self.base_url=base_url.strip().rstrip("/"); self.slug=slug.strip() if slug else None
        self.invoke_base_url=self.base_url+(f"/{self.slug}" if self.slug else "")
        self.api_key,self.jwt,self.api_key_header=api_key,jwt,api_key_header; self.environment=environment; self.version=version
        self._http=client or httpx.Client(timeout=timeout); self._catalog=None
    def _headers(self, method, path, body=None):
        stamp=str(int(time.time()*1000)); nonce=secrets.token_hex(16)
        raw="" if body is None or body=={} else (body if isinstance(body,str) else json.dumps(body,separators=(",",":"),ensure_ascii=False))
        canonical=".".join([stamp,nonce,method.upper(),path or "/",hashlib.sha256(raw.encode()).hexdigest()])
        secret=self.api_key or self.jwt or f"sdk:{self.slug or 'gateway'}"
        sig=hmac.new(secret.encode(),canonical.encode(),hashlib.sha256).hexdigest()
        h={"X-Cliodot-Client":"sdk","X-Cliodot-SDK-Version":self.version,"X-Cliodot-SDK-Timestamp":stamp,"X-Cliodot-SDK-Nonce":nonce,"X-Cliodot-SDK-Signature":sig}
        if self.api_key: h[self.api_key_header]=self.api_key
        if self.jwt: h["Authorization"]="Bearer "+self.jwt
        if self.environment: h["x-cliodot-environment"]="dev" if self.environment in ("dev","development") else "prod"
        return h
    def load_surface(self, force=False):
        if self._catalog is not None and not force: return self._catalog
        path="/sdk/surface"; resp=self._http.get(self.invoke_base_url+path,headers=self._headers("GET",path))
        data=resp.json()
        if resp.is_error or data.get("ok") is False: raise CliodotError("Failed to load Surface",status_code=resp.status_code,data=data)
        self._catalog=data.get("surface",data); return self._catalog
    def execute(self, sdk_path, operation, *args):
        catalog=self.load_surface(); ops=catalog.get("ops",[]) if isinstance(catalog,dict) else []
        dotted=".".join(sdk_path); op=next((x for x in ops if x.get("op")==operation and x.get("sdk_path")==sdk_path),None)
        if not op: raise CliodotError(f"Surface operation not found: {dotted}.{operation}")
        params={}; body=None; path_args=iter(args)
        for name in op.get("path_params",[]): params[name]=next(path_args)
        if op.get("body"): body=next(path_args,None)
        path=op.get("endpoint_path","/")
        for key,val in params.items(): path=path.replace("{"+key+"}",_segment(val))
        query=next(path_args,None) if op.get("query_schema") else None
        url=self.invoke_base_url+path; headers=self._headers(op.get("method","GET"),path,body)
        if query is not None and not body: return self._http.request(op.get("method","GET"),url,params=query,headers=headers).json()
        data=body if body is not None else None
        resp=self._http.request(op.get("method","GET"),url,json=data,headers=headers)
        result=resp.json()
        if resp.is_error or result.get("ok") is False: raise CliodotError("Surface request failed",status_code=resp.status_code,data=result)
        return result
    def __getattr__(self,name):
        if name.startswith("_"): raise AttributeError(name)
        return _SurfaceNamespace(self,[name])

class _SurfaceNamespace:
    def __init__(self,surface,path): self.surface=surface; self.path=path
    def __getattr__(self,name):
        if name.startswith("_"): raise AttributeError(name)
        return _SurfaceNamespace(self.surface,self.path+[name])
    def __call__(self,*args,**kwargs):
        op=kwargs.pop("operation",None)
        if kwargs: args=(*args,kwargs)
        return self.surface.execute(self.path[:-1],op or self.path[-1],*args)
