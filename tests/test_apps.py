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
