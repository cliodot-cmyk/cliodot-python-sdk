"""Webhook signature helpers."""
import hashlib,hmac,json,time
from typing import Any, Mapping
def sign_webhook_payload(payload: Any, secret: str) -> str:
    raw=payload if isinstance(payload,str) else json.dumps(payload,separators=(",",":"),ensure_ascii=False)
    return hmac.new(secret.encode(),raw.encode(),hashlib.sha256).hexdigest()
def verify_webhook_signature(payload: Any, signature: str | None, secret: str, *, prefix="sha256=") -> bool:
    if not signature or not secret: return False
    supplied=signature.strip()
    if supplied.startswith(prefix): supplied=supplied[len(prefix):]
    return hmac.compare_digest(supplied,sign_webhook_payload(payload,secret))
def verify_timestamped_signature(payload: Any, headers: Mapping[str,str], secret: str, *, tolerance_seconds=300, timestamp_header="x-cliodot-timestamp", signature_header="x-cliodot-signature") -> bool:
    h={k.lower():v for k,v in headers.items()}; stamp=h.get(timestamp_header.lower()); sig=h.get(signature_header.lower())
    if not stamp or not sig: return False
    try: ts=int(stamp)
    except (ValueError,TypeError): return False
    if abs(time.time()-ts)>tolerance_seconds: return False
    raw=payload if isinstance(payload,str) else json.dumps(payload,separators=(",",":"),ensure_ascii=False)
    expected=hmac.new(secret.encode(),f"{stamp}.{raw}".encode(),hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig.removeprefix("sha256="),expected)
