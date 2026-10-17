"""Shared HTTP primitives for Cliodot Apps."""
from __future__ import annotations
from typing import Any, Mapping
from urllib.parse import quote
import httpx

class CliodotError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None, code: str | None = None, data: Any = None):
        super().__init__(message); self.status_code=status_code; self.code=code; self.data=data

def _segment(value: str) -> str:
    return quote(str(value), safe="")

class AppClient:
    def __init__(self, *, base_url: str, app_id: str | None = None, api_key: str | None = None,
                 app_secret: str | None = None, app_api_key: str | None = None,
                 environment: str | None = None, timeout: float = 30.0, client: httpx.Client | None = None):
        if not isinstance(base_url,str) or not base_url.strip(): raise CliodotError(f"{type(self).__name__} requires base_url")
        self.base_url=base_url.strip().rstrip("/"); self.app_id=(app_id or "").strip() or None
        self.api_key=(api_key or app_api_key or "").strip() or None; self.app_secret=(app_secret or "").strip() or None
        self.environment=environment; self._owns_client=client is None
        self._http=client or httpx.Client(timeout=timeout, headers={"Accept":"application/json"})
    def close(self):
        if self._owns_client: self._http.close()
    def __enter__(self): return self
    def __exit__(self,*_): self.close()
    def _headers(self):
        h={"Accept":"application/json","Content-Type":"application/json"}
        if self.app_id: h["x-cliodot-app-id"]=self.app_id
        if self.api_key: h["Authorization"]=f"Bearer {self.api_key}"
        elif self.app_secret: h["x-cliodot-app-secret"]=self.app_secret
        if self.environment:
            env=self.environment.lower()
            if env in ("dev","development"): h["x-cliodot-environment"]="dev"
            elif env in ("prod","production"): h["x-cliodot-environment"]="prod"
            else: raise CliodotError("environment must be dev, prod, development, or production")
        return h
    def _request(self, method: str, path: str, *, json: Any=None, params: Mapping[str,Any] | None=None,
                 headers: Mapping[str,str] | None=None, base_url: str | None=None):
        url=(base_url or self.base_url).rstrip("/")+"/"+path.lstrip("/")
        try: response=self._http.request(method,url,json=json,params=params,headers={**self._headers(),**(headers or {})})
        except httpx.HTTPError as exc: raise CliodotError(f"Cliodot request failed: {method.upper()} {path}: {exc}") from exc
        try: data=response.json()
        except ValueError: data={"message":response.text}
        if response.is_error or (isinstance(data,dict) and data.get("ok") is False):
            message=(data.get("message") or data.get("error") or data.get("detail") or "Request failed") if isinstance(data,dict) else "Request failed"
            if isinstance(message,dict): message=message.get("message") or str(message)
            raise CliodotError(str(message),status_code=response.status_code,code=data.get("code") if isinstance(data,dict) else None,data=data)
        return data
