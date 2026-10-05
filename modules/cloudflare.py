"""Cloudflare account ops: zones, DNS, cache purge, workers. Needs CF_TOKEN."""
import json
import os
import urllib.request
import urllib.error
from core.base_module import BaseModule, ModuleResult

API = "https://api.cloudflare.com/client/v4"

def _token(config):
    tok = (config or {}).get("cf_token") or os.environ.get("CF_TOKEN")
    if not tok:
        raise RuntimeError("no token — pass --set cf_token=... or export CF_TOKEN (dash.cloudflare.com/profile/api-tokens)")
    return tok

def _call(config, path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method, headers={
        "Authorization": "Bearer " + _token(config), "Content-Type": "application/json",
        "User-Agent": "SecurityFramework/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            j = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Cloudflare HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:200]}")
    if not j.get("success"):
        raise RuntimeError("Cloudflare: " + "; ".join(e.get("message", "?") for e in j.get("errors", [])))
    return j["result"]

def _zone_id(config, name_or_id):
    if len(name_or_id) == 32 and all(c in "0123456789abcdef" for c in name_or_id.lower()):
        return name_or_id
    zones = _call(config, "/zones?per_page=50")
    z = next((x for x in zones if x["name"] == name_or_id.lower()), None)
    if not z: raise RuntimeError(f"no zone '{name_or_id}' on this token")
    return z["id"]

class CFZonesModule(BaseModule):
    @property
    def name(self): return "cf_zones"
    @property
    def description(self): return "Lists Cloudflare zones on the token."
    def run(self):
        r = ModuleResult(module_name=self.name, target=self.target or "account")
        try:
            zones = _call(self.config, "/zones?per_page=50")
            r.status = "SUCCESS"
            r.data = {"zones": [{"name": z["name"], "id": z["id"], "status": z["status"],
                                 "plan": (z.get("plan") or {}).get("name", "?")} for z in zones]}
        except Exception as e:
            r.status = "ERROR"; r.errors.append(str(e))
        return r

class CFDnsModule(BaseModule):
    @property
    def name(self): return "cf_dns"
    @property
    def description(self): return "Lists DNS records for a zone. Target = zone name or id."
    def run(self):
        r = ModuleResult(module_name=self.name, target=self.target)
        try:
            zid = _zone_id(self.config, self.target)
            recs = _call(self.config, f"/zones/{zid}/dns_records?per_page=100")
            r.status = "SUCCESS"
            r.data = {"zone_id": zid, "count": len(recs),
                      "records": [{"type": x["type"], "name": x["name"], "content": x["content"],
                                   "proxied": x["proxied"], "ttl": x["ttl"]} for x in recs]}
        except Exception as e:
            r.status = "ERROR"; r.errors.append(str(e))
        return r

class CFPurgeModule(BaseModule):
    @property
    def name(self): return "cf_purge"
    @property
    def description(self): return "Purges Cloudflare cache for a zone. Needs config confirm=yes."
    def run(self):
        r = ModuleResult(module_name=self.name, target=self.target)
        try:
            if str((self.config or {}).get("confirm", "")).lower() != "yes":
                r.status = "FAILED"; r.errors.append("refusing without confirm=yes — pass --set confirm=yes"); return r
            zid = _zone_id(self.config, self.target)
            _call(self.config, f"/zones/{zid}/purge_cache", "POST", {"purge_everything": True})
            r.status = "SUCCESS"; r.data = {"zone_id": zid, "purged": True}
        except Exception as e:
            r.status = "ERROR"; r.errors.append(str(e))
        return r

class CFWorkersModule(BaseModule):
    @property
    def name(self): return "cf_workers"
    @property
    def description(self): return "Lists workers + account id (integrates your worker fleet)."
    def run(self):
        r = ModuleResult(module_name=self.name, target=self.target or "account")
        try:
            token = _token(self.config)
            # account id via token verify
            req = urllib.request.Request(API + "/user/tokens/verify", headers={
                "Authorization": "Bearer " + token, "User-Agent": "SecurityFramework/1.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                v = json.loads(resp.read().decode("utf-8", "replace"))
            account_id = (v.get("result") or {}).get("account", {}).get("id", "?")
            workers = []
            if account_id != "?":
                try:
                    workers = _call(self.config, f"/accounts/{account_id}/workers/scripts?per_page=50")
                except Exception as e:
                    workers = [{"note": f"worker list failed: {e}"}]
            r.status = "SUCCESS"
            r.data = {"account_id": account_id,
                      "workers": [{"id": w.get("id"), "created": (w.get("created_on") or "")[:10],
                                   "modified": (w.get("modified_on") or "")[:10]} for w in workers if isinstance(w, dict) and w.get("id")]}
        except Exception as e:
            r.status = "ERROR"; r.errors.append(str(e))
        return r
