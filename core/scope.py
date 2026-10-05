"""Authorized-target enforcement.

Fail-closed: an empty Scope authorizes nothing. Constructing an
HttpClient without a Scope raises unless allow_all=True is passed
explicitly.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit


class ScopeViolation(Exception):
    """Raised when a target falls outside the authorized scope."""


@dataclass
class Scope:
    domains: list = field(default_factory=list)
    cidrs: list = field(default_factory=list)
    handles: list = field(default_factory=list)

    def __post_init__(self):
        self._nets = [ipaddress.ip_network(c, strict=False) for c in self.cidrs]

    @classmethod
    def from_file(cls, path):
        with open(path) as f:
            data = json.load(f)
        return cls(domains=data.get("domains", []),
                   cidrs=data.get("cidrs", []),
                   handles=data.get("handles", []))

    def _domain_ok(self, host):
        host = host.lower().rstrip(".")
        for pat in self.domains:
            pat = pat.lower().rstrip(".")
            if pat.startswith("*."):
                # wildcard matches subdomains only; list the apex to include it
                if host.endswith("." + pat[2:]):
                    return True
            elif host == pat:
                return True
        return False

    def _ip_ok(self, host):
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(addr in net for net in self._nets)

    def allows_url(self, url):
        host = urlsplit(url).hostname
        if not host:
            return False
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return self._domain_ok(host)   # hostname -> domain rules
        return self._ip_ok(host)           # IP literal -> CIDR rules

    def require_url(self, url):
        if not self.allows_url(url):
            raise ScopeViolation("out of scope: %r" % url)

    def allows_handle(self, handle):
        return handle.lower() in {h.lower() for h in self.handles}
