"""TCP port probe on common service ports. Proxy-aware. Stdlib only."""
import os
import socket
import urllib.parse
from core.base_module import BaseModule, ModuleResult
from modules.tls_cert import _tcp_connect

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
}

class PortProbeModule(BaseModule):
    @property
    def name(self) -> str:
        return "port_probe"

    @property
    def description(self) -> str:
        return "TCP connect probe on common ports; grabs banners where offered."

    @property
    def alias(self) -> str:
        return "open doors check"

    @property
    def reads(self) -> str:
        return "Raw TCP connections to the target host on common service ports."

    @property
    def returns(self) -> str:
        return "Open ports with service labels and first banner line, findings."

    @property
    def failure_modes(self) -> list:
        return [
            "Firewalls drop or RST probes — a closed port and a filtered port look identical here.",
            "Banner grabbing is fingerprintable; the target's defenders can see this scan.",
            "Service labels are port-number guesses, not identifications — verify before claiming.",
        ]

    @property
    def requires_auth(self) -> bool:
        # Doctrine section 6: this goes beyond ordinary public browsing.
        # It needs explicit per-action authorization under the ROE.
        return True

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        if not self.config.get("auth_confirmed"):
            result.status = "FAILED"
            result.errors.append(
                "port_probe requires explicit per-action authorization: "
                "pass --set auth_confirmed=yes with a written authorization on record.")
            return result
        host = self.target.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        ports = self.config.get("ports")
        if ports:
            try: port_list = [int(p) for p in str(ports).split(",")]
            except ValueError:
                result.status = "FAILED"; result.errors.append("ports must be comma-separated ints"); return result
        else:
            port_list = sorted(COMMON_PORTS)
        if not host:
            result.status = "FAILED"; result.errors.append("give a host"); return result
        # Fail-closed scope check for raw TCP.
        scope = self.config.get("_scope")
        if scope is not None:
            try:
                scope.require_host(host)
            except Exception as e:
                result.status = "FAILED"
                result.errors.append(str(e))
                return result
        elif not self.config.get("_allow_all", False):
            result.status = "FAILED"
            result.errors.append("unscoped run refused (no scope, no --allow-all)")
            return result
        open_ports = []
        for port in port_list:
            try:
                sock = _tcp_connect(host, port, timeout=4)
            except Exception:
                continue
            banner = ""
            try:
                sock.settimeout(3)
                # nudge banner-grabbing services
                if port in (80, 8080, 8000):
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(256)
                banner = data.decode("utf-8", "replace").split("\r\n")[0][:100]
            except Exception:
                pass
            finally:
                sock.close()
            open_ports.append({"port": port, "service": COMMON_PORTS.get(port, "?"), "banner": banner})
        result.status = "SUCCESS"
        result.data = {"host": host, "ports_scanned": len(port_list),
                       "open_count": len(open_ports), "open": open_ports,
                       "authorized": True}
        for op in open_ports:
            result.add_finding(
                claim="Port %d open on %s (banner: %s)" % (
                    op["port"], host, op["banner"] or "no banner"),
                tag="OBSERVED", method="TCP connect probe (authorized run)",
                evidence={"port": op["port"], "service_guess": op["service"]},
                confidence="CORROBORATED")
        return result
