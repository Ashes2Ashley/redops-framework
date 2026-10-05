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

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
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
                       "open_count": len(open_ports), "open": open_ports}
        return result
