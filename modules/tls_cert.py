"""TLS certificate inspection via direct handshake. Stdlib only."""
import base64
import os
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from core.base_module import BaseModule, ModuleResult


def _tcp_connect(host: str, port: int, timeout: int = 10) -> socket.socket:
    """Plain TCP, or HTTP CONNECT tunnel when a proxy is configured."""
    proxy = (
        os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
        or os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY")
    )
    if not proxy:
        return socket.create_connection((host, port), timeout=timeout)
    pu = urllib.parse.urlparse(proxy)
    sock = socket.create_connection((pu.hostname, pu.port or 8080), timeout=timeout)
    try:
        headers = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        if pu.username:
            creds = f"{urllib.parse.unquote(pu.username)}:{urllib.parse.unquote(pu.password or '')}"
            headers += "Proxy-Authorization: Basic " + base64.b64encode(creds.encode()).decode() + "\r\n"
        headers += "\r\n"
        sock.sendall(headers.encode("utf-8"))
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(4096)
            if not chunk:
                raise OSError("proxy closed the connection")
            resp += chunk
        status = resp.split(b"\r\n", 1)[0]
        if b" 200 " not in status:
            raise OSError("proxy CONNECT failed: " + status.decode("utf-8", "replace"))
        return sock
    except Exception:
        sock.close()
        raise

class TLSCertModule(BaseModule):
    @property
    def name(self) -> str:
        return "tls_cert"

    @property
    def description(self) -> str:
        return "Grabs the live TLS certificate: subject, issuer, SANs, validity window."

    def run(self) -> ModuleResult:
        result = ModuleResult(module_name=self.name, target=self.target)
        host = self.target.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        port = int(self.config.get("port", 443))
        if not host or "." not in host:
            result.status = "FAILED"
            result.errors.append("give a hostname, e.g. example.com")
            return result
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            # OPTIONAL (not NONE): handshake never fails on a bad cert, but the
            # peer cert is still parsed into a dict (CERT_NONE leaves it empty on TLS 1.3)
            ctx.verify_mode = ssl.CERT_OPTIONAL
            with _tcp_connect(host, port, timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    cipher = tls.cipher()
                    version = tls.version()
            if not cert:
                result.status = "FAILED"
                result.errors.append("no certificate presented")
                return result
            def dn(parts):
                return ", ".join("=".join(p[0]) for p in parts) if parts else "?"
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (not_after - now).days
            sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
            result.status = "SUCCESS"
            result.data = {
                "host": host, "port": port,
                "subject": dn(cert.get("subject")),
                "issuer": dn(cert.get("issuer")),
                "serial": cert.get("serialNumber"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "days_remaining": days_left,
                "expired": days_left < 0,
                "expires_soon_30d": 0 <= days_left < 30,
                "san_count": len(sans),
                "sans": sans[:25],
                "tls_version": version,
                "cipher": cipher[0] if cipher else "?",
            }
        except socket.timeout:
            result.status = "CONNECTION_ERROR"
            result.errors.append("connection timed out")
        except OSError as e:
            result.status = "CONNECTION_ERROR"
            result.errors.append(f"connection failed: {e}")
        except Exception as e:
            result.status = "ERROR"
            result.errors.append(f"Unexpected error: {e}")
        return result
