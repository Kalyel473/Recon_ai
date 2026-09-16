"""
High-Performance Async Port Scanner with Advanced TLS/SSL Analysis.
Uses asyncio and native sockets for concurrent connection management.
"""

import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import List, Tuple, Optional, Dict, Any
from airecon.core.config import COMMON_PORTS
from airecon.core.models import PortResult
from airecon.core.logger import Logger

class AsyncPortScanner:
    def __init__(self, timeout: float = 1.5, threads: int = 200):
        self.timeout = timeout
        self.concurrency = max(10, min(threads, 1000))

    def _grab_tls_details(self, ip: str, port: int) -> Tuple[str, Optional[Dict[str, Any]], List[str]]:
        banner = ""
        tls_info: Dict[str, Any] = {
            "protocol": "",
            "common_name": "",
            "issuer": "",
            "sans": [],
            "not_after": "",
            "days_left": None,
            "expired": False,
            "self_signed": False
        }
        sans: List[str] = []

        # Attempt 1: Try with default context (check_hostname=False, verify CA)
        cert = None
        s_proto = ""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            with socket.create_connection((ip, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as s:
                    s_proto = s.version() or "TLS"
                    cert = s.getpeercert()
        except ssl.SSLCertVerificationError:
            # Certificate validation failed (e.g. self-signed, untrusted CA or expired)
            tls_info["self_signed"] = True
        except (socket.error, OSError, ssl.SSLError):
            pass

        # Attempt 2: Fallback with CERT_NONE to at least get TLS version and raw connection
        if not s_proto:
            try:
                ctx_insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx_insecure.check_hostname = False
                ctx_insecure.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=self.timeout) as raw:
                    with ctx_insecure.wrap_socket(raw, server_hostname=ip) as s:
                        s_proto = s.version() or "TLS"
            except Exception:
                pass

        if s_proto:
            tls_info["protocol"] = s_proto
            banner = f"TLS/{s_proto}"

        if cert and isinstance(cert, dict):
            # Parse Common Name
            subject = cert.get("subject", ())
            for rdn in subject:
                for key, val in rdn:
                    if key == "commonName":
                        tls_info["common_name"] = val
                        break

            # Parse Issuer
            issuer = cert.get("issuer", ())
            for rdn in issuer:
                for key, val in rdn:
                    if key in ("organizationName", "commonName"):
                        tls_info["issuer"] = val
                        break

            # Parse SANs
            for item in cert.get("subjectAltName", ()):
                if item[0] == "DNS" and item[1]:
                    dns_name = item[1].lower()
                    if dns_name not in sans:
                        sans.append(dns_name)
            tls_info["sans"] = sans

            # Parse Validity
            not_after = cert.get("notAfter", "")
            if not_after:
                tls_info["not_after"] = not_after
                try:
                    exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days = (exp_dt - now).days
                    tls_info["days_left"] = days
                    tls_info["expired"] = (days < 0)
                except Exception:
                    pass

            if tls_info["common_name"]:
                banner += f" cert-cn={tls_info['common_name']}"
            if sans:
                banner += f" (SANs: {len(sans)})"
            if tls_info["expired"]:
                banner += " [CERT EXPIRADO]"
            elif tls_info["days_left"] is not None and tls_info["days_left"] < 30:
                banner += f" [Expira em {tls_info['days_left']}d]"

        return banner, tls_info if s_proto else None, sans

    def _grab_plain_banner(self, ip: str, port: int) -> str:
        banner = ""
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as s:
                s.settimeout(2.0)
                if port in (80, 8080, 8000, 8008, 8888):
                    s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
                raw = s.recv(1024)
                banner = raw.decode(errors="replace").strip()
        except (socket.error, OSError):
            pass
        return banner[:400]

    def _grab_banner(self, ip: str, port: int) -> Tuple[str, Optional[Dict[str, Any]], List[str]]:
        if port in (443, 8443, 993, 995, 465, 992, 6443):
            return self._grab_tls_details(ip, port)
        else:
            banner = self._grab_plain_banner(ip, port)
            return banner, None, []

    @staticmethod
    def guess_service(port: int, banner: str) -> Tuple[str, str]:
        service = COMMON_PORTS.get(port, "unknown")
        version = ""
        b = (banner or "").lower()
        patterns = [
            (r"openssh[_\-]([\w.]+)", "ssh"),
            (r"vsftpd\s*([\d.]+)", "ftp"),
            (r"pure-ftpd", "ftp"),
            (r"proftpd\s*([\d.]+)", "ftp"),
            (r"apache[/ ]([\d.]+)", "http"),
            (r"nginx[/ ]([\d.]+)", "http"),
            (r"iis[/ ]?([\d.]+)", "http"),
            (r"mysql\s+([\d.]+)", "mysql"),
            (r"mariadb", "mysql"),
            (r"microsoft", "msrpc"),
            (r"redis", "redis"),
            (r"postfix", "smtp"),
            (r"exim\s*([\d.]+)?", "smtp"),
            (r"dovecot", "pop3/imap"),
            (r"postgresql", "postgresql"),
        ]
        for pat, svc in patterns:
            m = re.search(pat, b)
            if m:
                service = svc
                try:
                    version = m.group(1) or ""
                except IndexError:
                    version = ""
                break

        if banner.startswith("HTTP/"):
            service = "http"
            m = re.search(r"server:\s*([^\r\n]+)", banner, re.IGNORECASE)
            if m:
                version = m.group(1).strip()

        return service, version

    async def _probe_port(self, ip: str, port: int, sem: asyncio.Semaphore) -> Optional[int]:
        async with sem:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port
            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                return None

    async def _async_scan(self, ip: str, ports: List[int]) -> List[int]:
        sem = asyncio.Semaphore(self.concurrency)
        tasks = [self._probe_port(ip, port, sem) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        open_ports = [p for p in results if isinstance(p, int)]
        return sorted(open_ports)

    def scan(self, ip: str, ports: List[int]) -> Tuple[List[PortResult], List[str]]:
        Logger.info(f"Varredura assíncrona de {len(ports)} portas em {ip} (concorrência: {self.concurrency})...")

        try:
            open_port_numbers = asyncio.run(self._async_scan(ip, ports))
        except Exception as e:
            Logger.warn(f"Fallback para verificação direta por socket: {e}")
            open_port_numbers = []
            for p in ports:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    if s.connect_ex((ip, p)) == 0:
                        open_port_numbers.append(p)

        port_results: List[PortResult] = []
        all_sans_discovered: List[str] = []

        for port in open_port_numbers:
            banner, tls_info, sans = self._grab_banner(ip, port)
            for san in sans:
                if san not in all_sans_discovered:
                    all_sans_discovered.append(san)

            service, version = self.guess_service(port, banner)
            pr = PortResult(
                port=port,
                state="open",
                service=service,
                banner=banner,
                version_hint=version,
                tls_details=tls_info
            )
            port_results.append(pr)

            printable_banner = "".join(ch if ch.isprintable() or ch.isspace() else " " for ch in banner)
            clean_banner = " ".join(printable_banner.split())[:80]
            Logger.found(
                f"{ip}:{port} OPEN  {service}"
                + (f" {version}" if version else "")
                + (f"  | {clean_banner}" if clean_banner else "")
            )

        Logger.ok(f"{ip}: {len(port_results)} porta(s) aberta(s)")
        return port_results, all_sans_discovered
