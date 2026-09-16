

import argparse
import os
import platform
import subprocess
import sys
import time
from datetime import datetime
from dataclasses import asdict
from typing import Optional, List, Dict, Any

from airecon.core.config import COMMON_PORTS, TOP_100_PORTS, parse_ports, resolve_target
from airecon.core.models import PortResult, HostResult, DNSResult, WebResult, ReconReport
from airecon.core.logger import Logger
from airecon.modules.discovery import HostDiscovery
from airecon.modules.scanner import AsyncPortScanner
from airecon.modules.dns_recon import DNSEnum
from airecon.modules.web_recon import WebRecon
from airecon.ai.engine import AIEngine
from airecon.reports.json_reporter import save_json_report
from airecon.reports.markdown_reporter import save_markdown_report
from airecon.reports.html_reporter import save_html_report


def local_system_info() -> Dict[str, Any]:
    info = {
        "hostname": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "interfaces": [],
    }
    try:
        if platform.system() == "Linux":
            info["interfaces"] = subprocess.run(
                ["ip", "-brief", "addr"], capture_output=True, text=True, timeout=5
            ).stdout.strip().splitlines()
        elif platform.system() == "Windows":
            info["interfaces"] = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=5
            ).stdout.strip().splitlines()
        elif platform.system() == "Darwin":
            info["interfaces"] = subprocess.run(
                ["ifconfig"], capture_output=True, text=True, timeout=5
            ).stdout.strip().splitlines()
    except Exception as e:
        info["interfaces"] = [f"erro: {e}"]
    return info


class AIRecon:
    def __init__(self, args):
        self.args = args
        self.ai = None if args.no_ai else AIEngine()
        self.report = ReconReport(target=args.target, started=datetime.now().isoformat())

    def run(self):
        Logger.info(f"=== AIRecon v2.0 iniciado | alvo: {self.args.target} ===")

        # Mode: Train AI (--learn)
        if self.args.learn:
            self._train_mode()
            return

        ips = resolve_target(self.args.target)
        if not ips:
            Logger.err("Nenhum IP válido encontrado. Encerrando.")
            return
        Logger.info(f"Alvos resolvidos: {len(ips)} IP(s)")

        # 1. Host Discovery
        if len(ips) > 1 or self.args.discover:
            hosts = HostDiscovery.sweep(ips, use_icmp=self.args.icmp, threads=self.args.threads)
        else:
            hosts = [HostResult(ip=ips[0], alive=True)]
            Logger.info(f"Alvo único assumido ativo: {ips[0]}")

        # 2. Port Selection
        if self.args.ports:
            ports = parse_ports(self.args.ports)
        elif self.args.top:
            ports = TOP_100_PORTS
        else:
            ports = sorted(COMMON_PORTS.keys())
        if self.args.full:
            ports = list(range(1, 1025))
            Logger.info("Modo FULL: portas 1-1024 ativadas")

        # 3. Port Scanning + Advanced TLS Analysis
        scanner = AsyncPortScanner(timeout=self.args.timeout, threads=self.args.threads)
        discovered_sans: List[str] = []
        for host in hosts:
            if not host.alive:
                continue
            open_results, sans = scanner.scan(host.ip, ports)
            host.open_ports = open_results
            for san in sans:
                if san not in discovered_sans:
                    discovered_sans.append(san)

        # 4. DNS Enumeration & Email Security Audit
        dns_context_facts: Dict[str, Any] = {}
        if self.args.dns or self.args.subdomains or self.args.reverse or self.args.full:
            dnse = DNSEnum(resolver=self.args.resolver, timeout=self.args.timeout)
            domain = self.args.target if "/" not in self.args.target else self.args.target.split("/")[0]
            try:
                import ipaddress
                ipaddress.ip_address(domain)
                domain = None
            except ValueError:
                pass

            if domain and (self.args.dns or self.args.subdomains or self.args.full):
                dr = DNSResult(domain=domain)
                recs, email_sec = dnse.enumerate_records(domain)
                dr.records = recs
                dr.email_security = email_sec
                dr.sans_discovered = discovered_sans

                # Populate AI context facts based on email security
                spf_info = email_sec.get("spf", {})
                dmarc_info = email_sec.get("dmarc", {})
                if not spf_info.get("found"):
                    dns_context_facts["spf_missing"] = True
                elif spf_info.get("qualifier") in ("+all", "?all"):
                    dns_context_facts["spf_permissive"] = True

                if not dmarc_info.get("found"):
                    dns_context_facts["dmarc_missing"] = True
                elif dmarc_info.get("policy") == "none":
                    dns_context_facts["dmarc_none"] = True

                if self.args.subdomains or self.args.full:
                    dr.subdomains = dnse.subdomain_bruteforce(domain)
                    # Add SANs to subdomains list if not already present
                    existing_subnames = {s["subdomain"].lower() for s in dr.subdomains}
                    for san in discovered_sans:
                        if san.lower() not in existing_subnames and san.lower().endswith(domain.lower()):
                            dr.subdomains.append({"subdomain": san, "ips": [], "source": "TLS SAN"})

                self.report.dns = asdict(dr)

            if self.args.reverse or self.args.full:
                rdns = dnse.reverse_lookup(f"{ips[0]}/24")
                if self.report.dns is None:
                    self.report.dns = {}
                self.report.dns["reverse"] = rdns

        # 5. AI Analysis across Hosts
        for host in hosts:
            if not host.alive:
                continue

            # Add TLS facts to context
            host_context = dict(dns_context_facts)
            for p in (host.open_ports or []):
                tls = p.get("tls_details") if isinstance(p, dict) else getattr(p, "tls_details", None)
                if tls:
                    if tls.get("expired"):
                        host_context["tls_expired"] = True
                    if tls.get("self_signed"):
                        host_context["tls_self_signed"] = True

            if self.ai and host.open_ports:
                host.ai_analysis = self.ai.analyze_host(host.ip, host.open_ports, context=host_context)
            self.report.hosts.append(asdict(host))

        # 6. Web Reconnaissance
        if self.args.web or self.args.full:
            webr = WebRecon(timeout=self.args.timeout)
            web_results = []
            for host in hosts:
                if not host.alive:
                    continue
                open_list = [p["port"] if isinstance(p, dict) else p.port for p in (host.open_ports or [])]
                for scheme, port_list in (("https", [443, 8443]), ("http", [80, 8080, 8000])):
                    for port in port_list:
                        if open_list and port not in open_list:
                            continue
                        url = f"{scheme}://{host.ip}" + (f":{port}" if port not in (80, 443) else "")
                        r = webr.probe(url)
                        if r:
                            web_results.append(asdict(r))

            if "/" not in self.args.target and any(c.isalpha() for c in self.args.target):
                for scheme in ("https", "http"):
                    r = webr.probe(f"{scheme}://{self.args.target}")
                    if r:
                        web_results.append(asdict(r))

            if web_results:
                self.report.web = web_results

        # 7. Local System Info
        if self.args.local:
            Logger.info("Coletando informações do sistema local...")
            self.report.summary["local_system"] = local_system_info()

        self.report.finished = datetime.now().isoformat()
        self._build_summary()
        self._save_reports()

    def _train_mode(self):
        alvo, classe = self.args.learn
        Logger.info(f"Modo treinamento da IA: {alvo} -> '{classe}'")
        ips = resolve_target(alvo)
        if not ips:
            Logger.err("Alvo inválido para treinamento.")
            return
        scanner = AsyncPortScanner(timeout=self.args.timeout, threads=self.args.threads)
        open_ports, _ = scanner.scan(ips[0], sorted(COMMON_PORTS.keys()) + TOP_100_PORTS)
        if not open_ports:
            Logger.err("Nenhuma porta aberta identificada — nada a aprender.")
            return
        self.ai.feedback(alvo, classe, open_ports)

    def _build_summary(self):
        open_total = sum(len(h.get("open_ports", [])) for h in self.report.hosts)
        services: Dict[str, List[str]] = {}
        for h in self.report.hosts:
            for p in h.get("open_ports", []):
                svc = p.get("service", "unknown")
                port = p.get("port")
                services.setdefault(svc, []).append(f"{h.get('ip')}:{port}")

        subdomains_count = len(self.report.dns.get("subdomains", [])) if self.report.dns else 0
        overall_risk = 0.0
        if self.ai:
            risks = [
                f.get("score", 0.0)
                for h in self.report.hosts
                for f in (h.get("ai_analysis") or {}).get("findings", [])
            ]
            overall_risk = max(risks) if risks else 0.0

        self.report.summary.update({
            "hosts_alive": len([h for h in self.report.hosts if h.get("alive", True)]),
            "total_open_ports": open_total,
            "services": services,
            "subdomains_found": subdomains_count,
            "ai_overall_risk": overall_risk,
        })

        Logger.ok("--- RESUMO GERAL ---")
        Logger.ok(f"Hosts ativos: {self.report.summary['hosts_alive']}")
        Logger.ok(f"Portas abertas identificadas: {open_total}")
        if self.ai:
            Logger.ok(f"Risco geral máximo (IA): {overall_risk}/10")
        if self.report.dns and self.report.dns.get("email_security"):
            es = self.report.dns["email_security"]
            Logger.ok(f"Segurança SPF: {es.get('spf', {}).get('status')}")
            Logger.ok(f"Segurança DMARC: {es.get('dmarc', {}).get('status')}")
        for svc, endpoints in services.items():
            Logger.ok(f"  {svc}: {', '.join(endpoints[:5])}" + (" ..." if len(endpoints) > 5 else ""))

    def _save_reports(self):
        fmt = (self.args.format or "all").lower()
        base_name = self.args.output or f"airecon_{self.args.target.replace('/', '_')}_{int(time.time())}"
        if base_name.endswith(".json") or base_name.endswith(".html") or base_name.endswith(".md"):
            base_name = os.path.splitext(base_name)[0]

        # JSON
        if fmt in ("all", "json"):
            save_json_report(self.report, f"{base_name}.json")

        # HTML Dashboard
        if fmt in ("all", "html"):
            save_html_report(self.report, f"{base_name}.html")

        # Markdown
        if fmt in ("all", "md", "markdown"):
            save_markdown_report(self.report, f"{base_name}.md")


def main():
    p = argparse.ArgumentParser(
        prog="airecon",
        description="AIRecon v2.0 — Reconhecimento e Auditoria de Segurança com IA Local Offline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s --target example.com --dns --web
  %(prog)s --target 192.168.1.0/24 --discover --top --format all
  %(prog)s --target exemplo.com -F --format html
  python %(prog)s --learn 10.0.0.5 windows_dc
"""
    )
    p.add_argument("--target", "-t", default="", help="IP, domínio ou CIDR (ex: 192.168.1.0/24 ou site.com)")
    p.add_argument("--ports", "-p", default="", help="Portas específicas: '80,443,8000-8080'")
    p.add_argument("--top", action="store_true", help="Escanear top ~100 portas mais comuns")
    p.add_argument("--discover", action="store_true", help="Forçar descoberta de hosts ativos")
    p.add_argument("--icmp", action="store_true", help="Usar ICMP ping sweep (requer privilégios; fallback automático para TCP)")
    p.add_argument("--dns", action="store_true", help="Enumerar registros DNS + Auditoria SPF e DMARC")
    p.add_argument("--subdomains", action="store_true", help="Bruteforce de subdomínios via wordlist")
    p.add_argument("--reverse", action="store_true", help="Reverse DNS no bloco /24 do alvo")
    p.add_argument("--web", action="store_true", help="Reconhecimento web (headers, tecnologias, paths sensíveis)")
    p.add_argument("--local", action="store_true", help="Coletar informações do sistema local")
    p.add_argument("--full", "-F", action="store_true", help="Modo completo: portas 1-1024 + DNS + Web + E-mail + Reverse")
    p.add_argument("--learn", nargs=2, metavar=("ALVO", "CLASSE"), help="Treinar modelo da IA: --learn 10.0.0.5 windows_dc")
    p.add_argument("--no-ai", action="store_true", help="Desativar motor de IA")
    p.add_argument("--threads", default=200, type=int, help="Concorrência máxima / threads (padrão: 200)")
    p.add_argument("--timeout", default=1.5, type=float, help="Timeout de conexão em segundos (padrão: 1.5)")
    p.add_argument("--resolver", default="8.8.8.8", help="Servidor DNS para consultas UDP (padrão: 8.8.8.8)")
    p.add_argument("--format", choices=["all", "json", "html", "md"], default="all", help="Formato do relatório de saída (padrão: all)")
    p.add_argument("--output", "-o", default="", help="Nome ou caminho base do arquivo de saída")
    p.add_argument("--quiet", "-q", action="store_true", help="Modo silencioso: exibir apenas achados e erros")

    args = p.parse_args()

    if not args.target and not args.learn:
        p.error("--target é obrigatório (exceto com --learn)")

    Logger.QUIET = args.quiet

    try:
        AIRecon(args).run()
    except KeyboardInterrupt:
        Logger.warn("Execução interrompida pelo usuário.")
        sys.exit(130)


if __name__ == "__main__":
    main()
