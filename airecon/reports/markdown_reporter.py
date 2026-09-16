"""
Markdown Report Exporter for AIRecon.
Generates GitHub-Flavored Markdown tables and audit summaries.
"""

from dataclasses import asdict
from typing import Any, Dict
from airecon.core.logger import Logger

def generate_markdown_report(report: Any) -> str:
    data = asdict(report) if hasattr(report, "__dataclass_fields__") else report

    target = data.get("target", "N/A")
    started = data.get("started", "")
    finished = data.get("finished", "")
    summary = data.get("summary", {})
    hosts = data.get("hosts", [])
    dns = data.get("dns", {})
    web = data.get("web", [])

    lines = [
        f"# 🛡️ AIRecon — Relatório de Reconhecimento de Segurança",
        f"",
        f"- **Alvo:** `{target}`",
        f"- **Início:** `{started}`",
        f"- **Término:** `{finished}`",
        f"",
        f"---",
        f"",
        f"## 📊 1. Resumo Executivo",
        f"",
        f"| Métrica | Valor |",
        f"|---|---|",
        f"| **Hosts Ativos** | {summary.get('hosts_alive', len(hosts))} |",
        f"| **Portas Abertas Identificadas** | {summary.get('total_open_ports', 0)} |",
        f"| **Pontuação Máxima de Risco (IA)** | **{summary.get('ai_overall_risk', 0.0)}/10** |",
        f"| **Subdomínios Descobertos** | {summary.get('subdomains_found', 0)} |",
        f"",
    ]

    # Email Security Section
    if dns and dns.get("email_security"):
        es = dns["email_security"]
        spf = es.get("spf", {})
        dmarc = es.get("dmarc", {})
        lines.extend([
            f"## ✉️ 2. Auditoria de Segurança de E-mail (Anti-Spoofing)",
            f"",
            f"| Mecanismo | Status | Diretiva / Registro |",
            f"|---|---|---|",
            f"| **SPF** | `{spf.get('status', 'N/A')}` | `{spf.get('raw', 'Não configurado')}` |",
            f"| **DMARC** | `{dmarc.get('status', 'N/A')}` | `{dmarc.get('raw', 'Não configurado')}` |",
            f"",
        ])

    # Hosts and Ports Section
    lines.extend([
        f"## 🔌 3. Serviços e Portas Abertas por Host",
        f"",
    ])

    for h in hosts:
        ip = h.get("ip", "")
        hn = f" ({h.get('hostname')})" if h.get("hostname") else ""
        lines.append(f"### Host: `{ip}`{hn}")
        lines.append("")

        open_ports = h.get("open_ports", [])
        if not open_ports:
            lines.append("_Nenhuma porta aberta detectada._\n")
            continue

        lines.append("| Porta | Serviço | Versão / Banner | Risco (IA) | CVEs Mapeados | Detalhes TLS |")
        lines.append("|---|---|---|---|---|---|")

        for p in open_ports:
            port = p.get("port")
            svc = p.get("service", "unknown")
            version = p.get("version_hint", "")
            banner = p.get("banner", "").replace("\n", " ").replace("\r", "")[:60]
            desc = f"{version} ({banner})" if version and banner else (version or banner or "-")

            ai_risk = p.get("ai_risk", {})
            score = f"{ai_risk.get('score', '-')}/10 ({ai_risk.get('severidade', '-')})" if ai_risk else "-"

            cves = p.get("cve_matches", [])
            cve_str = ", ".join(f"`{c.get('cve')}`" for c in cves) if cves else "-"

            tls = p.get("tls_details")
            tls_str = "-"
            if tls:
                cn = tls.get("common_name", "")
                days = tls.get("days_left")
                expired = " ⚠️ EXPIRADO" if tls.get("expired") else (f" ({days}d restantes)" if days is not None else "")
                tls_str = f"CN: {cn}{expired}"

            lines.append(f"| **{port}** | `{svc}` | {desc} | **{score}** | {cve_str} | {tls_str} |")

        lines.append("")

        # AI Recommendations for this host
        ai_analysis = h.get("ai_analysis")
        if ai_analysis and ai_analysis.get("recomendacoes"):
            lines.append(f"#### 🤖 Recomendações Priorizadas da IA:")
            for rec in ai_analysis["recomendacoes"]:
                prio = rec.get("prioridade", 5)
                acao = rec.get("acao", "")
                lines.append(f"- **[P{prio}]** {acao}")
            lines.append("")

    # DNS & Subdomains
    if dns:
        subdomains = dns.get("subdomains", [])
        sans = dns.get("sans_discovered", [])
        if subdomains or sans:
            lines.extend([
                f"## 🌐 4. Enumeração de Subdomínios e Nomes TLS (SANs)",
                f"",
            ])
            if subdomains:
                lines.append("| Subdomínio | IPs Associados | Origem |")
                lines.append("|---|---|---|")
                for s in subdomains:
                    ips = ", ".join(s.get("ips", []))
                    lines.append(f"| `{s.get('subdomain')}` | {ips} | {s.get('source', 'DNS')} |")
                lines.append("")

            if sans:
                lines.append(f"**Nomes Alternativos em Certificados TLS (SANs Descobertos):**")
                for san in sans:
                    lines.append(f"- `{san}`")
                lines.append("")

    # Web Recon
    if web:
        lines.extend([
            f"## 🕸️ 5. Reconhecimento de Aplicações Web",
            f"",
        ])
        for wr in web:
            url = wr.get("url", "")
            title = wr.get("title", "Sem título")
            techs = ", ".join(f"`{t}`" for t in wr.get("technologies", [])) or "Nenhuma identificada"
            paths = wr.get("interesting_paths", [])

            lines.append(f"### URL: [{url}]({url})")
            lines.append(f"- **Título da Página:** {title}")
            lines.append(f"- **Tecnologias / Headers:** {techs}")
            if paths:
                lines.append(f"- **Paths Sensíveis Respondendo:**")
                for path in paths:
                    lines.append(f"  - `{path.get('path')}` (HTTP {path.get('status')})")
            lines.append("")

    return "\n".join(lines)

def save_markdown_report(report_obj: Any, output_path: str):
    content = generate_markdown_report(report_obj)
    try:
        with open(output_path, "w", encoding="utf-8") as fp:
            fp.write(content)
        Logger.ok(f"Relatório Markdown salvo em: {output_path}")
    except OSError as e:
        Logger.err(f"Falha ao salvar relatório Markdown: {e}")
