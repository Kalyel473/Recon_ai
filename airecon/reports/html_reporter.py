"""
Standalone Modern HTML Dashboard Exporter for AIRecon.
100% self-contained: zero external CDNs, scripts or font downloads required.
"""

from dataclasses import asdict
from typing import Any
import html
from airecon.core.logger import Logger

def generate_html_report(report: Any) -> str:
    data = asdict(report) if hasattr(report, "__dataclass_fields__") else report

    target = html.escape(str(data.get("target", "N/A")))
    started = html.escape(str(data.get("started", "")))
    finished = html.escape(str(data.get("finished", "")))
    summary = data.get("summary", {})
    hosts = data.get("hosts", [])
    dns = data.get("dns", {})
    web = data.get("web", [])

    total_hosts = summary.get("hosts_alive", len(hosts))
    total_ports = summary.get("total_open_ports", 0)
    risk_score = float(summary.get("ai_overall_risk", 0.0))
    subdomains_count = summary.get("subdomains_found", 0)

    # Risk badge color
    if risk_score >= 8.5:
        risk_class = "risk-critical"
        risk_label = "CRÍTICO"
    elif risk_score >= 6.5:
        risk_class = "risk-high"
        risk_label = "ALTO"
    elif risk_score >= 4.0:
        risk_class = "risk-medium"
        risk_label = "MÉDIO"
    else:
        risk_class = "risk-low"
        risk_label = "BAIXO"

    # Email security summary
    email_sec_summary = "N/A"
    if dns and dns.get("email_security"):
        es = dns["email_security"]
        spf_status = es.get("spf", {}).get("status", "")
        dmarc_status = es.get("dmarc", {}).get("status", "")
        if "CRÍTICO" in spf_status or "VULNERÁVEL" in spf_status or "VULNERÁVEL" in dmarc_status:
            email_sec_summary = "Vulnerável a Spoofing"
            email_class = "badge-danger"
        elif "SEGURO" in spf_status and "SEGURO" in dmarc_status:
            email_sec_summary = "Protegido (SPF + DMARC)"
            email_class = "badge-success"
        else:
            email_sec_summary = "Proteção Parcial"
            email_class = "badge-warning"
    else:
        email_class = "badge-neutral"

    # Build HTML
    html_content = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AIRecon Report — {target}</title>
<style>
  :root {{
    --bg-main: #0f172a;
    --bg-card: #1e293b;
    --bg-card-hover: #273549;
    --border: #334155;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
    --primary: #38bdf8;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #22c55e;
    --badge-bg: #1e293b;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
  body {{ background: var(--bg-main); color: var(--text-main); padding: 2rem 1rem; line-height: 1.5; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  
  header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem; }}
  h1 {{ font-size: 1.8rem; font-weight: 700; color: var(--text-main); display: flex; align-items: center; gap: 0.5rem; }}
  .target-badge {{ background: #0284c7; color: white; padding: 0.2rem 0.8rem; border-radius: 9999px; font-size: 0.9rem; font-family: monospace; }}
  .meta-info {{ font-size: 0.85rem; color: var(--text-muted); text-align: right; }}

  /* Metric cards */
  .grid-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2.5rem; }}
  .card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 0.75rem; padding: 1.25rem; }}
  .card-title {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 0.5rem; }}
  .card-val {{ font-size: 1.8rem; font-weight: 700; }}
  
  .risk-critical {{ color: var(--critical); }}
  .risk-high {{ color: var(--high); }}
  .risk-medium {{ color: var(--medium); }}
  .risk-low {{ color: var(--low); }}

  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 0.375rem; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
  .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
  .badge-warning {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
  .badge-success {{ background: rgba(34, 197, 94, 0.2); color: var(--low); border: 1px solid var(--low); }}
  .badge-neutral {{ background: rgba(148, 163, 184, 0.2); color: var(--text-muted); border: 1px solid var(--text-muted); }}

  /* Section styles */
  .section {{ margin-bottom: 2.5rem; }}
  .section-header {{ font-size: 1.3rem; font-weight: 600; margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; border-left: 4px solid var(--primary); padding-left: 0.75rem; }}
  
  /* Tables */
  .table-responsive {{ overflow-x: auto; background: var(--bg-card); border: 1px solid var(--border); border-radius: 0.75rem; }}
  table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }}
  th {{ background: #162032; padding: 0.85rem 1rem; font-weight: 600; color: var(--text-muted); border-bottom: 1px solid var(--border); }}
  td {{ padding: 0.85rem 1rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: var(--bg-card-hover); }}

  .code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.85rem; color: #38bdf8; }}
  .cve-tag {{ background: rgba(239, 68, 68, 0.2); color: #fca5a5; padding: 0.1rem 0.4rem; border-radius: 0.25rem; font-family: monospace; font-size: 0.8rem; margin-right: 0.25rem; display: inline-block; margin-bottom: 0.2rem; }}
  .san-tag {{ background: rgba(56, 189, 248, 0.15); color: #7dd3fc; padding: 0.15rem 0.5rem; border-radius: 0.25rem; font-family: monospace; font-size: 0.8rem; margin: 0.2rem; display: inline-block; }}
  
  /* Rec list */
  .rec-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 0.5rem; padding: 0.85rem 1.25rem; margin-bottom: 0.6rem; display: flex; align-items: flex-start; gap: 1rem; }}
  .rec-prio {{ font-weight: 800; font-size: 0.8rem; padding: 0.2rem 0.5rem; border-radius: 0.25rem; background: #dc2626; color: white; white-space: nowrap; }}
  .rec-prio.p-high {{ background: #ea580c; }}
  .rec-prio.p-med {{ background: #ca8a04; }}
  .rec-prio.p-low {{ background: #16a34a; }}
  .rec-text {{ font-size: 0.95rem; color: var(--text-main); }}

  footer {{ text-align: center; color: var(--text-muted); font-size: 0.8rem; margin-top: 3rem; border-top: 1px solid var(--border); padding-top: 1.5rem; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>🛡️ AIRecon <span>Dashboard</span></h1>
      <span class="target-badge">ALVO: {target}</span>
    </div>
    <div class="meta-info">
      <div><strong>Início:</strong> {started}</div>
      <div><strong>Término:</strong> {finished}</div>
    </div>
  </header>

  <!-- Metric Overview -->
  <div class="grid-stats">
    <div class="card">
      <div class="card-title">Hosts Ativos</div>
      <div class="card-val">{total_hosts}</div>
    </div>
    <div class="card">
      <div class="card-title">Portas Abertas</div>
      <div class="card-val">{total_ports}</div>
    </div>
    <div class="card">
      <div class="card-title">Risco Máximo IA</div>
      <div class="card-val {risk_class}">{risk_score}<span style="font-size: 1rem; color: var(--text-muted)">/10</span></div>
      <span class="badge badge-danger" style="margin-top: 0.3rem;">{risk_label}</span>
    </div>
    <div class="card">
      <div class="card-title">Segurança de E-mail</div>
      <div class="card-val" style="font-size: 1.1rem; margin-top: 0.4rem;">
        <span class="badge {email_class}">{email_sec_summary}</span>
      </div>
    </div>
  </div>
"""

    # Email Security Audit Section
    if dns and dns.get("email_security"):
        es = dns["email_security"]
        spf = es.get("spf", {})
        dmarc = es.get("dmarc", {})
        html_content += f"""
  <div class="section">
    <div class="section-header">✉️ Auditoria Anti-Spoofing de E-mail (SPF & DMARC)</div>
    <div class="table-responsive">
      <table>
        <thead>
          <tr>
            <th>Mecanismo</th>
            <th>Status de Segurança</th>
            <th>Conteúdo do Registro</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>SPF</strong></td>
            <td><code>{html.escape(spf.get('status', 'N/A'))}</code></td>
            <td class="code">{html.escape(spf.get('raw', 'Registro não encontrado'))}</td>
          </tr>
          <tr>
            <td><strong>DMARC</strong></td>
            <td><code>{html.escape(dmarc.get('status', 'N/A'))}</code></td>
            <td class="code">{html.escape(dmarc.get('raw', 'Registro não encontrado'))}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
"""

    # Hosts and Ports Section
    html_content += """
  <div class="section">
    <div class="section-header">🔌 Serviços e Portas Identificadas</div>
"""
    for h in hosts:
        ip = html.escape(str(h.get("ip", "")))
        hn = html.escape(str(h.get("hostname", "")))
        hn_display = f" ({hn})" if hn else ""
        open_ports = h.get("open_ports", [])

        html_content += f"""
    <div style="margin-bottom: 1.5rem;">
      <h3 style="margin-bottom: 0.5rem; font-size: 1.1rem; color: var(--primary);">Host: {ip}{hn_display}</h3>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th style="width: 80px;">Porta</th>
              <th style="width: 120px;">Serviço</th>
              <th>Banner / Versão</th>
              <th style="width: 150px;">Risco IA</th>
              <th>Vulnerabilidades (CVE)</th>
              <th>Inspeção TLS</th>
            </tr>
          </thead>
          <tbody>
"""
        if not open_ports:
            html_content += """<tr><td colspan="6" style="text-align:center; color:var(--text-muted)">Nenhuma porta aberta detectada.</td></tr>"""
        else:
            for p in open_ports:
                port = p.get("port")
                svc = html.escape(str(p.get("service", "unknown")))
                version = html.escape(str(p.get("version_hint", "")))
                banner_raw = str(p.get("banner", ""))
                banner_clean = html.escape(" ".join(banner_raw.split())[:75])
                banner_desc = f"<strong>{version}</strong> — {banner_clean}" if version else banner_clean

                ai_risk = p.get("ai_risk", {})
                score = ai_risk.get("score", 0.0)
                sev = ai_risk.get("severidade", "LOW")
                if sev == "CRITICAL":
                    s_badge = "badge-danger"
                elif sev == "HIGH":
                    s_badge = "badge-warning"
                elif sev == "MEDIUM":
                    s_badge = "badge-warning"
                else:
                    s_badge = "badge-success"

                # CVE tags
                cves = p.get("cve_matches", [])
                cve_html = ""
                for c in cves:
                    cve_code = html.escape(c.get("cve", ""))
                    cve_html += f'<span class="cve-tag">{cve_code}</span>'
                if not cve_html:
                    cve_html = '<span style="color:var(--text-muted); font-size:0.8rem;">Nenhum conhecido</span>'

                # TLS details
                tls = p.get("tls_details")
                tls_html = "-"
                if tls:
                    cn = html.escape(str(tls.get("common_name", "")))
                    expired = tls.get("expired", False)
                    days = tls.get("days_left")
                    if expired:
                        tls_badge = '<span class="badge badge-danger">EXPIRADO</span>'
                    elif days is not None and days < 30:
                        tls_badge = f'<span class="badge badge-warning">{days}d restantes</span>'
                    else:
                        tls_badge = '<span class="badge badge-success">Válido</span>'
                    sans_count = len(tls.get("sans", []))
                    tls_html = f"<div><strong>CN:</strong> {cn} {tls_badge}</div>"
                    if sans_count:
                        tls_html += f"<div style='font-size:0.8rem; color:var(--text-muted); margin-top:0.2rem;'>SANs: {sans_count} nomes</div>"

                html_content += f"""
            <tr>
              <td><span class="code"><strong>{port}</strong></span></td>
              <td><code>{svc}</code></td>
              <td>{banner_desc}</td>
              <td><span class="badge {s_badge}">{score}/10 {sev}</span></td>
              <td>{cve_html}</td>
              <td>{tls_html}</td>
            </tr>
"""
        html_content += """
          </tbody>
        </table>
      </div>
    </div>
"""
        # Host AI Recommendations
        ai_analysis = h.get("ai_analysis")
        if ai_analysis and ai_analysis.get("recomendacoes"):
            html_content += """<div style="margin-bottom: 1.5rem;">
              <h4 style="margin-bottom: 0.5rem; font-size: 0.95rem; color: var(--text-muted);">🤖 Recomendações Priorizadas da IA:</h4>
            """
            for rec in ai_analysis["recomendacoes"]:
                prio = rec.get("prioridade", 5)
                acao = html.escape(str(rec.get("acao", "")))
                p_cls = "p-high" if prio >= 8 else ("p-med" if prio >= 6 else "p-low")
                html_content += f"""
              <div class="rec-card">
                <span class="rec-prio {p_cls}">P{prio}</span>
                <span class="rec-text">{acao}</span>
              </div>
"""
            html_content += "</div>"

    html_content += "</div>"

    # Subdomains & SANs Section
    if dns:
        subdomains = dns.get("subdomains", [])
        sans = dns.get("sans_discovered", [])
        if subdomains or sans:
            html_content += """
  <div class="section">
    <div class="section-header">🌐 Subdomínios & Descobertas via Certificados TLS (SANs)</div>
"""
            if sans:
                html_content += '<div style="margin-bottom: 1rem;"><strong style="font-size:0.9rem; color:var(--text-muted);">Nomes Alternativos extraídos de Certificados TLS (SANs):</strong><div style="margin-top:0.5rem;">'
                for san in sans:
                    html_content += f'<span class="san-tag">{html.escape(san)}</span>'
                html_content += '</div></div>'

            if subdomains:
                html_content += """
    <div class="table-responsive">
      <table>
        <thead>
          <tr>
            <th>Subdomínio</th>
            <th>IPs Resolvidos</th>
            <th>Origem</th>
          </tr>
        </thead>
        <tbody>
"""
                for s in subdomains:
                    sub_name = html.escape(str(s.get("subdomain", "")))
                    sub_ips = html.escape(", ".join(s.get("ips", [])))
                    sub_src = html.escape(str(s.get("source", "DNS")))
                    html_content += f"""
          <tr>
            <td class="code"><strong>{sub_name}</strong></td>
            <td>{sub_ips}</td>
            <td><span class="badge badge-neutral">{sub_src}</span></td>
          </tr>
"""
                html_content += """
        </tbody>
      </table>
    </div>
"""
            html_content += "</div>"

    # Web Recon Section
    if web:
        html_content += """
  <div class="section">
    <div class="section-header">🕸️ Reconhecimento de Aplicações Web</div>
"""
        for wr in web:
            u = html.escape(str(wr.get("url", "")))
            title = html.escape(str(wr.get("title", "")))
            techs = wr.get("technologies", [])
            paths = wr.get("interesting_paths", [])

            html_content += f"""
    <div class="card" style="margin-bottom: 1rem;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 0.5rem;">
        <strong><a href="{u}" target="_blank" style="color:var(--primary); text-decoration:none;">{u}</a></strong>
        <span style="color:var(--text-muted); font-size:0.85rem;">{title}</span>
      </div>
      <div style="margin-bottom: 0.5rem;">
"""
            for t in techs:
                t_str = html.escape(str(t))
                if "missing-sec-headers" in t_str:
                    html_content += f'<span class="badge badge-danger" style="margin: 0.1rem;">{t_str}</span>'
                else:
                    html_content += f'<span class="badge badge-neutral" style="margin: 0.1rem;">{t_str}</span>'
            html_content += "</div>"

            if paths:
                html_content += '<div style="margin-top:0.5rem; font-size:0.85rem;"><strong style="color:var(--text-muted)">Paths Detectados:</strong><ul style="margin-left:1.5rem; margin-top:0.3rem;">'
                for path_item in paths:
                    p_name = html.escape(str(path_item.get("path", "")))
                    p_st = path_item.get("status", "")
                    html_content += f'<li><code>{p_name}</code> (HTTP {p_st})</li>'
                html_content += '</ul></div>'

            html_content += "</div>"
        html_content += "</div>"

    html_content += """
  <footer>
    Relatório gerado automaticamente pelo <strong>AIRecon</strong> — Reconnaissance com IA Offline.
  </footer>
</div>
</body>
</html>
"""
    return html_content

def save_html_report(report_obj: Any, output_path: str):
    content = generate_html_report(report_obj)
    try:
        with open(output_path, "w", encoding="utf-8") as fp:
            fp.write(content)
        Logger.ok(f"Relatório HTML Dashboard salvo em: {output_path}")
    except OSError as e:
        Logger.err(f"Falha ao salvar relatório HTML: {e}")
