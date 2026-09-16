

from typing import List, Dict, Any

class InferenceEngine:
    RULES = [
        # Network & Lateral Movement
        (lambda f: f.get("445") and f.get("139"),
         9, "Windows SMB completo: enumerar compartilhamentos (null session), testar SMBv1 e considerar relay NTLM."),
        (lambda f: f.get("3389") and (f.get("445") or f.get("135")),
         8, "Perfil Windows Server exposto: verificar patch do BlueKeep (CVE-2019-0708) e proteção contra password spraying em RDP."),
        (lambda f: f.get("6379"),
         9, "Redis exposto: testar autenticação vazia -> se desprotegido, usar CONFIG SET para gravar webshell ou crontab."),
        (lambda f: f.get("2375") or f.get("2376"),
         10, "Docker Daemon API exposta: execução remota arbitrária e container escape imediatos — tratar como CRÍTICO."),
        (lambda f: f.get("27017") or f.get("9200"),
         8, "Banco NoSQL (MongoDB/Elasticsearch) na internet: testar queries diretas sem autenticação para despejo de dados."),
        (lambda f: f.get("53") and not f.get("80") and not f.get("443"),
         6, "Servidor DNS isolado: testar transferência de zona (AXFR) e verificar se atua como recursor aberto (DDoS reflector)."),
        (lambda f: (f.get("80") or f.get("443")) and (f.get("3306") or f.get("5432")),
         7, "Stack Web e Banco de Dados no mesmo host: qualquer injeção SQL no aplicativo web expõe diretamente o banco."),
        (lambda f: f.get("21") and f.get("banner:pure-ftpd"),
         5, "Pure-FTPd detectado: testar acesso Anonymous e TLS enforcement."),
        (lambda f: f.get("has_cve_critical"),
         10, "Vulnerabilidade CRÍTICA (CVSS >= 9.0) identificada em serviço exposto: priorizar correção e patch imediato."),

        # Email Security (SPF & DMARC)
        (lambda f: f.get("spf_missing"),
         8, "Domínio sem registro SPF: qualquer invasor pode enviar e-mails forjando o domínio (Spoofing/Phishing facilitado)."),
        (lambda f: f.get("spf_permissive"),
         6, "Registro SPF permissivo (+all ou ?all): neutraliza a proteção e autoriza envio por servidores não verificados."),
        (lambda f: f.get("dmarc_missing"),
         7, "Ausência de registro DMARC: provedores de e-mail de terceiros não têm diretrizes para rejeitar mensagens forjadas."),
        (lambda f: f.get("dmarc_none"),
         5, "Política DMARC configurada como 'p=none' (apenas monitoramento): mensagens forjadas ainda são entregues na caixa de entrada."),

        # TLS / Certificados
        (lambda f: f.get("tls_expired"),
         8, "Certificado TLS expirado em serviço ativo: gera alertas nos navegadores e quebra a cadeia de confiança."),
        (lambda f: f.get("tls_self_signed"),
         6, "Certificado TLS autoassinado em produção: suscetível a ataques Man-in-the-Middle (MITM)."),

        # Surface
        (lambda f: f.get("port_count", 0) >= 8,
         5, "Superfície de ataque ampla (>8 portas abertas): priorizar o fechamento de portas de gerenciamento no firewall."),
    ]

    @classmethod
    def infer(cls, port_map: list, features_banners: list, context: dict = None) -> List[Dict[str, Any]]:
        facts: Dict[str, Any] = {}
        for p in port_map:
            port = p["port"] if isinstance(p, dict) else getattr(p, "port", p["port"])
            facts[str(port)] = True
            cves = p.get("cve_matches", []) if isinstance(p, dict) else getattr(p, "cve_matches", [])
            for c in cves:
                if c.get("severity") == "CRITICAL" or c.get("cvss", 0) >= 9.0:
                    facts["has_cve_critical"] = True

        facts["port_count"] = len(port_map)

        for b in features_banners:
            facts[f"banner:{b.lower()}"] = True

        if context:
            for k, v in context.items():
                facts[k] = v

        recs = []
        for cond, prio, rec in cls.RULES:
            try:
                if cond(facts):
                    recs.append({"prioridade": prio, "acao": rec})
            except Exception:
                continue

        return sorted(recs, key=lambda r: -r["prioridade"])
