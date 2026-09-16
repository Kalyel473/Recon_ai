
import math
from typing import Dict, Any, List
from .cve_db import CVEDatabase

class FuzzyRiskEngine:
    RISK_DB = {
        21:    (6.0, "ftp — verificar anonymous login e versões vsftpd/proftpd vulneráveis"),
        22:    (5.0, "ssh — testar credenciais fracas, algoritmos legacy ou vulnerabilidades recentes (regreSSHion)"),
        23:    (9.0, "telnet — protocolo inseguro, credenciais em texto claro"),
        25:    (6.0, "smtp — open relay / enumeração de usuários (VRFY, EXPN)"),
        53:    (5.0, "dns — verificar zone transfer (AXFR), recursão aberta e cache snooping"),
        80:    (4.0, "http — fuzzing de diretórios, painéis administrativos expostos"),
        135:   (6.5, "msrpc — enumeração RPC, vetor lateral para redes Windows"),
        139:   (7.0, "netbios — enumeração de compartilhamentos/sessões nulas"),
        445:   (8.0, "smb — enumeração null session, NTLM relay, EternalBlue se legado"),
        1433:  (7.0, "mssql — credenciais default sa / xp_cmdshell"),
        3306:  (6.5, "mysql — credenciais padrão, acesso remoto root desprotegido"),
        3389:  (7.0, "rdp — BlueKeep se desatualizado, credencial spraying"),
        5432:  (6.5, "postgresql — superuser remoto sem auth / pg_read_file"),
        5900:  (8.0, "vnc — autenticação fraca, acesso desprotegido"),
        6379:  (8.5, "redis — acesso sem autenticação é crítico (webshell / crontab RCE)"),
        8080:  (5.0, "http-alt — painéis de gerenciamento (Tomcat, Jenkins) expostos"),
        8443:  (4.5, "https-alt — serviços web secundários ou interfaces administrativas"),
        9200:  (9.0, "elasticsearch — vazamento total de dados se exposto sem autenticação"),
        27017: (9.0, "mongodb — NoSQL sem autenticação = exposição de banco"),
        2375:  (9.5, "docker API exposta = execução imediata de containers privilegiados (RCE)"),
        5984:  (8.0, "couchdb — RCE e acesso não autenticado a documentos"),
        11211: (7.0, "memcached — amplificação DDoS e leitura de dados em memória"),
    }

    @classmethod
    def score_service(cls, port: int, banner: str = "", tls_details: dict = None) -> Dict[str, Any]:
        base_score, reason = cls.RISK_DB.get(port, (2.0, "serviço genérico — enumeração padrão"))
        score = base_score
        extras: List[str] = [reason]
        cve_matches: List[dict] = []

        # Match against offline CVE database
        if banner:
            matches = CVEDatabase.match(banner)
            for m in matches:
                cve_matches.append(m)
                score += (m["cvss"] * 0.4)
                extras.append(f"[{m['cve']}] {m['product']}: {m['description']}")

        # TLS inspections
        if tls_details:
            if tls_details.get("expired"):
                score += 3.0
                extras.append("Certificado TLS expirado! Conexão suscetível a alertas e MITM.")
            elif tls_details.get("days_left") is not None and tls_details["days_left"] < 15:
                score += 1.5
                extras.append(f"Certificado TLS expira em {tls_details['days_left']} dias.")
            if tls_details.get("self_signed"):
                score += 2.0
                extras.append("Certificado TLS autoassinado detectado.")

        # Exponential fuzzy normalization (0 to 10)
        final = 10 * (1 - math.exp(-score / 8.0))
        final_rounded = round(min(10.0, final), 1)

        return {
            "score": final_rounded,
            "severidade": cls._severity(final_rounded),
            "razoes": extras,
            "cve_matches": cve_matches
        }

    @staticmethod
    def _severity(score: float) -> str:
        if score >= 8.5:
            return "CRITICAL"
        if score >= 6.5:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
