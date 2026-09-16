

import re
from typing import List, Dict, Any

class CVEDatabase:
    # High-impact offline signatures for common network services
    SIGNATURES = [
        # OpenSSH
        {
            "pattern": r"openssh[_-]9\.[2-7]p1",
            "product": "OpenSSH 9.2p1-9.7p1",
            "cve": "CVE-2024-6387",
            "cvss": 8.1,
            "severity": "HIGH",
            "description": "regreSSHion: vulnerabilidade de Signal Handler Race Condition em servidores baseados em glibc levando a execução remota de código (RCE).",
        },
        {
            "pattern": r"openssh[_-]8\.[0-9]p1|openssh[_-]9\.[0-5]p1",
            "product": "OpenSSH <9.6",
            "cve": "CVE-2023-48795",
            "cvss": 5.9,
            "severity": "MEDIUM",
            "description": "Terrapin Attack: manipulação de números de sequência no protocolo SSH durante o handshake.",
        },
        {
            "pattern": r"openssh[_-]7\.[0-7]",
            "product": "OpenSSH 7.0-7.7",
            "cve": "CVE-2018-15473",
            "cvss": 5.3,
            "severity": "MEDIUM",
            "description": "User enumeration via timing discrepancy e pacotes de autenticação malformados.",
        },
        {
            "pattern": r"openssh[_-][1-6]\.",
            "product": "OpenSSH <7.0 (Legacy EOL)",
            "cve": "CVE-2016-0777",
            "cvss": 7.5,
            "severity": "HIGH",
            "description": "Versão obsoleta de OpenSSH suscetível a vazamento de chaves privadas (roaming bug).",
        },

        # Apache HTTP Server
        {
            "pattern": r"apache[/ ]2\.4\.(49|50)\b",
            "product": "Apache HTTP Server 2.4.49/2.4.50",
            "cve": "CVE-2021-41773",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "Path Traversal e execução remota de código (RCE) via codificação de caracteres na URL.",
        },
        {
            "pattern": r"apache[/ ]2\.[0-2]\.",
            "product": "Apache HTTP Server <=2.2 (EOL)",
            "cve": "CVE-2017-9798",
            "cvss": 7.5,
            "severity": "HIGH",
            "description": "OptionsBleed e múltiplos CVEs críticos em versão de fim de vida (EOL).",
        },

        # Nginx
        {
            "pattern": r"nginx[/ ]1\.(1[0-9]|2[0-5])\.",
            "product": "Nginx HTTP/2",
            "cve": "CVE-2023-44487",
            "cvss": 7.5,
            "severity": "HIGH",
            "description": "HTTP/2 Rapid Reset DDoS attack.",
        },
        {
            "pattern": r"nginx[/ ]0\.|nginx[/ ]1\.[0-9]\.",
            "product": "Nginx <1.10 (Legacy)",
            "cve": "CVE-2013-2028",
            "cvss": 7.5,
            "severity": "HIGH",
            "description": "Estouro de buffer em transferências Chunked levando a bypass de segurança.",
        },

        # Microsoft IIS & Windows Services
        {
            "pattern": r"microsoft-iis[/ ]6\.0",
            "product": "Microsoft IIS 6.0",
            "cve": "CVE-2017-7269",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "WebDAV ScStoragePathFromUrl Buffer Overflow RCE em Windows Server 2003.",
        },
        {
            "pattern": r"microsoft-iis[/ ]7\.5",
            "product": "Microsoft IIS 7.5",
            "cve": "CVE-2015-1635",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "MS15-034 HTTP.sys Remote Code Execution no cabeçalho Range.",
        },

        # FTP Servers
        {
            "pattern": r"vsftpd\s*2\.3\.4",
            "product": "vsftpd 2.3.4",
            "cve": "CVE-2011-2523",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "Backdoor embutido no código-fonte oficial (smiley face backdoor na porta 6200).",
        },
        {
            "pattern": r"proftpd\s*1\.3\.5\b",
            "product": "ProFTPD 1.3.5",
            "cve": "CVE-2015-3306",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "mod_copy permite cópia não autorizada de arquivos arbitrários no sistema operacional.",
        },

        # Databases
        {
            "pattern": r"mysql\s*(4\.|5\.[0-5]\.)",
            "product": "MySQL <=5.5",
            "cve": "CVE-2016-6662",
            "cvss": 8.8,
            "severity": "HIGH",
            "description": "Privilege Escalation e injeção de configuração através de my.cnf.",
        },
        {
            "pattern": r"redis",
            "product": "Redis Database Server",
            "cve": "CONFIG-SET-RCE",
            "cvss": 9.0,
            "severity": "CRITICAL",
            "description": "Se sem autenticação, comandos CONFIG SET permitem escrita de chaves SSH ou crontab para RCE.",
        },

        # Mail Servers
        {
            "pattern": r"exim\s*(4\.[89][0-9]?)",
            "product": "Exim Mail Server 4.87-4.91",
            "cve": "CVE-2019-10149",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "The Return of the WIZard: RCE imediato no tratamento de destinatários de e-mail.",
        }
    ]

    @classmethod
    def match(cls, banner: str, service: str = "") -> List[Dict[str, Any]]:
        if not banner:
            return []
        matches = []
        b = banner.lower()
        for sig in cls.SIGNATURES:
            if re.search(sig["pattern"], b, re.IGNORECASE):
                matches.append({
                    "product": sig["product"],
                    "cve": sig["cve"],
                    "cvss": sig["cvss"],
                    "severity": sig["severity"],
                    "description": sig["description"]
                })
        return matches
