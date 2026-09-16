"""
Default configurations, port definitions, wordlists and utility functions.
"""

import ipaddress
import socket
from typing import List

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1723: "pptp", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    27017: "mongodb", 9200: "elasticsearch", 2375: "docker",
}

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017, 9200, 2375,
    113, 465, 587, 992, 1443, 3000, 5000, 5439, 5984, 6443, 8000, 8008,
    8009, 8081, 8888, 9000, 9090, 9100, 10000, 11211, 15672, 55555,
    1433, 1434, 1521, 2049, 2181, 3690, 5060, 5222, 5439, 5672, 6385,
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/17.0",
]

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "portal", "vpn", "dev", "staging", "test",
    "api", "app", "blog", "shop", "store", "cdn", "static", "media", "img",
    "ns1", "ns2", "smtp", "webmail", "remote", "gateway", "auth", "sso",
    "git", "jenkins", "ci", "db", "database", "sql", "backup", "old",
    "intranet", "help", "support", "status", "monitor", "grafana", "kibana",
    "cloud", "s3", "storage", "assets", "assets2", "beta", "demo", "sandbox",
]

COMMON_WEB_PATHS = [
    "robots.txt", "sitemap.xml", ".env", ".git/HEAD", "admin", "login",
    "wp-admin/", "phpmyadmin/", "server-status", ".htaccess", "backup.zip",
    "config.php.bak", "web.config", "crossdomain.xml", "security.txt",
    "actuator/health", "api/", "graphql", ".well-known/security.txt",
]

def parse_ports(spec: str) -> List[int]:
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)

def resolve_target(target: str) -> List[str]:
    try:
        return [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()] \
            if "/" in target else [str(ipaddress.ip_address(target))]
    except ValueError:
        try:
            return [str(ip) for ip in socket.gethostbyname_ex(target)[2]]
        except socket.gaierror:
            return []
