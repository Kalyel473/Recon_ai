"""
DNS Reconnaissance Module: Raw UDP DNS Queries (RFC 1035), Subdomains and Email Security Audit.
Includes SPF and DMARC posture auditing without third-party dependencies.
"""

import concurrent.futures
import ipaddress
import random
import re
import socket
import struct
from typing import Dict, List, Any, Optional
from airecon.core.config import SUBDOMAIN_WORDLIST
from airecon.core.models import DNSResult
from airecon.core.logger import Logger

class DNSEnum:
    def __init__(self, resolver: str = "8.8.8.8", timeout: float = 3.0):
        self.resolver = resolver
        self.timeout = timeout

    def _query_raw(self, qname: str, qtype: int) -> List[str]:
        tid = random.randint(0, 65535)
        header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        q = b"".join(bytes([len(l)]) + l.encode() for l in qname.split(".")) + b"\x00"
        packet = header + q + struct.pack("!HH", qtype, 1)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            s.sendto(packet, (self.resolver, 53))
            try:
                data, _ = s.recvfrom(4096)
            except socket.timeout:
                return []
            except (socket.error, OSError):
                return []

        answers: List[str] = []
        try:
            ancount = struct.unpack("!H", data[6:8])[0]
            idx = 12
            while data[idx] != 0:
                idx += data[idx] + 1
            idx += 5
            for _ in range(ancount):
                if data[idx] & 0xC0 == 0xC0:
                    idx += 2
                else:
                    while data[idx] != 0:
                        idx += data[idx] + 1
                    idx += 1
                rtype, _, _, rdlen = struct.unpack("!HHIH", data[idx:idx + 10])
                idx += 10
                rdata = data[idx:idx + rdlen]
                idx += rdlen

                if rtype == 1 and rdlen == 4:
                    answers.append(socket.inet_ntoa(rdata))
                elif rtype in (5, 12):
                    answers.append(self._decode_name(data, idx - rdlen))
                elif rtype == 15:
                    pref = struct.unpack("!H", rdata[:2])[0]
                    answers.append(f"{pref} {self._decode_name(rdata, 2)}")
                elif rtype == 16:
                    txt, i = "", 0
                    while i < rdlen:
                        ln = rdata[i]
                        i += 1
                        txt += rdata[i:i + ln].decode(errors="replace")
                        i += ln
                    answers.append(txt)
                elif rtype == 28:
                    answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
                elif rtype == 6:
                    answers.append("SOA present")
        except (IndexError, struct.error):
            pass
        return answers

    def _decode_name(self, msg: bytes, offset: int) -> str:
        labels, jumped, end = [], False, offset
        while True:
            ln = msg[offset]
            if ln & 0xC0 == 0xC0:
                if not jumped:
                    end = offset + 2
                offset = ((ln & 0x3F) << 8) | msg[offset + 1]
                jumped = True
            elif ln == 0:
                if not jumped:
                    end = offset + 1
                break
            else:
                labels.append(msg[offset + 1:offset + 1 + ln].decode(errors="replace"))
                offset += 1 + ln
        return ".".join(labels)

    def audit_email_security(self, domain: str, txt_records: List[str]) -> Dict[str, Any]:
        result = {
            "spf": {"found": False, "raw": "", "qualifier": "missing", "status": "VULNERÁVEL (Sem SPF)"},
            "dmarc": {"found": False, "raw": "", "policy": "missing", "status": "VULNERÁVEL (Sem DMARC)"}
        }

        # Check SPF in TXT records
        for txt in txt_records:
            if txt.strip().startswith("v=spf1"):
                result["spf"]["found"] = True
                result["spf"]["raw"] = txt.strip()
                if "+all" in txt:
                    result["spf"]["qualifier"] = "+all"
                    result["spf"]["status"] = "CRÍTICO (+all autoriza qualquer IP)"
                elif "?all" in txt:
                    result["spf"]["qualifier"] = "?all"
                    result["spf"]["status"] = "FRACO (?all não define política neutra)"
                elif "~all" in txt:
                    result["spf"]["qualifier"] = "~all"
                    result["spf"]["status"] = "ACEITÁVEL (~all SoftFail)"
                elif "-all" in txt:
                    result["spf"]["qualifier"] = "-all"
                    result["spf"]["status"] = "SEGURO (-all HardFail rigoroso)"
                else:
                    result["spf"]["qualifier"] = "none"
                    result["spf"]["status"] = "INCOMPLETO (Sem diretiva all)"
                break

        # Check DMARC via TXT query on _dmarc.<domain>
        dmarc_target = f"_dmarc.{domain}"
        dmarc_answers = self._query_raw(dmarc_target, 16)
        for txt in dmarc_answers:
            if "v=DMARC1" in txt or "v=dmarc1" in txt:
                result["dmarc"]["found"] = True
                result["dmarc"]["raw"] = txt.strip()
                m_p = re.search(r"p=(none|quarantine|reject)", txt, re.IGNORECASE)
                policy = m_p.group(1).lower() if m_p else "unknown"
                result["dmarc"]["policy"] = policy
                if policy == "reject":
                    result["dmarc"]["status"] = "SEGURO (p=reject rejeita e-mails forjados)"
                elif policy == "quarantine":
                    result["dmarc"]["status"] = "MODERADO (p=quarantine direciona para spam)"
                elif policy == "none":
                    result["dmarc"]["status"] = "FRACO (p=none apenas monitora, não bloqueia spoofing)"
                break

        # Log status
        spf_status = result["spf"]["status"]
        dmarc_status = result["dmarc"]["status"]
        Logger.info(f"Auditoria SPF: {spf_status}")
        Logger.info(f"Auditoria DMARC: {dmarc_status}")

        return result

    def enumerate_records(self, domain: str) -> Tuple[Dict[str, List[str]], Dict[str, Any]]:
        Logger.info(f"Enumerando registros DNS de {domain}...")
        types = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "SOA": 6}
        recs: Dict[str, List[str]] = {}
        for name, qtype in types.items():
            ans = self._query_raw(domain, qtype)
            if ans:
                recs[name] = ans
                Logger.found(f"DNS {name}: {', '.join(ans[:3])}{' ...' if len(ans) > 3 else ''}")

        email_sec = self.audit_email_security(domain, recs.get("TXT", []))
        return recs, email_sec

    def subdomain_bruteforce(self, domain: str, wordlist: Optional[List[str]] = None, threads: int = 50) -> List[Dict[str, Any]]:
        wordlist = wordlist or SUBDOMAIN_WORDLIST
        Logger.info(f"Bruteforce de subdomínios ({len(wordlist)} entradas)...")
        found: List[Dict[str, Any]] = []

        def check(sub: str) -> Optional[Dict[str, Any]]:
            fqdn = f"{sub}.{domain}"
            ips = self._query_raw(fqdn, 1)
            if ips:
                Logger.found(f"Subdomínio: {fqdn} -> {', '.join(ips)}")
                return {"subdomain": fqdn, "ips": ips, "source": "wordlist"}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for r in ex.map(check, wordlist):
                if r:
                    found.append(r)

        Logger.ok(f"{len(found)} subdomínio(s) encontrado(s) via wordlist")
        return found

    def reverse_lookup(self, cidr: str, threads: int = 60) -> Dict[str, str]:
        Logger.info(f"Reverse DNS em {cidr}...")
        results: Dict[str, str] = {}
        try:
            ips = [str(i) for i in ipaddress.ip_network(cidr, strict=False).hosts()]
        except ValueError:
            return results

        def rdns(ip: str) -> Optional[str]:
            try:
                return socket.gethostbyaddr(ip)[0]
            except (socket.herror, OSError):
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for ip, name in zip(ips, ex.map(rdns, ips)):
                if name:
                    results[ip] = name
                    Logger.found(f"PTR {ip} -> {name}")

        return results
