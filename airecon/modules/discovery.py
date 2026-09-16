"""
Host Discovery Module: ICMP Raw Socket Ping with automatic TCP fallback.
"""

import concurrent.futures
import os
import random
import socket
import string
import struct
import time
from typing import List, Optional
from airecon.core.models import HostResult
from airecon.core.logger import Logger

class HostDiscovery:
    @staticmethod
    def tcp_ping(ip: str, ports=(80, 443, 22, 445), timeout: float = 1.5) -> bool:
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        return True
            except (socket.error, OSError):
                continue
        return False

    @staticmethod
    def icmp_ping(ip: str, timeout: float = 2.0) -> bool:
        try:
            ident = os.getpid() & 0xFFFF
            seq = random.randint(1, 65535)
            payload = b"AIRECON" + bytes(random.choices(string.ascii_letters, k=48))
            data = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
            checksum = 0
            for i in range(0, len(data), 2):
                chunk = data[i:i + 2]
                checksum += (chunk[0] << 8) + (chunk[1] if len(chunk) > 1 else 0)
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
            checksum = ~checksum & 0xFFFF
            packet = struct.pack("!BBHHH", 8, 0, socket.htons(checksum), ident, seq) + payload

            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                s.settimeout(timeout)
                s.sendto(packet, (ip, 0))
                start = time.time()
                while time.time() - start < timeout:
                    reply, addr = s.recvfrom(1024)
                    if addr[0] == ip and reply[20] == 0:
                        return True
                return False
        except PermissionError:
            return HostDiscovery.tcp_ping(ip, timeout=timeout)
        except (socket.error, OSError):
            return False

    @classmethod
    def sweep(cls, ips: List[str], use_icmp: bool = True, threads: int = 100) -> List[HostResult]:
        Logger.info(f"Host discovery em {len(ips)} hosts ({threads} threads)...")
        alive: List[HostResult] = []

        def probe(ip: str) -> Optional[HostResult]:
            up = False
            if use_icmp:
                try:
                    up = cls.icmp_ping(ip)
                except Exception:
                    up = False
            if not up:
                up = cls.tcp_ping(ip)
            if up:
                try:
                    hn = socket.gethostbyaddr(ip)[0]
                except (socket.herror, socket.gaierror):
                    hn = ""
                return HostResult(ip=ip, alive=True, hostname=hn)
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for res in ex.map(probe, ips):
                if res:
                    Logger.found(f"Host ativo: {res.ip}" + (f" ({res.hostname})" if res.hostname else ""))
                    alive.append(res)

        Logger.ok(f"{len(alive)} host(s) ativo(s) de {len(ips)}")
        return alive
