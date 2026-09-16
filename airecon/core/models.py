"""
Data models and report structures for AIRecon.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

@dataclass
class PortResult:
    port: int
    state: str
    service: str = ""
    banner: str = ""
    version_hint: str = ""
    ai_risk: Optional[dict] = None
    tls_details: Optional[dict] = None
    cve_matches: List[dict] = field(default_factory=list)

    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def __contains__(self, key):
        return hasattr(self, key)


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    alive: bool = False
    ttl_guess: str = ""
    open_ports: List[Any] = field(default_factory=list)
    ai_analysis: Optional[dict] = None

    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def __contains__(self, key):
        return hasattr(self, key)


@dataclass
class DNSResult:
    domain: str = ""
    records: Dict[str, Any] = field(default_factory=dict)
    subdomains: List[Dict[str, Any]] = field(default_factory=list)
    reverse: Dict[str, str] = field(default_factory=dict)
    email_security: Dict[str, Any] = field(default_factory=dict)
    sans_discovered: List[str] = field(default_factory=list)

    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def __contains__(self, key):
        return hasattr(self, key)


@dataclass
class WebResult:
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    title: str = ""
    technologies: List[str] = field(default_factory=list)
    interesting_paths: List[Dict[str, Any]] = field(default_factory=list)

    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def __contains__(self, key):
        return hasattr(self, key)


@dataclass
class ReconReport:
    target: str = ""
    started: str = ""
    finished: str = ""
    hosts: List[Any] = field(default_factory=list)
    dns: Optional[dict] = None
    web: Optional[list] = None
    summary: Dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def __contains__(self, key):
        return hasattr(self, key)
