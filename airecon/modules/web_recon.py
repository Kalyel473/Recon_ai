"""
Web Reconnaissance Module: HTTP probing, technology detection, security headers and path fuzzing.
"""

import random
import re
import ssl
import urllib.error
import urllib.request
from typing import Optional, Tuple, Dict, Any, List
from airecon.core.config import USER_AGENTS, COMMON_WEB_PATHS
from airecon.core.models import WebResult
from airecon.core.logger import Logger

class WebRecon:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def _fetch(self, url: str, headers_only: bool = False) -> Tuple[Optional[int], Dict[str, str], str]:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={
            "User-Agent": random.choice(USER_AGENTS),
            **({"Range": "bytes=0-0"} if headers_only else {}),
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                return r.status, dict(r.headers), r.read(200_000).decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), ""
        except (urllib.error.URLError, ssl.SSLError, OSError):
            return None, {}, ""

    def probe(self, scheme_host: str) -> Optional[WebResult]:
        url = scheme_host
        status, headers, body = self._fetch(url)
        if status is None:
            return None

        wr = WebResult(url=url, headers=headers)
        Logger.found(f"Web: {url} [HTTP {status}]")

        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if m:
            wr.title = " ".join(m.group(1).split())[:200]
            Logger.info(f"Título: {wr.title}")

        tech: List[str] = []
        h = {k.lower(): v for k, v in headers.items()}
        if "server" in h:
            tech.append(f"server:{h['server']}")
        if "x-powered-by" in h:
            tech.append(f"x-powered-by:{h['x-powered-by']}")
        if "x-aspnet-version" in h:
            tech.append("ASP.NET")
        if "wp-content" in body or "wp-json" in body:
            tech.append("WordPress")
        if "drupal" in body.lower():
            tech.append("Drupal")
        if "joomla" in body.lower():
            tech.append("Joomla")
        if "__next" in body:
            tech.append("Next.js")
        if "ng-version" in h:
            tech.append(f"Angular:{h['ng-version']}")

        security_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options"
        ]
        missing = [s for s in security_headers if s not in h]
        if missing:
            Logger.warn(f"Headers de segurança ausentes: {', '.join(missing)}")
            wr.technologies.append("missing-sec-headers:" + ",".join(missing))

        wr.technologies.extend(tech)
        for t in tech:
            Logger.info(f"Tech: {t}")

        Logger.info("Fuzzing de paths sensíveis comuns...")
        for path in COMMON_WEB_PATHS:
            st, _, _ = self._fetch(f"{url.rstrip('/')}/{path}", headers_only=True)
            if st and (st not in (404, 400) or (st == 403 and path in (".env", ".git/HEAD", "admin"))):
                wr.interesting_paths.append({"path": f"/{path}", "status": st})
                Logger.found(f"/{path} -> HTTP {st}")

        return wr
