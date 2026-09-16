

from typing import List, Dict, Any, Optional
from airecon.core.logger import Logger
from .fuzzy import FuzzyRiskEngine
from .bayes import NaiveBayesLearner
from .inference import InferenceEngine

class AIEngine:
    BANNER_KEYWORDS = (
        "ubuntu", "debian", "centos", "redhat", "windows", "microsoft",
        "apache", "nginx", "iis", "openssh", "pure-ftpd", "vsftpd",
        "mysql", "mariadb", "postgresql", "redis", "dovecot", "exim"
    )

    def __init__(self, model_path: str = "airecon_model.json"):
        self.fuzzy = FuzzyRiskEngine()
        self.bayes = NaiveBayesLearner(model_path)
        self.inference = InferenceEngine()
        Logger.info(f"Motor IA local carregado | {self.bayes.total} amostra(s) aprendidas")

    @classmethod
    def _banner_kws(cls, banner: str) -> List[str]:
        b = (banner or "").lower()
        return [kw for kw in cls.BANNER_KEYWORDS if kw in b]

    def analyze_host(self, ip: str, open_ports: list, context: Optional[dict] = None) -> Dict[str, Any]:
        features: List[str] = []
        banners_kws: List[str] = []
        findings: List[Dict[str, Any]] = []
        max_risk = 0.0

        for p in open_ports:
            port = p["port"] if isinstance(p, dict) else getattr(p, "port", p["port"])
            banner = p.get("banner", "") if isinstance(p, dict) else getattr(p, "banner", p.get("banner", ""))
            service = p.get("service", "") if isinstance(p, dict) else getattr(p, "service", p.get("service", ""))
            tls_details = p.get("tls_details") if isinstance(p, dict) else getattr(p, "tls_details", None)

            features.append(f"port:{port}")
            r = self.fuzzy.score_service(port, banner, tls_details)

            # Store ai_risk in the port object
            if isinstance(p, dict):
                p["ai_risk"] = r
                if r.get("cve_matches"):
                    p["cve_matches"] = r["cve_matches"]
            else:
                p.ai_risk = r
                if r.get("cve_matches"):
                    p.cve_matches = r["cve_matches"]

            findings.append({
                "port": port,
                "service": service,
                "score": r["score"],
                "severidade": r["severidade"],
                "motivos": r["razoes"],
                "cves": [c["cve"] for c in r.get("cve_matches", [])]
            })

            if service:
                features.append(f"svc:{service}")

            kws = self._banner_kws(banner)
            features.extend(f"banner:{k}" for k in kws)
            banners_kws.extend(kws)

            if r["score"] > max_risk:
                max_risk = r["score"]

        # Predict profile via Naive Bayes
        probs = self.bayes.predict(features)
        if probs:
            top_profile, confidence = list(probs.items())[0]
            Logger.found(f"IA [{ip}]: perfil provável = {top_profile} (confiança {confidence * 100:.0f}%)")

        # Evaluate rules via Inference Engine
        recs = self.inference.infer(open_ports, banners_kws, context=context)
        for r in recs[:3]:
            Logger.warn(f"IA [{ip}] P{r['prioridade']}: {r['acao']}")

        Logger.found(
            f"IA [{ip}]: risco máximo {max_risk}/10, "
            f"{len(findings)} achados, {len(recs)} recomendações"
        )

        return {
            "ip": ip,
            "risk_score": max_risk,
            "findings": findings,
            "profile": probs,
            "recomendacoes": recs
        }

    def feedback(self, ip: str, classe: str, open_ports: list):
        feats: List[str] = []
        for p in open_ports:
            port = p["port"] if isinstance(p, dict) else getattr(p, "port", p["port"])
            service = p.get("service", "") if isinstance(p, dict) else getattr(p, "service", p.get("service", ""))
            feats.append(f"port:{port}")
            if service:
                feats.append(f"svc:{service}")
        self.bayes.train(classe, feats)
        self.bayes.save()
        Logger.ok(f"Modelo atualizado: {ip} -> '{classe}' ({self.bayes.total} amostras aprendidas)")
