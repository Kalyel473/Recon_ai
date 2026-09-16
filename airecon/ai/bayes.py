

import json
import math
from collections import defaultdict
from typing import List, Dict
from airecon.core.logger import Logger

class NaiveBayesLearner:
    def __init__(self, model_path: str = "airecon_model.json"):
        self.model_path = model_path
        self.class_counts = defaultdict(int)
        self.feature_counts = defaultdict(lambda: defaultdict(int))
        self.total = 0
        self.load()

    def _featurize(self, features: List[str]) -> List[str]:
        return [f.strip().lower() for f in features if f]

    def train(self, classe: str, features: List[str]):
        classe = classe.strip().lower()
        for f in self._featurize(features):
            self.feature_counts[classe][f] += 1
        self.class_counts[classe] += 1
        self.total += 1

    def predict(self, features: List[str]) -> Dict[str, float]:
        if self.total == 0 or not self.class_counts:
            return {}

        feats = self._featurize(features)
        vocab = set()
        for c in self.feature_counts:
            vocab.update(self.feature_counts[c].keys())
        v = max(len(vocab), 1)

        probs = {}
        for classe, ccount in self.class_counts.items():
            log_p = math.log(ccount / self.total)
            fc = self.feature_counts[classe]
            total_feat_classe = sum(fc.values())
            for f in feats:
                log_p += math.log((fc.get(f, 0) + 1) / (total_feat_classe + v))
            probs[classe] = log_p

        mx = max(probs.values())
        exp = {c: math.exp(p - mx) for c, p in probs.items()}
        s = sum(exp.values())
        if s == 0:
            return {}
        return {c: round(x / s, 4) for c, x in sorted(exp.items(), key=lambda kv: -kv[1])}

    def save(self):
        data = {
            "class_counts": dict(self.class_counts),
            "feature_counts": {c: dict(f) for c, f in self.feature_counts.items()},
            "total": self.total,
        }
        try:
            with open(self.model_path, "w", encoding="utf-8") as fp:
                json.dump(data, fp, indent=2)
        except OSError as e:
            Logger.err(f"Falha ao salvar modelo Naive Bayes: {e}")

    def load(self):
        try:
            with open(self.model_path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            self.class_counts = defaultdict(int, data.get("class_counts", {}))
            self.feature_counts = defaultdict(
                lambda: defaultdict(int),
                {c: defaultdict(int, f) for c, f in data.get("feature_counts", {}).items()}
            )
            self.total = data.get("total", 0)
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            pass
