"""
JSON Report Exporter for AIRecon.
"""

import json
from dataclasses import asdict
from typing import Any
from airecon.core.logger import Logger

def save_json_report(report_obj: Any, output_path: str):
    data = asdict(report_obj) if hasattr(report_obj, "__dataclass_fields__") else report_obj
    try:
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(data, fp, indent=2, ensure_ascii=False)
        Logger.ok(f"Relatório JSON salvo em: {output_path}")
    except OSError as e:
        Logger.err(f"Falha ao salvar relatório JSON: {e}")
