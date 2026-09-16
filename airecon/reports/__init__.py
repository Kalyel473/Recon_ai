"""
Report generation modules for AIRecon (JSON, Markdown, HTML).
"""

from .json_reporter import save_json_report
from .markdown_reporter import generate_markdown_report, save_markdown_report
from .html_reporter import generate_html_report, save_html_report

__all__ = [
    "save_json_report",
    "generate_markdown_report", "save_markdown_report",
    "generate_html_report", "save_html_report"
]
