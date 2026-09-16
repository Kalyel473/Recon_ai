"""
Console logger with color-coded levels and quiet mode support.
"""

from datetime import datetime
import sys

class Logger:
    COLORS = {
        "info": "\033[94m",    # Blue
        "ok": "\033[92m",      # Green
        "warn": "\033[93m",    # Yellow
        "err": "\033[91m",     # Red
        "found": "\033[95m",   # Magenta
        "end": "\033[0m",
    }
    QUIET = False

    @classmethod
    def log(cls, level: str, msg: str):
        if cls.QUIET and level not in ("found", "err"):
            return
        ts = datetime.now().strftime("%H:%M:%S")
        c = cls.COLORS.get(level, "")
        e = cls.COLORS["end"]
        out = f"[{ts}] {c}[{level.upper():5}]{e} {msg}"
        try:
            print(out, flush=True)
        except UnicodeEncodeError:
            encoding = sys.stdout.encoding or "ascii"
            safe_out = out.encode(encoding, errors="replace").decode(encoding)
            print(safe_out, flush=True)

    @classmethod
    def info(cls, m: str): cls.log("info", m)

    @classmethod
    def ok(cls, m: str): cls.log("ok", m)

    @classmethod
    def warn(cls, m: str): cls.log("warn", m)

    @classmethod
    def err(cls, m: str): cls.log("err", m)

    @classmethod
    def found(cls, m: str): cls.log("found", m)
