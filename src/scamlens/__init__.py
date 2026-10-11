"""ScamLens ID: pendeteksi pesan dan tautan penipuan berbahasa Indonesia."""

from .scorer import Finding, Result, analyze_text

__all__ = ["Finding", "Result", "analyze_text"]
__version__ = "0.2.0"
