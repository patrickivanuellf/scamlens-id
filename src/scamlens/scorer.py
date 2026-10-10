"""Menggabungkan temuan aturan teks dan URL menjadi skor risiko 0-100."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .rules import RULES
from .url_analyzer import analyze_url, extract_urls

REPORT_HINT = "Laporkan ke aduankonten.id (BSSN) atau kanal resmi lembaga terkait."


@dataclass
class Finding:
    id: str
    category: str
    weight: int
    explanation: str
    evidence: str = ""


@dataclass
class Result:
    score: int
    level: str
    findings: list[Finding] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    advice: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _level(score: int) -> str:
    if score < 25:
        return "rendah"
    if score < 55:
        return "sedang"
    return "tinggi"


def _combine(weights: list[int]) -> int:
    """Gabungan probabilistik: 1 - prod(1 - w/100). Menghindari skor melebihi 100."""
    remaining = 1.0
    for w in weights:
        remaining *= 1 - w / 100
    return round((1 - remaining) * 100)


def analyze_text(text: str) -> Result:
    findings: list[Finding] = []
    for rule in RULES:
        match = rule.pattern.search(text)
        if match:
            findings.append(Finding(rule.id, rule.category, rule.weight,
                                    rule.explanation, match.group(0)[:80]))

    urls = extract_urls(text)
    for url in urls:
        for uf in analyze_url(url):
            findings.append(Finding(uf.id, "url", uf.weight, uf.explanation, url[:80]))

    score = _combine([f.weight for f in findings])
    level = _level(score)
    if level != "rendah":
        advice = ("Jangan klik tautan, jangan kirim OTP/PIN, dan verifikasi lewat kanal resmi. "
                  + REPORT_HINT)
    else:
        advice = ("Tidak ada pola penipuan yang menonjol, tetapi tetap verifikasi "
                  "jika diminta data pribadi.")
    findings.sort(key=lambda f: f.weight, reverse=True)
    return Result(score, level, findings, urls, advice)
