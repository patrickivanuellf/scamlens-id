"""Menggabungkan temuan aturan teks dan URL menjadi skor risiko 0-100."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .normalize import normalize_text
from .rules import RULES, is_negated
from .url_analyzer import analyze_url, extract_urls

REPORT_HINT = "Laporkan ke aduankonten.id (BSSN) atau kanal resmi lembaga terkait."
LEVEL_SEDANG = 25
LEVEL_TINGGI = 55
MAX_CHARS = 20_000


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
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def level_for(score: int) -> str:
    if score < LEVEL_SEDANG:
        return "rendah"
    if score < LEVEL_TINGGI:
        return "sedang"
    return "tinggi"


def _combine(weights: list[int]) -> int:
    """Gabungan probabilistik: 1 - prod(1 - w/100). Menghindari skor melebihi 100."""
    remaining = 1.0
    for w in weights:
        remaining *= 1 - w / 100
    return round((1 - remaining) * 100)


def _advice(level: str, findings: list[Finding]) -> str:
    if level == "rendah":
        return ("Tidak ada pola penipuan yang menonjol, tetapi tetap verifikasi "
                "jika diminta data pribadi atau uang.")
    ids = {f.id for f in findings}
    lines = ["Jangan klik tautan, jangan kirim OTP/PIN, dan verifikasi lewat kanal resmi."]
    if any(i.startswith("APK") or i == "URL-08" for i in ids):
        lines.append("Jangan pasang file .apk dari chat. Jika sudah terlanjur: aktifkan mode pesawat, "
                     "hapus aplikasinya, lalu hubungi bank dan ganti kata sandi dari perangkat lain.")
    if ids & {"OTP-01", "DAT-01"}:
        lines.append("OTP, PIN, dan kata sandi tidak boleh dibagikan kepada siapa pun, "
                     "termasuk yang mengaku petugas.")
    if ids & {"TRF-01", "FAM-01", "FAM-02", "FAM-03", "INV-01", "INV-02", "LOK-01", "LOK-02", "DON-01"}:
        lines.append("Jangan transfer sebelum memastikan lewat telepon ke nomor resmi atau "
                     "anggota keluarga yang Anda kenal.")
    lines.append(REPORT_HINT)
    return " ".join(lines)


def analyze_text(text: str) -> Result:
    notes: list[str] = []
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS]
        notes.append(f"Teks dipotong ke {MAX_CHARS} karakter pertama.")
    norm = normalize_text(text)

    findings: list[Finding] = []
    suppressed: list[str] = []
    for rule in RULES:
        chosen = None
        was_negated = False
        for match in rule.pattern.finditer(norm):
            if rule.negatable and is_negated(norm, match.start(), match.end()):
                was_negated = True
                continue
            chosen = match
            break
        if chosen is not None:
            findings.append(Finding(rule.id, rule.category, rule.weight, rule.explanation,
                                    chosen.group(0)[:80]))
        elif was_negated:
            suppressed.append(rule.id)

    if suppressed:
        notes.append("Pola " + ", ".join(suppressed) + " disebut dalam kalimat peringatan "
                     "(misalnya 'jangan berikan ...'), sehingga tidak dihitung sebagai ancaman.")

    urls = extract_urls(norm)
    for url in urls:
        for uf in analyze_url(url):
            findings.append(Finding(uf.id, "url", uf.weight, uf.explanation, url[:80]))

    score = _combine([f.weight for f in findings])
    level = level_for(score)
    findings.sort(key=lambda f: f.weight, reverse=True)
    return Result(score, level, findings, urls, _advice(level, findings), notes)
