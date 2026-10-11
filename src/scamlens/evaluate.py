"""Evaluasi mesin deteksi terhadap dataset berlabel (CSV atau JSONL).

Kolom wajib: ``label`` (``scam``/``ham``) dan ``text``. Kolom opsional: ``id``,
``split`` (``dev``/``test``), ``category``.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path

from .scorer import Result, analyze_text

LEVEL_RANK = {"rendah": 0, "sedang": 1, "tinggi": 2}


@dataclass(frozen=True)
class Sample:
    id: str
    label: str  # "scam" | "ham"
    text: str
    category: str = ""
    split: str = ""


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    def to_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": round(self.precision, 4), "recall": round(self.recall, 4),
            "f1": round(self.f1, 4), "accuracy": round(self.accuracy, 4),
        }


@dataclass
class Report:
    positive_level: str
    metrics: Metrics
    per_category_recall: dict[str, tuple[int, int]] = field(default_factory=dict)
    false_positives: list[tuple[Sample, Result]] = field(default_factory=list)
    false_negatives: list[tuple[Sample, Result]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "positive_level": self.positive_level,
            "metrics": self.metrics.to_dict(),
            "per_category_recall": {
                k: {"terdeteksi": v[0], "total": v[1]}
                for k, v in sorted(self.per_category_recall.items())
            },
            "false_positives": [_err(s, r) for s, r in self.false_positives],
            "false_negatives": [_err(s, r) for s, r in self.false_negatives],
        }


def _err(s: Sample, r: Result) -> dict:
    return {"id": s.id, "category": s.category, "score": r.score, "level": r.level,
            "text": s.text, "rules": [f.id for f in r.findings]}


def load_dataset(path: str | Path) -> list[Sample]:
    p = Path(path)
    samples: list[Sample] = []
    if p.suffix.lower() == ".jsonl":
        with p.open(encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
    else:
        with p.open(encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
    for i, row in enumerate(rows, 1):
        label = str(row.get("label", "")).strip().lower()
        text = row.get("text")
        if label not in {"scam", "ham"} or not text:
            raise ValueError(f"Baris {i}: butuh label 'scam'/'ham' dan teks tidak kosong.")
        samples.append(Sample(
            id=str(row.get("id") or f"R{i:04d}"), label=label, text=text,
            category=str(row.get("category") or ""), split=str(row.get("split") or ""),
        ))
    return samples


def evaluate(samples: list[Sample], positive_level: str = "sedang") -> Report:
    if positive_level not in ("sedang", "tinggi"):
        raise ValueError("positive_level harus 'sedang' atau 'tinggi'")
    threshold = LEVEL_RANK[positive_level]
    m = Metrics()
    report = Report(positive_level, m)
    per_cat: dict[str, list[int]] = {}
    for s in samples:
        res = analyze_text(s.text)
        predicted_scam = LEVEL_RANK[res.level] >= threshold
        if s.label == "scam":
            c = per_cat.setdefault(s.category or "-", [0, 0])
            c[1] += 1
            if predicted_scam:
                m.tp += 1
                c[0] += 1
            else:
                m.fn += 1
                report.false_negatives.append((s, res))
        else:
            if predicted_scam:
                m.fp += 1
                report.false_positives.append((s, res))
            else:
                m.tn += 1
    report.per_category_recall = {k: (v[0], v[1]) for k, v in per_cat.items()}
    return report


def format_report(report: Report, show_errors: bool = False, title: str = "") -> str:
    m = report.metrics
    lines = []
    if title:
        lines.append(title)
    lines.append(f"Sampel: {m.total}  (positif = level >= {report.positive_level})")
    lines.append(f"  TP={m.tp}  FP={m.fp}  FN={m.fn}  TN={m.tn}")
    lines.append(f"  Precision {m.precision:.1%} | Recall {m.recall:.1%} | "
                 f"F1 {m.f1:.1%} | Akurasi {m.accuracy:.1%}")
    lines.append("  Recall per kategori penipuan:")
    for cat, (hit, tot) in sorted(report.per_category_recall.items()):
        lines.append(f"    {cat:<18} {hit}/{tot}")
    if show_errors:
        lines.append(f"  False positive ({len(report.false_positives)}) - pesan sah yang ditandai:")
        for s, r in report.false_positives:
            lines.append(f"    [{s.id}] skor {r.score} {[f.id for f in r.findings]}: {s.text[:90]}")
        lines.append(f"  False negative ({len(report.false_negatives)}) - penipuan yang lolos:")
        for s, r in report.false_negatives:
            lines.append(f"    [{s.id}] skor {r.score} {[f.id for f in r.findings]}: {s.text[:90]}")
    return "\n".join(lines)
