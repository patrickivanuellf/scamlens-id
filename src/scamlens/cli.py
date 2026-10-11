"""Antarmuka baris perintah ScamLens ID.

Perintah:
  scamlens check "teks" | --file pesan.txt | (stdin)   periksa satu pesan/URL
  scamlens batch pesan.txt|pesan.jsonl                  periksa banyak pesan sekaligus
  scamlens rules                                        daftar semua aturan
  scamlens eval data/eval/pesan_uji.csv                 ukur precision/recall pada dataset

Kode keluar: 0 = aman (di bawah ambang), 1 = risiko >= ambang (--fail-on), 2 = kesalahan pemakaian.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .evaluate import evaluate, format_report, load_dataset
from .rules import RULES
from .scorer import LEVEL_SEDANG, LEVEL_TINGGI, Result, analyze_text
from .url_analyzer import URL_RULES

ICON = {"rendah": "[AMAN?]", "sedang": "[WASPADA]", "tinggi": "[BAHAYA]"}
COLOR = {"rendah": "32", "sedang": "33", "tinggi": "31"}
RANK = {"rendah": 0, "sedang": 1, "tinggi": 2}


class CliError(Exception):
    """Kesalahan pemakaian/IO yang ditampilkan ramah dengan kode keluar 2."""


def _paint(text: str, level: str, enabled: bool) -> str:
    return f"\033[{COLOR[level]}m{text}\033[0m" if enabled else text


def _use_color(args: argparse.Namespace) -> bool:
    return not getattr(args, "no_color", False) and sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _bar(score: int, width: int = 20) -> str:
    filled = round(score / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _trips(level: str, fail_on: str) -> bool:
    return fail_on != "never" and RANK[level] >= RANK[fail_on]


def _read_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        raise CliError(f"File tidak ditemukan: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise CliError(f"Tidak bisa membaca {path}: {exc}") from None


def format_result(result: Result, color: bool = False, quiet: bool = False) -> str:
    head = f"{ICON[result.level]} Skor risiko: {result.score}/100 ({result.level}) {_bar(result.score)}"
    head = _paint(head, result.level, color)
    if quiet:
        return head
    lines = [head]
    if result.findings:
        lines.append("Temuan:")
        for f in result.findings:
            lines.append(f"  - [{f.id}] {f.explanation}  (+{f.weight})")
            if f.evidence:
                lines.append(f"      bukti: {f.evidence!r}")
    if result.urls:
        lines.append("Tautan terdeteksi:")
        lines.extend(f"  - {u}" for u in result.urls)
    for note in result.notes:
        lines.append(f"Catatan: {note}")
    lines.append("")
    lines.append(result.advice)
    return "\n".join(lines)


def _get_text(args: argparse.Namespace) -> str:
    if args.file:
        text = _read_file(args.file)
    elif args.text is not None:
        text = args.text
    elif sys.stdin.isatty():
        raise CliError("Tidak ada input. Contoh: scamlens check \"teks pesan\" atau --file pesan.txt")
    else:
        text = sys.stdin.read()
    if not text.strip():
        raise CliError("Teks kosong, tidak ada yang bisa diperiksa.")
    return text


def cmd_check(args: argparse.Namespace) -> int:
    result = analyze_text(_get_text(args))
    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(format_result(result, _use_color(args), args.quiet))
    return 1 if _trips(result.level, args.fail_on) else 0


def _load_batch(path: str) -> list[str]:
    raw = _read_file(path)
    messages: list[str] = []
    for n, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        if path.lower().endswith(".jsonl"):
            try:
                text = json.loads(line)["text"]
            except (ValueError, KeyError, TypeError):
                raise CliError(f"{path} baris {n}: harus JSON dengan kunci \"text\".") from None
            messages.append(str(text))
        else:
            messages.append(line)
    if not messages:
        raise CliError(f"{path} tidak berisi pesan.")
    return messages


def cmd_batch(args: argparse.Namespace) -> int:
    messages = _load_batch(args.file)
    results = [analyze_text(m) for m in messages]
    if args.json:
        payload = [{"index": i, "text": m, **r.to_dict()} for i, (m, r) in enumerate(zip(messages, results), 1)]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        color = _use_color(args)
        for i, (m, r) in enumerate(zip(messages, results), 1):
            tag = _paint(f"{r.level:<6}", r.level, color)
            ids = ",".join(f.id for f in r.findings[:3])
            print(f"{i:>4} | {r.score:>3} | {tag} | {m[:60]!r} | {ids}")
        counts = {lvl: sum(1 for r in results if r.level == lvl) for lvl in RANK}
        print(f"\nTotal {len(results)}: tinggi={counts['tinggi']} sedang={counts['sedang']} rendah={counts['rendah']}")
    return 1 if any(_trips(r.level, args.fail_on) for r in results) else 0


def cmd_rules(args: argparse.Namespace) -> int:
    rows = [{"id": r.id, "kategori": r.category, "bobot": r.weight, "penjelasan": r.explanation,
             "tipe": "teks"} for r in RULES]
    rows += [{"id": k, "kategori": "url", "bobot": w, "penjelasan": t, "tipe": "url"}
             for k, (w, t) in URL_RULES.items()]
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    print(f"Ambang: sedang >= {LEVEL_SEDANG}, tinggi >= {LEVEL_TINGGI}\n")
    for r in rows:
        print(f"{r['id']:<7} {r['bobot']:>3}  {r['kategori']:<24} {r['penjelasan']}")
    print(f"\nTotal {len(rows)} aturan ({len(RULES)} teks, {len(URL_RULES)} URL).")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    try:
        samples = load_dataset(args.dataset)
    except FileNotFoundError:
        raise CliError(f"Dataset tidak ditemukan: {args.dataset}") from None
    except ValueError as exc:
        raise CliError(str(exc)) from None
    if args.split != "all":
        samples = [s for s in samples if s.split == args.split]
    if not samples:
        raise CliError("Tidak ada sampel setelah penyaringan split.")
    report = evaluate(samples, args.positive_level)
    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(format_report(report, args.errors, f"Dataset: {args.dataset} (split: {args.split})"))
    m = report.metrics
    failed = []
    if args.min_precision is not None and m.precision < args.min_precision:
        failed.append(f"precision {m.precision:.1%} < {args.min_precision:.1%}")
    if args.min_recall is not None and m.recall < args.min_recall:
        failed.append(f"recall {m.recall:.1%} < {args.min_recall:.1%}")
    if failed:
        print("GAGAL ambang: " + "; ".join(failed), file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scamlens", description="Periksa pesan/tautan penipuan berbahasa Indonesia.")
    parser.add_argument("--version", action="version", version=f"scamlens {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--json", action="store_true", help="keluaran JSON")
        p.add_argument("--fail-on", choices=["sedang", "tinggi", "never"], default="sedang",
                       help="level minimum yang membuat kode keluar 1 (default: sedang)")
        p.add_argument("--no-color", action="store_true", help="matikan warna ANSI")

    check = sub.add_parser("check", help="analisis satu teks atau URL")
    check.add_argument("text", nargs="?", help="teks atau URL (kosong = baca stdin)")
    check.add_argument("-f", "--file", help="baca teks dari file")
    check.add_argument("-q", "--quiet", action="store_true", help="hanya tampilkan baris skor")
    common(check)
    check.set_defaults(func=cmd_check)

    batch = sub.add_parser("batch", help="periksa banyak pesan (.txt satu per baris, atau .jsonl)")
    batch.add_argument("file")
    common(batch)
    batch.set_defaults(func=cmd_batch)

    rules = sub.add_parser("rules", help="tampilkan semua aturan dan bobotnya")
    rules.add_argument("--json", action="store_true")
    rules.set_defaults(func=cmd_rules)

    ev = sub.add_parser("eval", help="ukur precision/recall pada dataset berlabel (CSV/JSONL)")
    ev.add_argument("dataset")
    ev.add_argument("--split", choices=["dev", "test", "blind", "all"], default="all")
    ev.add_argument("--positive-level", choices=["sedang", "tinggi"], default="sedang",
                    help="level yang dihitung sebagai 'penipuan' (default: sedang)")
    ev.add_argument("--errors", action="store_true", help="tampilkan false positive/negative")
    ev.add_argument("--json", action="store_true")
    ev.add_argument("--min-precision", type=float, help="gagal (kode 1) bila precision di bawah nilai ini")
    ev.add_argument("--min-recall", type=float, help="gagal (kode 1) bila recall di bawah nilai ini")
    ev.set_defaults(func=cmd_eval)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CliError as exc:
        print(f"Kesalahan: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
