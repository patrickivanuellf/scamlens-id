"""Antarmuka baris perintah: scamlens check "teks" | --file pesan.txt [--json]."""

from __future__ import annotations

import argparse
import json
import sys

from .scorer import analyze_text

ICON = {"rendah": "[AMAN?]", "sedang": "[WASPADA]", "tinggi": "[BAHAYA]"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scamlens", description="Periksa pesan/tautan penipuan.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    check = sub.add_parser("check", help="analisis teks atau URL")
    check.add_argument("text", nargs="?", help="teks atau URL (kosong = baca stdin)")
    check.add_argument("--file", help="baca teks dari file")
    check.add_argument("--json", action="store_true", help="keluaran JSON")
    args = parser.parse_args(argv)

    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            text = fh.read()
    else:
        text = args.text if args.text is not None else sys.stdin.read()

    result = analyze_text(text)
    if args.json:
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return 0

    print(f"{ICON[result.level]} Skor risiko: {result.score}/100 ({result.level})")
    for f in result.findings:
        print(f"  - [{f.id}] {f.explanation}  (bukti: {f.evidence!r})")
    print(f"\n{result.advice}")
    return 0 if result.level == "rendah" else 1


if __name__ == "__main__":
    raise SystemExit(main())
