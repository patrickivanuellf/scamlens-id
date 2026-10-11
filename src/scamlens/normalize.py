"""Normalisasi teks agar trik penyamaran umum tidak mengelabui aturan.

Menangani: huruf fullwidth/matematis (NFKC), karakter tak terlihat, huruf Cyrillic yang
mirip huruf Latin, leetspeak (``h4diah`` -> ``hadiah``), huruf dipisah (``O T P``,
``M.E.N.A.N.G``), dan huruf yang diulang (``segeraaa``). URL dibiarkan utuh.
"""

from __future__ import annotations

import re
import unicodedata

from .url_analyzer import URL_RE

_INVISIBLE = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)

# Cyrillic yang tampak seperti huruf Latin.
_HOMOGLYPHS = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u04bb": "h",
})

LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

_TOKEN = re.compile(r"[A-Za-z0-9@$]+")
# 50jt, 10rb, 24jam: angka+satuan yang dikenal bukan leetspeak (tetapi "0TP" tetap dibongkar).
_UNIT_LIKE = re.compile(
    r"^\d+(?:jt|rb|ribu|juta|jam|hari|menit|detik|gb|mb|kb|kg|km|x|k|m|an|th|persen|pcs|ml|l)$",
    re.IGNORECASE,
)
_SPACED = re.compile(r"\b(?:[A-Za-z][ .\-_]){2,}[A-Za-z]\b")
_REPEATED = re.compile(r"([A-Za-z])\1{2,}")


def _unleet(match: re.Match[str]) -> str:
    token = match.group(0)
    if _UNIT_LIKE.match(token):
        return token
    specials = sum(1 for ch in token if ch in "01345 7@$".replace(" ", ""))
    letters = sum(1 for ch in token if ch.isalpha())
    if specials == 0 or letters < 2 or specials > letters:
        return token
    return token.translate(LEET)


def _collapse_spaced(match: re.Match[str]) -> str:
    return re.sub(r"[ .\-_]", "", match.group(0))


def _collapse_repeat(match: re.Match[str]) -> str:
    ch = match.group(1)
    return match.group(0) if ch in "wW" else ch


def _normalize_segment(seg: str) -> str:
    seg = _SPACED.sub(_collapse_spaced, seg)
    seg = _TOKEN.sub(_unleet, seg)
    seg = _REPEATED.sub(_collapse_repeat, seg)
    return re.sub(r"[ \t]+", " ", seg)


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(_INVISIBLE).translate(_HOMOGLYPHS)
    out: list[str] = []
    last = 0
    for m in URL_RE.finditer(text):
        out.append(_normalize_segment(text[last:m.start()]))
        out.append(m.group(0))
        last = m.end()
    out.append(_normalize_segment(text[last:]))
    return "".join(out)
