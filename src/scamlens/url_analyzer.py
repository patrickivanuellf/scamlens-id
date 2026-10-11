"""Analisis heuristik untuk URL: typosquatting, shortener, TLD mencurigakan, dsb.

Tidak pernah membuka atau mengunjungi URL; hanya membaca string-nya.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

# Dipakai juga oleh normalize.py untuk membongkar leetspeak di nama domain.
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})

_BARE_TLDS = (
    "id|com|net|org|co|xyz|top|click|icu|cfd|sbs|cyou|monster|buzz|live|site|online|info|link|me|ly|"
    "gl|app|shop|vip|cc|ws|to|fun|rest|today|work|life|tk|ml|ga|cf|gq|gy|gd|at|is|us|in"
)
_SCHEME_OR_WWW = r"(?:https?://|www\.)[^\s<>\"')]+"
# Domain tanpa skema (mis. "bit.ly/abc", "bca-verif.top/login"), bukan bagian dari email.
_BARE = (
    rf"(?<![@\w./-])(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{_BARE_TLDS})"
    rf"(?![a-z0-9-])(?:/[^\s<>\"')]*)?"
)
URL_RE = re.compile(rf"{_SCHEME_OR_WWW}|{_BARE}", re.IGNORECASE)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "s.id", "t.ly", "cutt.ly", "is.gd", "rb.gy", "shorturl.at",
    "tiny.cc", "v.gd", "ow.ly", "rebrand.ly", "bitly.ws",
}
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "icu", "cfd", "sbs", "cyou", "monster", "buzz", "live",
    "vip", "fun", "rest", "today", "work", "life", "tk", "ml", "ga", "cf", "gq",
}
FREE_HOSTING = {
    "000webhostapp.com", "weebly.com", "blogspot.com", "github.io", "netlify.app", "pages.dev",
    "vercel.app", "web.app", "firebaseapp.com", "glitch.me", "wixsite.com", "sites.google.com",
}
SECOND_LEVEL_ID = {"co", "go", "ac", "or", "web", "my", "sch", "mil", "net"}
TRUSTED_SUFFIXES = (".go.id", ".ac.id", ".sch.id", ".mil.id")
LURE_WORDS = {
    "klaim", "hadiah", "bonus", "verifikasi", "verif", "verify", "secure", "login",
    "update", "undian", "thr", "bansos", "gratis", "konfirmasi", "refund",
}
BRAND_ALIASES = {"ig": "instagram", "wa": "whatsapp", "tg": "telegram"}
BRAND_AFFIXES = {"klik", "mobile", "online", "id", "bank", "indonesia", "cs", "care", "secure",
                 "login", "verif", "verifikasi", "update", "promo", "hadiah", "m", "my", "e"}

# Contoh daftar merek dan domain resmi (verifikasi ulang sebelum dipakai serius).
BRANDS: dict[str, set[str]] = {
    "bca": {"bca.co.id", "klikbca.com"},
    "bri": {"bri.co.id"},
    "bni": {"bni.co.id"},
    "mandiri": {"bankmandiri.co.id"},
    "bpjs": {"bpjs-kesehatan.go.id", "bpjsketenagakerjaan.go.id"},
    "shopee": {"shopee.co.id"},
    "tokopedia": {"tokopedia.com"},
    "jne": {"jne.co.id"},
    "sicepat": {"sicepat.com"},
    "dana": {"dana.id"},
    "gopay": {"gopay.co.id"},
    "ovo": {"ovo.id"},
    "pln": {"pln.co.id"},
    "indomaret": {"indomaret.co.id"},
    "taspen": {"taspen.co.id"},
    "pajak": {"pajak.go.id"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "telegram": {"telegram.org", "t.me"},
}

# Registri aturan URL: id -> (bobot, penjelasan). Sumber tunggal untuk analisis dan `scamlens rules`.
URL_RULES: dict[str, tuple[int, str]] = {
    "URL-01": (35, "Tautan memakai alamat IP, bukan nama domain."),
    "URL-02": (25, "Tautan dipendekkan sehingga tujuan asli tersembunyi."),
    "URL-03": (25, "Ekstensi domain .{tld} sering dipakai situs penipuan."),
    "URL-04": (30, "Domain memakai punycode, bisa meniru huruf yang mirip."),
    "URL-05": (30, "Ada karakter '@' untuk menyamarkan tujuan sebenarnya."),
    "URL-06": (8, "Tautan tidak memakai HTTPS."),
    "URL-07": (15, "Terlalu banyak subdomain."),
    "URL-08": (45, "Tautan mengunduh file APK langsung."),
    "URL-09": (40, "Domain memuat nama '{brand}' tetapi bukan domain resmi ({official})."),
    "URL-10": (35, "Penulisan domain mirip merek '{brand}' (kemungkinan salah ketik yang disengaja)."),
    "URL-11": (12, "Domain memuat banyak tanda hubung, pola umum domain palsu."),
    "URL-12": (15, "Domain memuat kata pancingan ('{word}') pada situs yang bukan domain resmi."),
    "URL-13": (12, "Situs berada di layanan hosting gratis, sering dipakai halaman phishing."),
}


@dataclass(frozen=True)
class UrlFinding:
    id: str
    weight: int
    explanation: str


def _finding(id_: str, **fmt: str) -> UrlFinding:
    weight, text = URL_RULES[id_]
    return UrlFinding(id_, weight, text.format(**fmt) if fmt else text)


def extract_urls(text: str) -> list[str]:
    seen: list[str] = []
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?)'\"")
        if url and url not in seen:
            seen.append(url)
    return seen


def registered_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and labels[-1] == "id" and labels[-2] in SECOND_LEVEL_ID:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _edit1(a: str, b: str) -> bool:
    """True bila a dan b berjarak tepat 1 sunting (sisip/hapus/ganti)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    i = j = 0
    skipped = False
    while i < len(short) and j < len(long_):
        if short[i] == long_[j]:
            i += 1
            j += 1
        elif skipped:
            return False
        else:
            skipped = True
            j += 1
    return True


def _is_official(reg: str) -> bool:
    return any(reg in official for official in BRANDS.values()) or reg.endswith(TRUSTED_SUFFIXES)


def _brand_of(token: str) -> str | None:
    """Merek yang dirujuk token: sama persis, alias, atau merek + imbuhan umum (klikbca)."""
    if token in BRANDS:
        return token
    if token in BRAND_ALIASES:
        return BRAND_ALIASES[token]
    for brand in BRANDS:
        if token.startswith(brand) and token[len(brand):] in BRAND_AFFIXES:
            return brand
        if token.endswith(brand) and token[: -len(brand)] in BRAND_AFFIXES:
            return brand
    return None


def analyze_url(url: str) -> list[UrlFinding]:
    explicit_http = url.lower().startswith("http://")  # tanpa skema = skema tidak diketahui
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    findings: list[UrlFinding] = []
    if not host:
        return findings

    try:
        ipaddress.ip_address(host)
        findings.append(_finding("URL-01"))
        if parsed.path.lower().endswith(".apk"):
            findings.append(_finding("URL-08"))
        return findings
    except ValueError:
        pass

    reg = registered_domain(host)
    reg_plain = registered_domain(host.translate(LEET))  # b1t.ly -> bit.ly
    tld = host.rsplit(".", 1)[-1]
    trusted = _is_official(reg)

    if reg in SHORTENERS or reg_plain in SHORTENERS:
        findings.append(_finding("URL-02"))
    if tld in SUSPICIOUS_TLDS:
        findings.append(_finding("URL-03", tld=tld))
    if "xn--" in host:
        findings.append(_finding("URL-04"))
    if "@" in parsed.netloc:
        findings.append(_finding("URL-05"))
    if explicit_http:
        findings.append(_finding("URL-06"))
    if host.count(".") >= 4:
        findings.append(_finding("URL-07"))
    if parsed.path.lower().endswith(".apk"):
        findings.append(_finding("URL-08"))
    if trusted:
        return findings

    if host.count("-") >= 3:
        findings.append(_finding("URL-11"))
    if reg in FREE_HOSTING:
        findings.append(_finding("URL-13"))

    tokens = [t for t in re.split(r"[.\-_]", host) if t]
    brand_hit = False
    for token in tokens:
        brand = _brand_of(token)
        if brand:
            findings.append(_finding("URL-09", brand=brand, official=", ".join(sorted(BRANDS[brand]))))
            brand_hit = True
            break
    if not brand_hit:
        for token in tokens:
            plain = token.translate(LEET)
            for brand in BRANDS:
                if len(brand) >= 5 and token != brand and (plain == brand or _edit1(plain, brand)):
                    findings.append(_finding("URL-10", brand=brand))
                    brand_hit = True
                    break
            if brand_hit:
                break

    lure = next((t for t in tokens if t in LURE_WORDS), None)
    if lure:
        findings.append(_finding("URL-12", word=lure))
    return findings
