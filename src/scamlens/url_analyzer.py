"""Analisis heuristik untuk URL: typosquatting, shortener, TLD mencurigakan, dsb."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')]+", re.IGNORECASE)

SHORTENERS = {"bit.ly", "tinyurl.com", "s.id", "t.ly", "cutt.ly", "is.gd", "rb.gy", "shorturl.at"}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "icu", "cfd", "sbs", "cyou", "monster", "buzz", "live"}
SECOND_LEVEL_ID = {"co", "go", "ac", "or", "web", "my", "sch", "mil", "net"}

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
    "taspen": {"taspen.co.id"},
    "pajak": {"pajak.go.id"},
}


@dataclass(frozen=True)
class UrlFinding:
    id: str
    weight: int
    explanation: str


def extract_urls(text: str) -> list[str]:
    return [u.rstrip(".,;") for u in URL_RE.findall(text)]


def registered_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and labels[-1] == "id" and labels[-2] in SECOND_LEVEL_ID:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def analyze_url(url: str) -> list[UrlFinding]:
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    findings: list[UrlFinding] = []
    if not host:
        return findings

    try:
        ipaddress.ip_address(host)
        findings.append(UrlFinding("URL-01", 35, "Tautan memakai alamat IP, bukan nama domain."))
        return findings
    except ValueError:
        pass

    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1]

    if reg in SHORTENERS:
        findings.append(UrlFinding("URL-02", 20, "Tautan dipendekkan sehingga tujuan asli tersembunyi."))
    if tld in SUSPICIOUS_TLDS:
        findings.append(UrlFinding("URL-03", 20, f"Ekstensi domain .{tld} sering dipakai situs penipuan."))
    if "xn--" in host:
        findings.append(UrlFinding("URL-04", 30, "Domain memakai punycode, bisa meniru huruf yang mirip."))
    if "@" in parsed.netloc:
        findings.append(UrlFinding("URL-05", 30, "Ada karakter '@' untuk menyamarkan tujuan sebenarnya."))
    if parsed.scheme == "http":
        findings.append(UrlFinding("URL-06", 8, "Tautan tidak memakai HTTPS."))
    if host.count(".") >= 4:
        findings.append(UrlFinding("URL-07", 15, "Terlalu banyak subdomain."))
    if parsed.path.lower().endswith(".apk"):
        findings.append(UrlFinding("URL-08", 45, "Tautan mengunduh file APK langsung."))

    tokens = set(re.split(r"[.\-_]", host))
    for brand, official in BRANDS.items():
        if brand in tokens and reg not in official:
            findings.append(UrlFinding(
                "URL-09", 40,
                f"Domain memuat nama '{brand}' tetapi bukan domain resmi ({', '.join(sorted(official))}).",
            ))
            break
    return findings
