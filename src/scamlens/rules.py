"""Aturan deteksi pola penipuan yang umum di Indonesia.

Setiap aturan berisi pola regex, bobot risiko (0-100), dan penjelasan yang
ditampilkan ke pengguna. Bobot adalah kontribusi awal; skor akhir digabung di scorer.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern: re.Pattern[str]
    weight: int
    explanation: str


def _r(id_: str, category: str, pattern: str, weight: int, explanation: str) -> Rule:
    return Rule(id_, category, re.compile(pattern, re.IGNORECASE), weight, explanation)


RULES: list[Rule] = [
    _r("URG-01", "urgensi",
       r"\b(segera|sekarang juga|hari ini juga|batas waktu|dalam \d+ ?(jam|menit))\b",
       12, "Memakai tekanan waktu agar korban tidak sempat berpikir."),
    _r("ACC-01", "ancaman akun",
       r"(akun|rekening|kartu|nomor).{0,25}(diblokir|dibekukan|ditangguhkan|ditutup|bermasalah)",
       25, "Mengancam akun/rekening akan diblokir, pola khas phishing."),
    _r("HDH-01", "hadiah palsu",
       r"(selamat.{0,40}(menang|terpilih)|anda (menang|terpilih)|undian|hadiah)",
       30, "Mengklaim korban memenangkan hadiah atau undian."),
    _r("OTP-01", "minta data rahasia",
       r"(kirim|berikan|sebutkan|masukkan|input|konfirmasi).{0,30}"
       r"(otp|pin|cvv|kode verifikasi|kode rahasia|password|kata sandi)",
       45, "Meminta OTP/PIN/kata sandi. Layanan resmi tidak pernah memintanya."),
    _r("APK-01", "file APK",
       r"\.apk\b|(pasang|install|instal|unduh|download).{0,25}(apk|aplikasi)",
       40, "Mengajak memasang aplikasi/APK di luar toko resmi, modus malware."),
    _r("KUR-01", "kurir/undangan palsu",
       r"(foto paket|resi pengiriman|surat tilang|undangan (pernikahan|digital)|lihat dokumen)",
       20, "Memakai tema kurir/undangan/tilang yang sering dipakai menyebar APK jahat."),
    _r("THR-01", "bantuan palsu",
       r"\b(thr|bansos|bantuan sosial|pencairan dana|subsidi)\b",
       20, "Memakai tema THR/bansos/pencairan dana yang sering dipalsukan."),
    _r("DON-01", "donasi palsu",
       r"(donasi|sumbangan|infaq|sedekah).{0,40}(transfer|rekening|segera)",
       20, "Meminta donasi lewat transfer pribadi, perlu diverifikasi."),
    _r("IMP-01", "peniruan pihak resmi",
       r"(pihak|petugas|admin|customer service|cs)\s+(bank|bca|bri|bni|mandiri|bpjs|pajak|ojk|polisi|kurir)",
       25, "Mengaku sebagai petugas/lembaga resmi."),
    _r("TRF-01", "biaya di muka",
       r"(transfer|top ?up|biaya (admin|administrasi|pajak)).{0,30}"
       r"(dulu|terlebih dahulu|agar|untuk (mencairkan|klaim))",
       40, "Meminta biaya di muka untuk mencairkan hadiah/dana."),
    _r("JDL-01", "judi/pinjol",
       r"\b(slot gacor|togel|maxwin|pinjol|pinjaman cepat)\b",
       20, "Menawarkan judi online atau pinjaman ilegal."),
]
