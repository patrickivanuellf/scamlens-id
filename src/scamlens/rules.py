"""Aturan deteksi pola penipuan yang umum di Indonesia.

Setiap aturan berisi pola regex, bobot risiko (0-100), dan penjelasan yang ditampilkan ke
pengguna. Bobot adalah kontribusi awal; skor akhir digabung di scorer.py.

Aturan bertanda ``negatable`` tidak dihitung bila pola muncul dalam kalimat peringatan,
misalnya "Jangan berikan kode OTP kepada siapa pun" atau "Pihak bank tidak pernah meminta PIN".
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
    negatable: bool = False


def _r(id_: str, category: str, pattern: str, weight: int, explanation: str,
       negatable: bool = False) -> Rule:
    return Rule(id_, category, re.compile(pattern, re.IGNORECASE), weight, explanation, negatable)


_BRANDS = (r"bank|bca|bri|bni|mandiri|bpjs|pajak|djp|ojk|polisi|kepolisian|kurir|shopee|tokopedia|"
           r"dana|gopay|ovo|telkomsel|operator(?: seluler)?|pln|indomaret|alfamart")

RULES: list[Rule] = [
    _r("URG-01", "urgensi",
       r"\b(segera|sekarang juga|hari ini juga|detik ini|batas waktu|kesempatan terakhir|buruan|"
       r"cepat sebelum|sebelum (?:kadaluarsa|hangus|ditutup|terlambat)|dalam \d+ ?(?:jam|menit))\b",
       12, "Memakai tekanan waktu agar korban tidak sempat berpikir."),
    _r("ACC-01", "ancaman akun",
       r"(?:akun|rekening|kartu|nomor|kuota|saldo|listrik|bpjs).{0,25}"
       r"(?:diblokir|dibekukan|ditangguhkan|ditutup|bermasalah|dinonaktifkan|dihapus|diputus|"
       r"terblokir|terkena pembekuan)|(?:blokir|pembekuan|penutupan) (?:akun|rekening|kartu)",
       25, "Mengancam akun/rekening akan diblokir, pola khas phishing."),
    _r("HDH-01", "hadiah palsu",
       r"selamat.{0,40}(?:menang|terpilih|pemenang)|anda (?:telah |berhasil )?(?:menang|terpilih)|"
       r"anda mendapat(?:kan)? hadiah|pemenang (?:undian|giveaway|hadiah)|"
       r"(?:kamu|anda|nomor anda|nomormu) (?:beruntung|menang|terpilih)|"
       r"menang (?:undian|lotere|giveaway|hadiah)",
       30, "Mengklaim korban memenangkan hadiah atau undian.", True),
    _r("HDH-02", "hadiah palsu",
       r"(?:klaim|cairkan|ambil|tukar)\s+(?:segera\s+)?(?:hadiah|bonus|saldo|cashback|voucher|iphone|poin)|"
       r"hadiah.{0,25}(?:menunggu|siap diklaim|belum diklaim)|"
       r"(?:saldo|bonus|cashback).{0,30}berhasil diklaim|"
       r"(?:voucher|pulsa|kuota|saldo|bonus|cashback).{0,30}gratis",
       25, "Menawarkan hadiah/saldo gratis yang harus 'diklaim', umpan umum penipuan.", True),
    _r("OTP-01", "minta data rahasia",
       r"(?:kirim|mengirim|berikan|sebutkan|menyebutkan|masukkan|input|konfirmasi|mengonfirmasi|beritahu|"
       r"bagikan|sampaikan|teruskan|meneruskan)"
       r".{0,35}(?:otp|\bpin\b|cvv|kode\s+(?:verifikasi|rahasia|keamanan|otp|\d+\s*digit)|"
       r"\d+\s*digit|password|kata sandi)",
       45, "Meminta OTP/PIN/kata sandi. Layanan resmi tidak pernah memintanya.", True),
    _r("DAT-01", "minta data pribadi",
       r"(?:kirim|mengirim|kirimkan|unggah|mengunggah|upload|foto|lampirkan|melampirkan|berikan|sertakan|"
       r"isi data|isi|mengisi|lengkapi)"
       r".{0,40}(?:ktp|kartu keluarga|\bkk\b|npwp|selfie|swafoto|kartu atm|nomor kartu|data rekening)|"
       r"\bkyc\b.{0,30}(?:wajib|unggah|upload|update)",
       30, "Meminta foto KTP/selfie/data rekening yang dipakai untuk pembobolan akun.", True),
    _r("APK-01", "file APK",
       r"\.apk\b|(?:pasang|install|instal|unduh|download|memasang|mengunduh).{0,25}(?:apk|aplikasi)"
       r"(?!.{0,40}(?:play store|app ?store|google play))",
       40, "Mengajak memasang aplikasi/APK di luar toko resmi, modus malware.", True),
    _r("KUR-01", "kurir/undangan palsu",
       r"foto paket|resi pengiriman|surat (?:tilang|panggilan)|e-?tilang|"
       r"undangan (?:pernikahan|digital)|lihat dokumen|bea cukai|"
       r"(?:paket|barang).{0,20}(?:tertahan|gagal (?:dikirim|diantar)|tidak dapat dikirim|bermasalah)|"
       r"alamat.{0,15}(?:tidak lengkap|tidak ditemukan)|konfirmasi (?:alamat|penerimaan)",
       20, "Memakai tema kurir/undangan/tilang yang sering dipakai menyebar APK jahat.", True),
    _r("THR-01", "bantuan palsu",
       r"\b(?:thr|bansos|bantuan sosial|pencairan dana|subsidi|dana (?:bantuan|hibah)|program bantuan)\b",
       20, "Memakai tema THR/bansos/pencairan dana yang sering dipalsukan."),
    _r("DON-01", "donasi palsu",
       r"(?:donasi|sumbangan|infaq|sedekah).{0,40}(?:transfer|rekening pribadi|segera)",
       20, "Meminta donasi lewat transfer pribadi, perlu diverifikasi."),
    _r("IMP-01", "peniruan pihak resmi",
       rf"\b(?:pihak|petugas|admin|customer service|cs|perwakilan|hrd)\s+(?:{_BRANDS})\b|"
       rf"\b(?:saya|kami)\s+(?:dari|adalah)\s+(?:tim\s+|petugas\s+|admin\s+)?(?:{_BRANDS})\b",
       20, "Mengaku sebagai petugas/lembaga resmi.", True),
    _r("TRF-01", "biaya di muka",
       r"(?:transfer|top ?up|setor|biaya (?:admin(?:istrasi)?|pajak|asuransi|deposit)|pajak hadiah|deposit)"
       r".{0,45}(?:dulu|terlebih dahulu|lebih dulu|agar|supaya|"
       r"untuk (?:mencairkan|pencairan|klaim|mengklaim|aktivasi))",
       40, "Meminta biaya di muka untuk mencairkan hadiah/dana.", True),
    _r("JDL-01", "judi/pinjol",
       r"\b(?:slot gacor|gacor|maxwin|togel|judi (?:online|bola)|pinjol|pinjaman (?:cepat|online|kilat)|"
       r"tanpa (?:bi checking|slik|survei|agunan)|pinjaman.{0,25}tanpa jaminan|dana cepat)\b",
       25, "Menawarkan judi online atau pinjaman ilegal."),
    _r("LOK-01", "lowongan palsu",
       r"(?:kerja|bekerja|part ?time|freelance|loker|lowongan|pekerjaan)[^.!?\n]{0,70}?"
       r"(?:gaji|komisi|penghasilan|dibayar)[^.!?\n]{0,40}?"
       r"(?:per (?:hari|minggu|tugas|jam)|harian|\d+\s?(?:jt|juta|rb|ribu)|rp\s?\d)",
       30, "Lowongan dengan gaji/komisi tinggi dan syarat ringan, ciri penipuan kerja online."),
    _r("LOK-02", "lowongan palsu",
       r"dibayar harian|kerja (?:online|dari rumah)|part ?time online|tanpa pengalaman|modal hp|"
       r"klik iklan|like (?:&|dan) subscribe|anda lolos seleksi|diterima kerja",
       25, "Memakai frasa khas lowongan kerja online palsu."),
    _r("INV-01", "investasi bodong",
       r"(?:profit|keuntungan|untung|cuan|bunga|imbal hasil|penghasilan pasif|bagi hasil)"
       r".{0,40}(?:pasti|dijamin|\d+\s?%\s*(?:per|setiap|/)\s*(?:hari|minggu|bulan)|per hari|harian|"
       r"tanpa risiko)|(?:dijamin|pasti) (?:untung|profit|cuan|aman)|(?:tanpa|bebas) risiko|modal kecil",
       35, "Menjanjikan keuntungan pasti/tinggi tanpa risiko, ciri investasi bodong."),
    _r("INV-02", "investasi bodong",
       r"deposit.{0,30}(?:profit|untung|keuntungan)|robot trading|bot trading",
       35, "Pola deposit lalu 'profit' cepat, khas investasi/judi bodong."),
    _r("FAM-01", "penyamaran keluarga",
       r"(?:nomor|no\.?|wa|hp|handphone)(?:\s*(?:wa|hp|ku|saya|aku))*\s*(?:yang\s+)?(?:baru|lama)\b|"
       r"ganti (?:nomor|hp)|nomor (?:wa )?(?:lama )?(?:hilang|rusak|diblokir)|hp\s?(?:ku|saya|aku)? ?rusak|"
       r"pakai nomor (?:teman|orang)|simpan nomor (?:ini|baru)",
       20, "Mengaku keluarga yang ganti nomor, pembuka penipuan 'mama minta pulsa'."),
    _r("FAM-02", "permintaan uang mendadak",
       r"tolong (?:transfer|isi pulsa|bayarin|bayarkan|talangi|transferin|kirim(?:in)? uang)|"
       r"pinjam uang|bisa pinjam|butuh (?:biaya|uang|dana)",
       20, "Meminta transfer/pulsa/pinjaman uang secara mendadak."),
    _r("FAM-03", "darurat palsu",
       r"(?:kecelakaan|musibah|dirawat|ditahan).{0,60}(?:biaya|uang|transfer|dana)",
       25, "Mengarang keadaan darurat untuk meminta uang."),
    _r("LNK-01", "ajakan klik",
       r"(?:klik|buka|kunjungi|akses|tekan|unduh|download|cek).{0,25}(?:link|tautan|url|situs|di sini|disini|berikut)",
       10, "Mengajak membuka tautan."),
    _r("CON-01", "pindah kanal",
       r"(?:hubungi|chat|kontak|konfirmasi|daftar)\b.{0,30}"
       r"(?:admin|panitia|agen|petugas|\bwa\b|whatsapp|telegram|wa\.me|t\.me)",
       15, "Mengarahkan korban ke kontak/grup pribadi di luar kanal resmi."),
    _r("TAR-01", "perubahan tarif palsu",
       r"(?:perubahan|kenaikan|skema|penyesuaian)\s+(?:tarif|biaya)\s+(?:transfer|transaksi|admin)|"
       r"tarif (?:transfer|transaksi) baru|biaya.{0,20}rp\s?\d[\d.]*\s?/\s?transaksi|"
       r"migrasi.{0,25}(?:skema|tarif|nasabah)",
       35, "Isu 'perubahan tarif/migrasi nasabah' yang dipakai untuk mencuri akses m-banking."),
    _r("BAL-01", "minta balasan",
       r"balas\s+(?:ya|setuju|tidak|ok|y)\b.{0,50}(?:atau|untuk)|(?:ketik|balas)\s+(?:ya|setuju)\b",
       25, "Meminta balasan 'YA/TIDAK' sebagai persetujuan palsu."),
    _r("LGL-01", "ancaman hukum/tagihan",
       r"(?:dipanggil|dilaporkan|dilacak).{0,30}(?:polisi|kepolisian|kejaksaan|pengadilan|saksi)|"
       r"pencucian uang|terlibat (?:kasus|kejahatan)|"
       r"(?:pelanggaran|melanggar) lalu lintas.{0,40}denda|tunggakan.{0,25}(?:denda|pajak|bpjs|listrik)|menunggak",
       25, "Mengancam dengan proses hukum atau tunggakan agar korban panik."),
    _r("AKS-01", "verifikasi akun palsu",
       r"verifikasi.{0,20}(?:akun|data|identitas|nasabah)|(?:perbarui|update|pembaruan|migrasi)\s+"
       r"(?:data|aplikasi|akun|kyc)|konfirmasi identitas|akun.{0,30}(?:dilaporkan|melanggar)",
       20, "Meminta 'verifikasi/pembaruan' data akun, pola umum phishing."),
    _r("RFD-01", "refund/cashback palsu",
       r"(?:refund|pengembalian (?:dana|pajak)|kelebihan bayar|cashback)"
       r".{0,60}(?:login|klik|isi|masukkan|data rekening)",
       25, "Menjanjikan refund/cashback asal korban login atau mengisi data."),
]

# ---------------------------------------------------------------- konteks negasi

_CLAUSE_BREAK = re.compile(r"[.,;:!?\n]")
_NEG_WORD = re.compile(
    r"\b(?:jangan|dilarang|hindari|tidak boleh|waspada|hati-hati|awas|never|do not|don't)\b", re.IGNORECASE)
_NEG_AFTER = re.compile(r"^\s*(?:\w+\s+){0,2}(?:tidak|tak|belum)\s+(?:pernah|akan)\b", re.IGNORECASE)


def is_negated(text: str, start: int, end: int) -> bool:
    """True bila pola di ``text[start:end]`` muncul dalam kalimat larangan/peringatan."""
    clause = _CLAUSE_BREAK.split(text[max(0, start - 60):start])[-1]
    if _NEG_WORD.search(clause) or _NEG_WORD.search(text[start:end]):
        return True
    return bool(_NEG_AFTER.match(text[end:end + 40]))
