import pytest

from scamlens import analyze_text

PERINGATAN = [
    "Kode OTP Anda 482913. Jangan berikan kode ini kepada siapa pun termasuk pihak bank.",
    "Waspada penipuan! Pihak bank tidak pernah meminta PIN, OTP, atau kata sandi Anda.",
    "Ingat: jangan klik tautan mencurigakan dan jangan kirim OTP kepada siapa pun.",
    "Hati-hati modus penipuan APK. Jangan pernah install aplikasi dari link WhatsApp.",
]

PENIPUAN = [
    "Jangan khawatir, kirim OTP Anda sekarang agar akun tidak diblokir.",
    "Jangan sampai akun Anda diblokir, kirim kode OTP segera.",
    "Jangan abaikan pesan ini! Install aplikasi di http://kurir-cek.xyz/paket.apk",
]


@pytest.mark.parametrize("text", PERINGATAN)
def test_kalimat_peringatan_tidak_dianggap_penipuan(text):
    assert analyze_text(text).level == "rendah"


@pytest.mark.parametrize("text", PENIPUAN)
def test_negasi_palsu_tidak_melonggarkan_deteksi(text):
    assert analyze_text(text).level != "rendah"


def test_catatan_menjelaskan_pola_yang_dilewati():
    r = analyze_text("Jangan berikan kode OTP kepada siapa pun.")
    assert any("OTP-01" in n for n in r.notes)
