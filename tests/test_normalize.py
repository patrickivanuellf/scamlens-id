from scamlens.normalize import normalize_text


def test_leetspeak_dibongkar():
    assert normalize_text("S3L4M4T m3nang h4diah").lower() == "selamat menang hadiah"
    assert "otp" in normalize_text("kirim 0tp").lower()


def test_huruf_dipisah_digabung():
    assert normalize_text("Kirim O T P sekarang") == "Kirim OTP sekarang"
    assert "MENANG" in normalize_text("Anda M.E.N.A.N.G undian")


def test_fullwidth_dan_homoglyph():
    assert normalize_text("\uff33\uff45\uff4c\uff41\uff4d\uff41\uff54") == "Selamat"
    assert normalize_text("h\u0430diah") == "hadiah"  # 'а' Cyrillic


def test_huruf_berulang_dan_spasi_nol_lebar():
    assert normalize_text("segeraaa") == "segera"
    assert normalize_text("ha\u200bdiah") == "hadiah"


def test_angka_dan_satuan_tidak_diubah():
    text = "Rp 50jt, 10rb, 24jam, 20.000"
    assert normalize_text(text) == text


def test_url_dibiarkan_utuh():
    url = "https://b1t.ly/h4diah-1d"
    assert url in normalize_text(f"klik {url} sekarang")
