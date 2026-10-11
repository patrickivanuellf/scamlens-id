from scamlens import analyze_text


def test_pesan_penipuan_apk_kurir_berisiko_tinggi():
    text = ("Paket Anda tertahan. Segera install aplikasi kurir di "
            "http://jne-cek.xyz/foto-paket.apk lalu kirim kode OTP.")
    r = analyze_text(text)
    assert r.level == "tinggi"
    ids = {f.id for f in r.findings}
    assert {"APK-01", "OTP-01", "URL-08"} <= ids


def test_hadiah_dan_biaya_di_muka():
    r = analyze_text("Selamat Anda menang undian! Transfer biaya admin dulu untuk klaim hadiah.")
    assert r.score >= 55


def test_pesan_biasa_berisiko_rendah():
    r = analyze_text("Besok rapat jam 10 di kantor ya, jangan lupa bawa laptop.")
    assert r.level == "rendah"
    assert r.findings == []


def test_skor_tidak_melebihi_100():
    text = "Selamat Anda menang! Segera kirim OTP, install apk, akun diblokir, transfer dulu."
    assert analyze_text(text).score <= 100


def test_obfuscation_tetap_terdeteksi():
    assert analyze_text("S3L4M4T anda m3nang h4diah! kirim O T P segera").level != "rendah"


def test_domain_tanpa_skema_ikut_dinilai():
    assert analyze_text("Cek ini bit.ly/3AbCdEf").level == "sedang"


def test_promo_toko_resmi_tidak_dianggap_hadiah_palsu():
    assert analyze_text("Hadiah ulang tahun untuk member kami: potongan 10% di semua gerai.").level == "rendah"


def test_teks_sangat_panjang_dipotong():
    r = analyze_text("a " * 30000)
    assert any("dipotong" in n for n in r.notes)


def test_advice_apk_berisi_langkah_pemulihan():
    r = analyze_text("Install aplikasi di http://jne-cek.xyz/foto.apk")
    assert "mode pesawat" in r.advice
