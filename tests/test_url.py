from scamlens.url_analyzer import analyze_url, extract_urls, registered_domain


def ids(url):
    return {f.id for f in analyze_url(url)}


def test_domain_resmi_tidak_ditandai_merek():
    assert "URL-09" not in ids("https://www.bca.co.id/id/beranda")
    assert "URL-09" not in ids("https://bankmandiri.co.id/")


def test_typosquatting_merek():
    assert "URL-09" in ids("http://bca-klaim-hadiah.top/login")


def test_ip_shortener_dan_tld():
    assert "URL-01" in ids("http://192.168.10.5/login")
    assert "URL-02" in ids("https://bit.ly/abc123")
    assert "URL-03" in ids("https://promo-lebaran.xyz")


def test_registered_domain_id():
    assert registered_domain("www.bpjs-kesehatan.go.id") == "bpjs-kesehatan.go.id"
    assert registered_domain("a.b.example.com") == "example.com"


def test_ekstraksi_url():
    urls = extract_urls("Klik https://a.xyz/x, atau www.contoh.id/y.")
    assert urls == ["https://a.xyz/x", "www.contoh.id/y"]


def test_domain_tanpa_skema_terdeteksi():
    urls = extract_urls("Cek bit.ly/3AbCdEf dan bca-verif.top/login ya")
    assert urls == ["bit.ly/3AbCdEf", "bca-verif.top/login"]


def test_email_bukan_url():
    assert extract_urls("Kirim CV ke hrd@perusahaan.co.id sebelum Jumat") == []


def test_shortener_dengan_leetspeak():
    assert "URL-02" in ids("https://b1t.ly/abc")


def test_merek_dengan_imbuhan_dan_salah_ketik():
    assert "URL-09" in ids("http://klikbca-login.icu")
    assert "URL-10" in ids("https://tokopedla-secure.top/batal")


def test_domain_pemerintah_dipercaya():
    assert ids("https://ppdb.jatengprov.go.id/pengumuman") == set()


def test_kata_pancingan_dan_hosting_gratis():
    assert "URL-12" in ids("https://klaim-hadiah.xyz")
    assert "URL-13" in ids("https://promo.github.io/login")


def test_http_hanya_ditandai_bila_skema_eksplisit():
    assert "URL-06" in ids("http://contoh-aman.com/a")
    assert "URL-06" not in ids("contoh-aman.com/a")
    assert "URL-06" not in ids("https://contoh-aman.com/a")
