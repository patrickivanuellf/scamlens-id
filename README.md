# ScamLens ID

Pendeteksi pesan dan tautan penipuan berbahasa Indonesia. Tempel teks WhatsApp/SMS atau sebuah URL,
dapatkan **skor risiko 0-100** beserta **alasan yang bisa dibaca** dalam bahasa Indonesia.

![CI](https://github.com/patrickivanuellf/scamlens-id/actions/workflows/ci.yml/badge.svg)

## Kenapa proyek ini?

Menurut data BSSN, Indonesia menghadapi sekitar 5,5 miliar serangan siber sepanjang 2025, dan
OJK/Indonesia Anti-Scam Centre mencatat kerugian penipuan transaksi keuangan Rp9,1 triliun
sejak 2024 sampai Januari 2026. Modus yang dominan menyasar pengguna biasa: phishing, APK jahat
berkedok kurir/undangan, hadiah dan THR palsu, serta permintaan OTP. ScamLens ID membantu
mengenali pola itu sebelum korban mengklik.

## Cara pakai

```bash
pip install -e ".[dev]"

scamlens check "Selamat Anda menang! Install aplikasi di http://jne-cek.xyz/foto.apk lalu kirim OTP"
scamlens check --file pesan.txt --json
```

Contoh keluaran:

```
[BAHAYA] Skor risiko: 93/100 (tinggi)
  - [OTP-01] Meminta OTP/PIN/kata sandi. Layanan resmi tidak pernah memintanya.
  - [URL-08] Tautan mengunduh file APK langsung.
  - [URL-09] Domain memuat nama 'jne' tetapi bukan domain resmi (jne.co.id).
```

Kode keluar CLI: `0` = risiko rendah, `1` = sedang/tinggi (berguna untuk skrip).

## Cara kerja

1. **Aturan teks** (`rules.py`): regex pola modus Indonesia, masing-masing dengan bobot dan penjelasan.
2. **Analisis URL** (`url_analyzer.py`): IP-host, shortener, TLD mencurigakan, punycode, `@`,
   APK langsung, dan peniruan merek (typosquatting) terhadap daftar domain resmi.
3. **Skor** (`scorer.py`): bobot digabung dengan rumus `1 - Π(1 - w/100)` sehingga tidak pernah
   melebihi 100 dan temuan tambahan menaikkan skor dengan imbal hasil menurun.

Detail: [docs/architecture.md](docs/architecture.md).

## Pengembangan

```bash
pytest --cov=scamlens
ruff check .
```

## Batasan dan etika

- Alat ini **defensif**: hanya menganalisis teks/URL, tidak menjalankan file atau mengunjungi tautan.
- Berbasis heuristik, jadi bisa **false positive/negative**. Skor bukan vonis; selalu verifikasi lewat kanal resmi.
- Daftar merek dan domain resmi hanyalah contoh dan perlu diverifikasi ulang secara berkala.
- Jangan memasukkan data pribadi asli ke dalam dataset atau issue publik.

## Roadmap

- [ ] Cek umur domain (WHOIS/RDAP)
- [ ] Analisis statis APK (izin berbahaya, nama paket menyamar)
- [ ] Klasifikasi ML ringan (TF-IDF + logistic regression) dengan evaluasi vs baseline aturan
- [ ] REST API (FastAPI) dan halaman web
- [ ] Bot Telegram sebagai demo

## Lisensi

MIT
