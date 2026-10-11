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

## Instalasi

```bash
pip install -e ".[dev]"      # Python >= 3.10, tanpa dependensi runtime
```

## Cara pakai

```bash
scamlens check "Akun Anda diblokir! Verifikasi segera di bca-verif.top/login"
scamlens check --file pesan.txt --json
echo "pesan mencurigakan" | scamlens check
scamlens batch pesan.txt            # satu pesan per baris (atau .jsonl dengan kunci "text")
scamlens rules                      # semua aturan beserta bobotnya
scamlens eval data/eval/pesan_uji.csv --errors
```

Contoh keluaran:

```
[BAHAYA] Skor risiko: 77/100 (tinggi) [###############-----]
Temuan:
  - [URL-09] Domain memuat nama 'bca' tetapi bukan domain resmi (bca.co.id, klikbca.com).  (+40)
      bukti: 'bca-verif.top/login'
  - [ACC-01] Mengancam akun/rekening akan diblokir, pola khas phishing.  (+25)
      bukti: 'Akun Anda diblokir'
  - [URL-03] Ekstensi domain .top sering dipakai situs penipuan.  (+25)
  ...
Jangan klik tautan, jangan kirim OTP/PIN, dan verifikasi lewat kanal resmi. Laporkan ke aduankonten.id ...
```

Kalimat peringatan tidak dianggap penipuan:

```
$ scamlens check "Jangan berikan kode OTP kepada siapa pun."
[AMAN?] Skor risiko: 0/100 (rendah) [--------------------]
Catatan: Pola OTP-01 disebut dalam kalimat peringatan ('jangan berikan ...'), sehingga tidak dihitung ...
```

### Kode keluar (untuk skrip/CI)

| Kode | Arti |
|---|---|
| `0` | risiko di bawah ambang |
| `1` | risiko >= ambang (`--fail-on sedang` default, atau `tinggi`, atau `never`) |
| `2` | kesalahan pemakaian (file tidak ada, teks kosong, dataset rusak) |

Berlaku sama untuk mode `--json`. Tambahkan `--no-color` atau set `NO_COLOR` untuk mematikan warna.

## Cara kerja

1. **Normalisasi** (`normalize.py`): membongkar `S3L4M4T`, `O T P`, huruf fullwidth/Cyrillic, huruf berulang. URL dibiarkan utuh.
2. **Aturan teks** (`rules.py`): 27 regex pola modus Indonesia, masing-masing dengan bobot dan penjelasan.
   Aturan "permintaan" (OTP, APK, hadiah, ...) tidak dihitung bila muncul dalam kalimat larangan
   ("jangan berikan ...", "pihak bank tidak pernah meminta ...").
3. **Analisis URL** (`url_analyzer.py`): domain dengan atau tanpa `http://`, IP-host, shortener, TLD
   mencurigakan, punycode, `@`, APK langsung, peniruan merek (`bca-verif.top`, `klikbca-login.icu`),
   salah ketik merek (`tokopedla`), kata pancingan, dan hosting gratis. Tidak pernah membuka URL.
4. **Skor** (`scorer.py`): bobot digabung dengan `1 - Π(1 - w/100)` sehingga tidak pernah melebihi 100.
   Ambang: `sedang >= 25`, `tinggi >= 55`.

Detail: [docs/architecture.md](docs/architecture.md).

## Evaluasi

Mesin diukur dengan `scamlens eval` pada dataset sintetis berlabel (lihat [data/eval/](data/eval/README.md)).
Positif = level `sedang` atau `tinggi`.

| Set | Mesin v0.1 (sebelum) | Mesin v0.2 (sekarang) | Catatan |
|---|---|---|---|
| `pesan_uji.csv` (214 pesan) | P 89% / R 64% | P 100% / R 100% | **Optimistis**: aturan disusun sambil melihat set ini |
| `pesan_buta.csv` (60 pesan, dibekukan) | P 82% / R 30% | **P 100% / R 73%** | Angka yang lebih jujur, tidak dipakai menyetel aturan |

Angka di atas **bukan klaim akurasi di dunia nyata**. Dataset sintetis buatan penulis aturan lebih mudah
daripada pesan nyata, dan set buta pun ditulis oleh orang yang sama. Anggap recall dunia nyata bisa
lebih rendah dari 73%. Langkah berikutnya yang paling berharga adalah menambah **pesan asli yang
sudah dianonimkan**.

### Batasan yang diketahui (dari kegagalan di set buta)

- "Kirimkan **6 angka** yang masuk ke SMS" (sinonim "kode OTP") belum dikenali.
- Biaya di muka yang disebut tanpa kata "transfer" (mis. "bayar biaya materai dan asuransi dulu").
- Permintaan **voucher/gift card** dari "bos" palsu.
- Lowongan/peluang usaha tanpa gaji eksplisit ("untung jutaan per bulan", "gaji per jam").
- Janji saldo berlipat ("transfer 100 ribu, saldo jadi 1 juta") tanpa kata "profit/untung".
- Penipuan yang hanya bergantung pada konteks (mis. pesan keluarga yang meminta transfer tanpa
  kata kunci) memang sulit tanpa ML dan data nyata.

## Pengembangan

```bash
pytest --cov=scamlens
ruff check .
scamlens eval data/eval/pesan_uji.csv --split dev --errors   # lihat apa yang meleset
```

CI menjalankan tes, lint, dan `scamlens eval` dengan ambang minimal (precision 0,95 / recall 0,90).
Saat menambah aturan: setel dari kesalahan `dev`, jangan menambal ke `pesan_buta.csv`.

## Batasan dan etika

- Alat ini **defensif**: hanya menganalisis teks/URL, tidak menjalankan file atau mengunjungi tautan.
- Berbasis heuristik, jadi bisa **false positive/negative**. Skor bukan vonis; selalu verifikasi lewat kanal resmi.
- Daftar merek dan domain resmi (`url_analyzer.BRANDS`) hanyalah contoh dan perlu diverifikasi ulang secara berkala.
- Jangan memasukkan data pribadi asli ke dalam dataset atau issue publik.

## Roadmap

- [x] Dataset uji berlabel dan perintah `scamlens eval`
- [x] Normalisasi anti-penyamaran, konteks negasi, domain tanpa skema
- [ ] Tutup batasan di atas dengan set buta baru
- [ ] Bot Telegram (memanggil `analyze_text` langsung)
- [ ] REST API (FastAPI) dan ekstensi Chrome
- [ ] Cek umur domain (WHOIS/RDAP)
- [ ] Analisis statis APK (izin berbahaya, nama paket menyamar)
- [ ] Klasifikasi ML ringan (TF-IDF + logistic regression) dibandingkan dengan baseline aturan

## Lisensi

MIT
