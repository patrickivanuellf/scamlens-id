# Arsitektur ScamLens ID

```
input (teks / URL / stdin / file)
        │
        ▼
 ┌────────────────┐
 │ normalize.py   │  NFKC, leetspeak, "O T P", huruf berulang (URL dibiarkan utuh)
 └───────┬────────┘
         ▼
 ┌──────────────┐  ┌──────────────────────────────┐
 │ rules.py     │  │ url_analyzer.py              │
 │ regex+bobot  │  │ heuristik URL (dengan/tanpa  │
 │ + negasi     │  │ skema), merek, TLD, shortener│
 └──────┬───────┘  └──────────────┬───────────────┘
        └────────────┬────────────┘
                     ▼
        scorer.py → Result(score, level, findings, urls, advice, notes)
                     ▼
   cli.py: check | batch | rules | eval       [nanti: api.py, bot.py]
                     ▲
        evaluate.py (dataset berlabel → precision/recall)
```

## Threat model singkat

| Modus | Sinyal yang dideteksi | Aturan |
|---|---|---|
| APK berkedok kurir/undangan/tilang | ajakan install, tema kurir, URL .apk | APK-01, KUR-01, URL-08 |
| Phishing bank/e-wallet | ancaman blokir, peniruan petugas, domain mirip merek | ACC-01, IMP-01, AKS-01, URL-09, URL-10 |
| Hadiah/undian/THR/bansos palsu | klaim menang, tema bantuan | HDH-01, HDH-02, THR-01 |
| Penipuan biaya di muka | transfer dulu untuk klaim | TRF-01 |
| Pencurian kredensial | permintaan OTP/PIN/kata sandi/KTP | OTP-01, DAT-01 |
| Donasi palsu | transfer ke rekening pribadi | DON-01 |
| Lowongan kerja & investasi palsu | gaji/untung tinggi tanpa risiko | LOK-01/02, INV-01/02 |
| "Mama minta pulsa" | ganti nomor + minta uang + darurat | FAM-01/02/03 |
| Perubahan tarif bank, tilang, tunggakan | isu tarif/migrasi, ancaman hukum | TAR-01, BAL-01, LGL-01 |

Daftar lengkap beserta bobot: `scamlens rules`.

## Keputusan desain

- **Stdlib only**: mudah dipasang dan diaudit.
- **Setiap temuan punya ID, bobot, penjelasan, dan bukti** agar hasil bisa dijelaskan, tidak sekadar "skor".
- **Konteks negasi** (`rules.is_negated`): "Jangan berikan OTP kepada siapa pun" tidak boleh dianggap
  penipuan. Hanya aturan bertanda `negatable` yang disenyapkan, dan negasi hanya berlaku dalam
  klausa yang sama (dibatasi tanda baca) supaya "Jangan khawatir, kirim OTP" tetap terdeteksi.
- **Normalisasi sebelum aturan**: penipu memakai `S3L4M4T`, `O T P`, huruf fullwidth, dan Cyrillic.
  URL tidak dinormalisasi agar domainnya tidak rusak.
- **Gabungan probabilistik** `1 - Π(1 - w/100)`: skor tidak pernah melewati 100, temuan tambahan
  menaikkan skor dengan imbal hasil menurun.
- **Ambang**: `sedang >= 25`, `tinggi >= 55` (`scorer.py`).

## Evaluasi

`scamlens eval` mengukur precision/recall pada dataset berlabel. Set `dev`/`test` dipakai menyusun
aturan; set `pesan_buta.csv` dibekukan untuk angka yang lebih jujur. Lihat `data/eval/README.md`.
Pesan sintetis buatan penulis aturan lebih mudah daripada pesan nyata, jadi angka di README adalah
**batas atas**, bukan klaim akurasi di dunia nyata.
