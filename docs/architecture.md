# Arsitektur ScamLens ID

```
input (teks/URL/stdin)
        │
        ▼
 ┌──────────────┐    ┌───────────────────┐
 │ rules.py     │    │ url_analyzer.py   │
 │ regex + bobot│    │ heuristik URL     │
 └──────┬───────┘    └─────────┬─────────┘
        └───────┬──────────────┘
                ▼
          scorer.py  →  Result(score, level, findings, advice)
                ▼
     cli.py (teks/JSON)   [nanti: api.py, bot.py]
```

## Threat model singkat

| Modus | Sinyal yang dideteksi | Aturan |
|---|---|---|
| APK berkedok kurir/undangan/tilang | ajakan install, tema kurir, URL .apk | APK-01, KUR-01, URL-08 |
| Phishing bank/e-wallet | ancaman blokir, peniruan petugas, domain mirip merek | ACC-01, IMP-01, URL-09 |
| Hadiah/undian/THR/bansos palsu | klaim menang, tema bantuan | HDH-01, THR-01 |
| Penipuan biaya di muka | transfer dulu untuk klaim | TRF-01 |
| Pencurian kredensial | permintaan OTP/PIN/kata sandi | OTP-01 |
| Donasi palsu | transfer ke rekening pribadi | DON-01 |

## Keputusan desain

- **Stdlib only** untuk MVP: mudah dipasang, mudah diaudit.
- **Setiap temuan punya ID, bobot, penjelasan, dan bukti** agar hasil bisa dijelaskan, tidak sekadar "skor".
- **Pemisahan modul** supaya lapisan ML/API/bot bisa ditambah tanpa mengubah inti.

## Rencana evaluasi

Kumpulkan dataset pesan penipuan dan pesan normal yang sudah dianonimkan, ukur precision/recall
aturan, lalu bandingkan dengan model ML sederhana. Laporkan hasilnya di README.

## Referensi data (untuk riset lanjutan)

- BSSN: Laporan Keamanan Digital Indonesia 2026; kanal lapor aduankonten.id
- OJK / Indonesia Anti-Scam Centre: statistik kerugian penipuan transaksi keuangan
- ITSEC Asia: pola penipuan musiman (Ramadan/Lebaran)
