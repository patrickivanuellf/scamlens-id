# Dataset evaluasi ScamLens ID

Semua pesan di sini **sintetis**: ditulis tangan meniru pola penipuan dan pesan sah di Indonesia.
Tidak ada nomor, nama, atau rekening asli. Domain penipuan memakai TLD murahan yang sengaja
dibuat-buat (mis. `jne-cek.xyz`) dan nomor telepon berpola `0812-0000-0000`.

| Berkas | Isi | Fungsi |
|---|---|---|
| `pesan_uji.csv` | 214 pesan (114 penipuan, 100 sah) dengan kolom `split` = `dev` (70%) atau `test` (30%) | Dipakai **saat menyusun aturan**. Aturan ditulis dengan melihat seluruh berkas ini, jadi angkanya optimistis. |
| `pesan_buta.csv` | 60 pesan (30 penipuan, 30 sah) dengan gaya bahasa berbeda | **Dibekukan.** Ditulis setelah aturan selesai dan tidak pernah dipakai untuk menyetel. Ini angka yang lebih jujur. |

Kolom: `id`, `split`, `label` (`scam`/`ham`), `category`, `text`.

## Cara memakai

```bash
scamlens eval data/eval/pesan_uji.csv --split dev --errors   # lihat kesalahan, perbaiki aturan
scamlens eval data/eval/pesan_buta.csv                       # cek sesekali, JANGAN disetel ke sini
```

## Aturan kerja agar evaluasi tetap jujur

1. Setel aturan hanya dari kesalahan di `dev`.
2. Jangan melihat kesalahan `pesan_buta.csv` lalu menambal aturan satu per satu. Jika perlu, buat set buta baru.
3. Ganti sebagian data sintetis dengan pesan **asli yang sudah dianonimkan** (nama, nomor, rekening diganti)
   secepat mungkin. Data sintetis buatan penulis aturan selalu lebih mudah daripada data nyata.
