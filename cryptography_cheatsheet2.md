# Cheatsheet Cryptography — Symmetric-Key: Stream Cipher Modern

> Lanjutan dari **Stream Cipher Klasik/Legacy (Bab 1)** dan **Block Cipher Klasik/Legacy (Bab 2)**. Fokus bab ini: **stream cipher modern** — Salsa20, ChaCha20, ChaCha20-Poly1305, dan yang paling sering muncul di CTF: **nonce misuse / nonce reuse attack**.

---

## 3.1 Kenapa "Modern" Berbeda dari Legacy (§1)

Stream cipher legacy (RC4, LFSR-based) dipatahkan karena:
- Bias statistik di keystream (RC4)
- Struktur linear yang bisa direkonstruksi (LFSR)
- IV/key terlalu pendek (WEP)

Stream cipher modern (Salsa20/ChaCha20) dirancang untuk menghindari semua itu:
- Berbasis **ARX** (Add-Rotate-XOR) — tidak ada S-box/tabel yang bisa dianalisis statistik seperti RC4
- **Nonce eksplisit** (biasanya 64-bit atau 96-bit) + **counter internal** → tidak butuh key baru untuk tiap pesan
- Didesain dengan **cryptanalysis modern** dalam pikiran (differential, linear cryptanalysis)

💡 **Tips:** Karena desainnya solid, di CTF **implementasi ChaCha20/Salsa20 sendiri hampir tidak pernah dipatahkan langsung**. Fokus serangan hampir selalu ke **cara pakainya** — terutama **nonce reuse** (§3.4). Kalau soal menyebut ChaCha20/Salsa20, langsung curigai nonce.

---

## 3.2 Salsa20

Didesain oleh **Daniel J. Bernstein (djb)**, 2005 — pemenang kategori software eSTREAM.

**Parameter:**
- Key: 128-bit atau 256-bit
- Nonce: 64-bit
- Counter: 64-bit (internal, bertambah tiap blok 64-byte)
- Output blok: 64 byte per invokasi

**Struktur internal:** matriks 4×4 word 32-bit, diisi dari **constant** ("expand 32-byte k"), **key**, **counter**, dan **nonce**, lalu diproses lewat **20 ronde** (10x column round + row round, disebut *double round*) operasi ARX (add mod 2³², rotate left, XOR).

```python
# Ilustrasi struktur state Salsa20 (bukan implementasi penuh)
# constants | key[0..3]
# key[4..7] | constants
# counter[0..1] | nonce[0..1]
# constants | key[4..7]  ... (susunan tepatnya lihat spesifikasi djb)
```

⚠️ **Warning:** Jangan implementasi ulang Salsa20 dari nol untuk soal serius — pakai library (`pynacl`, `cryptography`, `pycryptodome`) untuk menghindari bug implementasi yang justru membuka celah baru.

---

## 3.3 ChaCha20

Evolusi dari Salsa20 (djb, 2008), meningkatkan **diffusion per ronde** dengan mengubah urutan operasi quarter-round. Distandarkan di **RFC 8439** (bersama Poly1305).

**Parameter (RFC 8439 — yang paling umum dipakai, termasuk di TLS 1.3):**
- Key: **256-bit (32 byte)**
- Nonce: **96-bit (12 byte)**
- Counter: **32-bit (4 byte)**, dimulai dari nilai tertentu (biasanya 0 atau 1)
- Blok output: 64 byte per invokasi counter

```
keystream_block = ChaCha20_block(key, counter, nonce)
ciphertext = plaintext XOR keystream
```

```python
from Crypto.Cipher import ChaCha20

cipher = ChaCha20.new(key=key32byte, nonce=nonce12byte)
ciphertext = cipher.encrypt(plaintext)

# Dekripsi (nonce & key sama)
cipher2 = ChaCha20.new(key=key32byte, nonce=nonce12byte)
plaintext = cipher2.decrypt(ciphertext)
```

💡 **Tips:** Ada juga varian **nonce 64-bit (legacy/IETF draft lama)** dengan counter 64-bit — kalau kamu lihat library pakai nonce 8 byte bukan 12 byte, itu variannya, bukan bug. Cek dokumentasi library yang dipakai (`pycryptodome` default RFC 8439 = nonce 12 byte).

### ChaCha20 vs Salsa20 — Ringkasan

| Aspek | Salsa20 | ChaCha20 |
|---|---|---|
| Nonce standar | 64-bit | 96-bit (RFC 8439) |
| Counter | 64-bit | 32-bit (RFC 8439) |
| Quarter-round | Kolom lalu baris | Diagonal, diffusion lebih cepat |
| Umum dipakai di | libsodium (`crypto_stream_salsa20`) | TLS 1.3, WireGuard, SSH (`chacha20-poly1305`) |

---

## 3.4 Nonce Misuse / Nonce Reuse Attack — Serangan Paling Umum di CTF

Ini adalah **many-time pad attack (§1.5) versi modern**. Prinsipnya identik — hanya beda cipher.

### Kenapa Fatal
ChaCha20/Salsa20 menghasilkan keystream dari `(key, nonce, counter)`. Kalau `(key, nonce)` sama dipakai untuk **2 pesan berbeda**, keystream-nya **identik**:

```
C1 = P1 XOR KS
C2 = P2 XOR KS
─────────────────
C1 XOR C2 = P1 XOR P2     ← key & nonce lenyap total
```

Sama seperti §1.5, ini dibuka dengan **crib dragging** atau statistik many-time pad kalau ada banyak pesan.

```python
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# Kalau nonce sama dipakai ulang:
diff = xor_bytes(ct1, ct2)   # = P1 XOR P2, lanjut crib drag seperti §1.5
```

### Skenario Nonce Reuse yang Sering Muncul di CTF

| Skenario | Penyebab | Cara Deteksi |
|---|---|---|
| **Nonce hardcoded / default** | Developer pakai nonce statis (`b"\x00"*12`) di kode | Baca source/binary, cari nonce constant |
| **Counter/nonce predictable** | Nonce = timestamp atau counter incremental yang bisa ditebak | Kirim banyak request, amati pola nonce di traffic |
| **Nonce di-generate ulang dari seed yang sama** | RNG di-seed dengan nilai tetap (mis. seed dari waktu proses yang sama) | Bandingkan nonce antar pesan — kalau identik/predictable, exploit |
| **Nonce pendek + banyak pesan (birthday bound)** | Nonce random tapi terlalu pendek (mis. custom 32-bit) untuk jumlah pesan yang besar | Hitung probabilitas collision (§3.5) |
| **Retry/resend pakai nonce sama** | Aplikasi retry request tanpa regenerasi nonce | Amati 2 response identik di length untuk input berbeda |

⚠️ **Warning:** Ini **bukan** kelemahan algoritma ChaCha20/Salsa20 — ini kelemahan **implementasi/protokol**. CTF sengaja membuat skenario ini untuk menguji pemahaman kamu tentang *cara pakai* cipher modern, bukan cipher-nya sendiri.

💡 **Tips CTF:** Kalau soal menyediakan **oracle enkripsi** (kamu bisa kirim plaintext, dapat ciphertext) dan nonce ternyata **bisa kamu kontrol atau tebak** → kirim plaintext yang kamu tahu (mis. all-zero) untuk **mengekstrak keystream murni**:
```
KS = C_known XOR P_known
```
lalu pakai `KS` itu untuk dekripsi ciphertext target yang pakai nonce sama.

```python
# Ekstrak keystream dari oracle yang nonce-nya predictable/reusable
known_plaintext = b"\x00" * len(target_ciphertext)
oracle_ct = send_to_oracle(known_plaintext, same_nonce)
keystream = xor_bytes(oracle_ct, known_plaintext)   # = oracle_ct karena P=0
recovered = xor_bytes(target_ciphertext, keystream)
```

---

## 3.5 Nonce/Counter Space & Birthday Bound

Untuk nonce **random** (bukan counter deterministik), risiko collision naik seiring jumlah pesan — sesuai **birthday paradox**.

Perkiraan jumlah pesan `n` sebelum peluang collision signifikan (~50%) untuk nonce `b`-bit:
```
n ≈ sqrt(2^b)
```

| Ukuran nonce | Perkiraan batas aman jumlah pesan (random nonce) |
|---|---|
| 64-bit | ~2^32 pesan (≈4 miliar) — riskan di sistem volume tinggi |
| 96-bit (ChaCha20 standar) | ~2^48 pesan — sangat aman untuk penggunaan normal |

⚠️ **Warning:** Inilah kenapa protokol modern (TLS 1.3, WireGuard) sering pakai **nonce deterministik** (counter, bukan random) untuk ChaCha20 — menghindari risiko birthday collision sepenuhnya, dengan syarat counter **tidak pernah reset** untuk key yang sama.

---

## 3.6 ChaCha20-Poly1305 (AEAD) — Sekilas

ChaCha20 sering dipasangkan dengan **Poly1305** (MAC) membentuk skema **AEAD** (Authenticated Encryption with Associated Data) — mirip peran AES-GCM di dunia block cipher (dibahas detail di Bab 4 — Block Cipher Modern).

```python
from Crypto.Cipher import ChaCha20_Poly1305

cipher = ChaCha20_Poly1305.new(key=key32byte, nonce=nonce12byte)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

# Dekripsi + verifikasi integritas
cipher2 = ChaCha20_Poly1305.new(key=key32byte, nonce=nonce12byte)
plaintext = cipher2.decrypt_and_verify(ciphertext, tag)   # raise error kalau tag invalid
```

💡 **Tips:** Kalau soal CTF menyebut `tag` atau `MAC` bersama ChaCha20 → itu ChaCha20-Poly1305 (AEAD), bukan ChaCha20 murni. Serangan yang relevan: **nonce reuse pada AEAD bisa lebih parah** — bisa membuka **forgery** (memalsukan pesan valid), bukan cuma bocor plaintext. Detail forgery Poly1305 nonce-reuse mirip prinsip GCM di §4 (bab berikutnya) — akan dibahas lebih dalam di sana.

⚠️ **Warning:** Jangan urutan terbalik: **cipher dulu, MAC belakangan** (Encrypt-then-MAC) adalah pola yang benar dan dipakai ChaCha20-Poly1305. Kalau soal menunjukkan implementasi custom dengan urutan MAC-then-Encrypt atau Encrypt-and-MAC, itu red flag desain lemah yang mungkin sengaja dibuat rentan untuk soal.

---

## 3.7 Referensi Silang & Alur Identifikasi Cepat

```
Soal menyebut ChaCha20/Salsa20/XChaCha20?
 ├─ Ada oracle enkripsi & nonce terlihat/predictable?
 │    └─ Nonce reuse attack (§3.4) — ekstrak keystream, XOR ke target
 ├─ Ada banyak ciphertext dengan nonce yang sama persis?
 │    └─ Many-time pad / crib dragging (§3.4, prinsip sama §1.5)
 ├─ Ada "tag" atau "MAC" di output?
 │    └─ ChaCha20-Poly1305 (AEAD, §3.6) — cek juga forgery via nonce reuse
 └─ Nonce benar-benar random & unik tiap pesan, tidak ada bug jelas?
      └─ Kemungkinan besar TIDAK ada celah crypto — cek layer lain
         (implementasi, side-channel, atau bug di luar cipher)
```

**Terhubung dengan bab lain dalam seri:**
- Symmetric-key → *Stream Cipher Klasik/Legacy* (§1 — bab sebelumnya, prinsip many-time pad)
- Symmetric-key → *Block Cipher Klasik/Legacy* (§2 — bab sebelumnya)
- Symmetric-key → *Block Cipher Modern* (AES-GCM/AEAD, nonce misuse pada GCM) — **bab berikutnya (Bab 4)**

---

## 3.8 Mini Checklist — Soal CTF "Stream Cipher Modern"

- [ ] Identifikasi cipher: cari nama "ChaCha20", "Salsa20", "XChaCha20", atau ciri konstanta `"expand 32-byte k"` di binary/traffic
- [ ] Cek apakah nonce **statis/hardcoded** di source atau traffic
- [ ] Cek apakah nonce **predictable** (timestamp, counter yang bisa ditebak)
- [ ] Cek apakah kamu bisa **mengontrol nonce** lewat oracle (untuk ekstraksi keystream)
- [ ] Kalau ada beberapa ciphertext dengan nonce sama → lakukan XOR antar ciphertext (crib drag)
- [ ] Kalau ada `tag`/MAC → curigai AEAD (ChaCha20-Poly1305), cek kemungkinan forgery via nonce reuse
- [ ] Jangan buang waktu coba memecahkan algoritma ChaCha20/Salsa20 itu sendiri — fokus ke *penggunaan nonce*

---

*Catatan gaya: bab ini melanjutkan format seri kamu (§X.Y, 💡 Tips, ⚠️ Warning, tabel perbandingan, checklist), sebagai Bab 3 setelah Stream Cipher Klasik (Bab 1) dan Block Cipher Klasik (Bab 2). Selanjutnya: Bab 4 — Block Cipher Modern (AES-GCM/AEAD, nonce misuse pada GCM, forgery attack).*
