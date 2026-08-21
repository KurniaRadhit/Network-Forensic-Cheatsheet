# Cheatsheet Cryptography — Symmetric-Key: Block Cipher Modern (AES-GCM/AEAD)

> Lanjutan dari **Stream Cipher Klasik (Bab 1)**, **Block Cipher Klasik (Bab 2)**, dan **Stream Cipher Modern (Bab 3)**. Fokus bab ini: **AES**, mode **GCM**, konsep **AEAD**, dan serangan paling sering muncul di CTF: **nonce reuse pada GCM (forbidden attack)**.

---

## 4.1 AES (Advanced Encryption Standard) — Sekilas

Pengganti DES (§2.2), standar sejak 2001 (dulu bernama Rijndael).

- Block size: **128-bit (16 byte)** — tetap, tidak bergantung key size
- Key size: **128 / 192 / 256-bit**
- Struktur: **Substitution-Permutation Network (SPN)**, bukan Feistel seperti DES
- Ronde: 10 (AES-128), 12 (AES-192), 14 (AES-256)
- Status: **Belum ada serangan praktis** yang mematahkan AES penuh — fokus serangan CTF selalu ke **mode operasi** dan **implementasi**, bukan algoritma inti.

💡 **Tips:** Sama seperti ChaCha20/Salsa20 di §3, AES sendiri hampir tidak pernah "dipecahkan" di CTF. Yang diserang adalah **cara pakainya**: mode ECB (§2.3), padding oracle CBC (§2.5), atau nonce reuse GCM (§4.4 di bawah).

---

## 4.2 AEAD — Authenticated Encryption with Associated Data

AEAD = enkripsi **+** autentikasi/integritas dalam satu skema. Menjamin:
1. **Confidentiality** — isi pesan rahasia (seperti mode enkripsi biasa)
2. **Integrity** — ciphertext tidak diubah
3. **Authenticity** — ciphertext benar dibuat oleh pemegang key
4. **Associated Data (AD)** — data tambahan yang **diautentikasi tapi tidak dienkripsi** (mis. header paket, metadata)

```
(ciphertext, tag) = AEAD_Encrypt(key, nonce, plaintext, associated_data)
plaintext = AEAD_Decrypt(key, nonce, ciphertext, tag, associated_data)
   # decrypt GAGAL total (raise error) kalau tag tidak cocok
```

⚠️ **Warning:** Kalau `associated_data` diubah walau ciphertext-nya sama persis, **verifikasi tag akan gagal**. Ini beda dengan CBC biasa (§2.3) yang tetap "berhasil" didekripsi meski isinya berubah (makanya CBC rentan bit-flipping tanpa AEAD).

**Contoh skema AEAD populer:**
| Skema | Cipher dasar | Umum dipakai di |
|---|---|---|
| AES-GCM | AES (CTR mode) + GHASH | TLS 1.2/1.3, disk encryption |
| ChaCha20-Poly1305 | ChaCha20 (§3.6) + Poly1305 | TLS 1.3, WireGuard, SSH |
| AES-CCM | AES (CTR) + CBC-MAC | Bluetooth LE, Zigbee, WPA2 (CCMP) |
| AES-SIV | AES | Nonce-misuse resistant (§4.6) |

---

## 4.3 AES-GCM — Struktur

GCM = **Galois/Counter Mode**. Kombinasi:
- **CTR mode** untuk enkripsi (AES dipakai sebagai keystream generator, mirip stream cipher!)
- **GHASH** (operasi di Galois Field GF(2¹²⁸)) untuk menghasilkan **authentication tag**

```
Counter block awal (J0) diturunkan dari nonce (biasanya 96-bit)
Keystream_i = AES(key, J0 + i)          ← mirip prinsip CTR/ChaCha20
C_i = P_i XOR Keystream_i
Tag = GHASH(H, AD, C) XOR AES(key, J0)  ← H = AES(key, 0^128), "hash subkey"
```

```python
from Crypto.Cipher import AES

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce12byte)
cipher.update(associated_data)              # optional AD, sebelum encrypt
ciphertext, tag = cipher.encrypt_and_digest(plaintext)

# Dekripsi + verifikasi
cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce12byte)
cipher2.update(associated_data)
plaintext = cipher2.decrypt_and_verify(ciphertext, tag)  # raise ValueError kalau tag salah
```

💡 **Tips:** Karena enkripsi GCM = **CTR mode**, semua prinsip nonce-reuse dari §1.5 (many-time pad) dan §3.4 (ChaCha20 nonce reuse) **berlaku langsung** ke GCM — plus ada bonus serangan tambahan ke bagian autentikasinya (§4.4).

---

## 4.4 Nonce Reuse pada GCM — "Forbidden Attack"

Ini adalah serangan **paling terkenal & paling sering ditanyakan** soal AES-GCM di CTF. Kalau `(key, nonce)` dipakai ulang di GCM, dampaknya **lebih parah daripada sekadar bocor plaintext** (seperti many-time pad biasa) — **authentication key (`H`) bisa direkonstruksi**, membuka **forgery total**.

### Tahap 1 — Bocor Plaintext (identik dengan §1.5 / §3.4)
```
C1 XOR C2 = P1 XOR P2     (karena keystream sama saat nonce sama)
```
→ Crib dragging seperti biasa.

### Tahap 2 — Recovery Authentication Key `H` (khusus GCM, lebih parah)
GHASH adalah **fungsi polinomial** atas `H` (hash subkey). Kalau attacker punya **≥2 pasang (ciphertext+AD, tag)** yang di-generate dengan **nonce sama**, `H` bisa dihitung dengan menyelesaikan persamaan polinomial di `GF(2^128)` — karena GHASH linear terhadap blok ciphertext/AD, bukan terhadap key AES itu sendiri.

**Dampak setelah `H` diketahui:**
- Attacker bisa **memalsukan tag valid** untuk ciphertext manapun (selama nonce yang sama dipakai) → **forgery**
- Bisa mengubah **associated data** tanpa terdeteksi (karena tahu cara hitung tag baru)
- **Tidak perlu tahu AES key** untuk forge — cukup `H` (bagian autentikasi), walau plaintext tetap butuh keystream dari key asli untuk didekripsi

⚠️ **Warning:** Inilah kenapa GCM disebut **"catastrophic on nonce reuse"** — jauh lebih fatal dibanding CBC atau ChaCha20 murni yang "hanya" bocor plaintext. Sekali nonce reuse ketahuan di GCM → integritas SELURUH sistem yang pakai key itu runtuh, bukan cuma 2 pesan yang collide.

💡 **Tips CTF:** Kalau soal:
1. Menyediakan **≥2 ciphertext+tag dengan nonce yang sama** (cek dulu — sering nonce di-print/terlihat di response), dan
2. Meminta kamu **forge** pesan baru yang valid (bypass autentikasi)

→ Ini **forbidden attack** klasik. Cari implementasi siap pakai daripada nulis solver GF(2^128) dari nol:
```bash
# Tool/library yang sering dipakai untuk forbidden attack CTF:
# - "gcm-forbidden-attack-tool" (Python, GitHub — banyak versi PoC dari writeup CTF)
# - Cryptohack / Cryptopals punya challenge & referensi solver serupa
pip install pycryptodome  # dasar buat AES-GCM manual & polynomial math
```

Referensi teori: paper **"Authentication Weaknesses in GCM"** oleh Antoine Joux (2006) — sumber asli istilah *forbidden attack*.

---

## 4.5 Nonce Terlalu Pendek / Predictable pada GCM

Selain reuse eksplisit, ada skenario lain yang sama berbahayanya:

| Skenario | Risiko |
|---|---|
| Nonce **random tapi pendek** (< 96-bit custom) | Birthday bound tercapai lebih cepat (lihat §3.5 — prinsip sama) |
| Nonce = **counter yang reset** (mis. restart service, counter balik ke 0) | Reuse tidak sengaja terhadap key yang sama |
| Nonce **user-controlled** lewat API/parameter | Attacker bisa sengaja mengirim nonce yang sama dua kali → langsung forbidden attack |
| **IV panjang ≠ 96-bit** | GCM standar pakai 96-bit; kalau IV lain panjang, ada proses hashing tambahan (`GHASH(IV)`) yang justru bisa memunculkan celah lain kalau diimplementasi salah |

⚠️ **Warning:** NIST merekomendasikan **maksimum 2^32 enkripsi** dengan key & random-nonce 96-bit yang sama sebelum risiko collision jadi signifikan. Kalau soal menunjukkan sistem yang generate nonce random terus-menerus dengan volume tinggi tanpa rotasi key → curigai kemungkinan collision by design.

---

## 4.6 AES-SIV & Nonce-Misuse-Resistant AEAD (untuk perbandingan)

Beberapa skema AEAD didesain **tahan terhadap nonce reuse** — kalau nonce reuse terjadi, dampaknya cuma bocor "apakah 2 plaintext identik", **tidak sampai forgery total** seperti GCM.

- **AES-SIV (RFC 5297)** — deterministik, tag dihitung dari hash seluruh plaintext dulu (jadi nonce reuse hanya bocor kesamaan plaintext, bukan authentication key)
- **AES-GCM-SIV** — kombinasi kenyamanan GCM dengan resistansi SIV

💡 **Tips:** Kalau di soal CTF kamu menemukan skema ini dipakai, forbidden attack (§4.4) **tidak berlaku** — cari celah lain (implementasi, side-channel, atau bug logic aplikasi).

---

## 4.7 Referensi Silang & Alur Identifikasi Cepat

```
Soal menyebut AES-GCM / AEAD / "tag" bersama AES?
 ├─ Ada ≥2 ciphertext dengan nonce SAMA?
 │    ├─ Ekstrak P1 XOR P2 dulu (§4.4 Tahap 1, sama seperti §1.5/§3.4)
 │    └─ Coba recover H → forge tag baru (§4.4 Tahap 2 — forbidden attack)
 ├─ Nonce terlihat pendek/predictable/user-controlled?
 │    └─ Coba paksa nonce collision (§4.5), lalu lanjut forbidden attack
 ├─ Skema disebut "SIV" atau "GCM-SIV"?
 │    └─ Nonce-misuse resistant — forbidden attack TIDAK berlaku (§4.6)
 └─ Tidak ada nonce reuse & skema standar?
      └─ Kemungkinan besar tidak ada celah crypto langsung — cek CBC/ECB (§2)
         atau kelemahan lain di luar cipher (implementasi, logic aplikasi)
```

**Terhubung dengan bab lain dalam seri:**
- Symmetric-key → *Stream Cipher Klasik/Legacy* (§1 — prinsip many-time pad dasar)
- Symmetric-key → *Block Cipher Klasik/Legacy* (§2 — ECB, CBC, padding oracle)
- Symmetric-key → *Stream Cipher Modern* (§3 — ChaCha20-Poly1305, prinsip nonce reuse yang sama)

---

## 4.8 Mini Checklist — Soal CTF "AES-GCM / AEAD"

- [ ] Konfirmasi mode: GCM, CCM, atau ChaCha20-Poly1305? (cek nama fungsi/library di source)
- [ ] Cek apakah ada **nonce yang terlihat berulang** di antara request/response
- [ ] Cek apakah nonce **bisa dikontrol attacker** (parameter API, dsb.)
- [ ] Kalau nonce reuse ditemukan → ekstrak `P1 XOR P2` dulu (quick win), baru coba recovery `H` untuk forgery
- [ ] Kalau target minta **bypass autentikasi** (bukan cuma baca plaintext) → confirm ini forbidden attack, bukan sekadar many-time pad
- [ ] Cek apakah skema pakai varian nonce-misuse-resistant (SIV) → kalau ya, forbidden attack tidak berlaku, cari vektor lain
- [ ] Pastikan associated data (AD) ikut diperhitungkan saat menyusun ulang skema serangan — jangan lupakan AD, itu bagian dari input GHASH

---

*Catatan gaya: bab ini melengkapi seri Symmetric-Key Cryptography kamu — Bab 1 (Stream Cipher Klasik), Bab 2 (Block Cipher Klasik), Bab 3 (Stream Cipher Modern), Bab 4 (Block Cipher Modern, bab ini). Kalau mau lanjut, opsi berikutnya bisa masuk ke Asymmetric-key Cryptography (RSA, ECC) atau Hash & MAC (length extension, HMAC) — tinggal bilang urutan yang kamu mau.*
