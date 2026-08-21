# Cheatsheet Cryptography — Symmetric-Key: Block Cipher Klasik/Legacy

> Lanjutan dari bab **Stream Cipher Klasik/Legacy**. Fokus bab ini: **block cipher klasik/legacy** (DES, 3DES, mode operasi ECB/CBC, padding, dan padding oracle attack). Sesuaikan penomoran Bab dengan seri utama kamu.

---

## 2.1 Konsep Dasar Block Cipher

Berbeda dari stream cipher (§1), block cipher mengenkripsi data dalam **blok berukuran tetap** (mis. 64-bit untuk DES, 128-bit untuk AES).

```
ciphertext_block = E(key, plaintext_block)
```

Karena plaintext jarang pas kelipatan block size, dibutuhkan:
1. **Padding** — mengisi blok terakhir (§2.4)
2. **Mode operasi** — cara menyambung banyak blok (§2.3)

💡 **Tips:** Kalau di soal CTF panjang ciphertext selalu **kelipatan 8 atau 16 byte**, itu ciri khas block cipher (DES=8 byte/blok, AES=16 byte/blok) — beda dengan stream cipher yang panjangnya bebas (lihat §1.1).

---

## 2.2 DES & 3DES

### DES (Data Encryption Standard)
- Block size: **64-bit (8 byte)**
- Key size: **56-bit efektif** (dikemas dalam 64-bit dengan 8 parity bit)
- Struktur: **Feistel network**, 16 ronde
- Status: **Broken** — brute force 56-bit sudah feasible sejak akhir 1990-an (mesin *EFF DES Cracker* / "Deep Crack" < 24 jam). Sekarang dengan GPU/FPGA modern jauh lebih cepat.

⚠️ **Warning:** Kalau soal CTF pakai DES murni (bukan 3DES) dengan key 56-bit tanpa info tambahan → kemungkinan besar solusinya **brute force key space** (`2^56`), bisa dipercepat dengan cluster/GPU atau known-plaintext untuk mempersempit pencarian.

### 3DES (Triple DES)
- Terapkan DES **3 kali** dengan kombinasi **EDE (Encrypt-Decrypt-Encrypt)**:
```
C = E(K3, D(K2, E(K1, P)))
```
- Varian key:
  - **Keying Option 1**: K1, K2, K3 berbeda semua → efektif ~112-bit (meet-in-the-middle attack mengurangi dari 168-bit)
  - **Keying Option 2**: K1 = K3, K2 beda → efektif ~112-bit
  - **Keying Option 3**: K1 = K2 = K3 → sama saja dengan DES biasa (backward compatible)

💡 **Tips:** Kalau soal bilang "3DES" tapi hasil dekripsi tetap jebol dengan brute force wajar, cek dulu apakah itu **Keying Option 3** (K1=K2=K3) — efektif cuma DES biasa.

```python
from Crypto.Cipher import DES3, DES

# DES
cipher = DES.new(key8byte, DES.MODE_ECB)

# 3DES
cipher = DES3.new(key16or24byte, DES3.MODE_CBC, iv)
```

---

## 2.3 Mode Operasi: ECB vs CBC (dan turunannya)

### ECB (Electronic Codebook)
Setiap blok dienkripsi **independen** dengan key yang sama.

```
C_i = E(K, P_i)
```

⚠️ **Warning — kelemahan fatal ECB:** Blok plaintext yang **identik** menghasilkan blok ciphertext yang **identik**. Ini menyebabkan **pattern leakage** — contoh klasik: gambar (BMP/PNG mentah) yang dienkripsi ECB, pola gambar aslinya masih terlihat di ciphertext ("ECB penguin" — cari contoh gambar Tux terkenal terenkripsi ECB).

💡 **Tips CTF:** Kalau ciphertext punya **blok 16-byte (atau 8-byte utk DES) yang berulang**, hampir pasti mode **ECB** dan plaintext punya bagian berulang. Cek dengan:
```python
def detect_ecb(ciphertext: bytes, blocksize=16):
    blocks = [ciphertext[i:i+blocksize] for i in range(0, len(ciphertext), blocksize)]
    return len(blocks) != len(set(blocks))  # True kalau ada blok duplikat
```

**ECB Byte-at-a-Time Decryption (mirip serangan pada AES-ECB oracle, prinsip sama utk DES):**
1. Manfaatkan oracle enkripsi yang menambahkan plaintext rahasia di akhir input attacker-controlled
2. Atur panjang input attacker supaya byte rahasia pertama berada di posisi akhir blok
3. Brute force 256 kemungkinan byte, bandingkan dengan blok target
4. Ulangi geser 1 byte demi 1 byte untuk membocorkan seluruh secret

### CBC (Cipher Block Chaining)
Setiap blok di-XOR dengan ciphertext blok sebelumnya sebelum dienkripsi. Blok pertama pakai **IV (Initialization Vector)**.

```
C_i = E(K, P_i XOR C_{i-1})     C_0 = IV
P_i = D(K, C_i) XOR C_{i-1}
```

**Sifat penting untuk CTF:**
- **IV harus random & unik** (tidak wajib rahasia, tapi tidak boleh diprediksi/reuse)
- **Bit-flipping attack**: mengubah 1 byte di `C_{i-1}` akan mengubah byte yang sama secara terprediksi di `P_i` (via XOR), TAPI merusak total blok `P_{i-1}` (karena didekripsi lewat block cipher). Berguna untuk soal yang memvalidasi field tertentu di plaintext (mis. `role=user` → `role=admin`) tanpa perlu tahu key.

```python
# Bit-flipping: ubah C_{i-1} untuk mengontrol P_i
def bitflip(ciphertext_prev_block, known_plain, target_plain):
    delta = bytes(k ^ t for k, t in zip(known_plain, target_plain))
    return bytes(c ^ d for c, d in zip(ciphertext_prev_block, delta))
```

⚠️ **Warning:** Kalau `IV` dipakai ulang untuk beberapa pesan dengan key sama, blok pertama tiap pesan bocor informasi via XOR (mirip prinsip §1.5 many-time pad, tapi khusus blok pertama).

### Ringkasan Mode Lain (referensi cepat)

| Mode | Paralel enc? | Paralel dec? | Perlu IV? | Catatan CTF |
|---|---|---|---|---|
| ECB | Ya | Ya | Tidak | Pattern leakage, byte-at-a-time attack |
| CBC | Tidak | Ya | Ya | Padding oracle (§2.5), bit-flipping |
| CFB | Tidak | Ya | Ya | Mirip stream cipher, XOR-based, error propagation terbatas |
| OFB | Ya (keystream) | Ya | Ya | Keystream independen ciphertext, IV reuse = many-time pad |
| CTR | Ya | Ya | Ya (nonce+counter) | Nonce reuse = many-time pad (§1.5), umum di cipher modern |

---

## 2.4 Padding: PKCS#7 (dan varian umum)

Karena block cipher butuh input kelipatan block size, blok terakhir di-pad.

### PKCS#7
Tambahkan `N` byte bernilai `N`, dengan `N` = jumlah byte yang dibutuhkan agar genap block size.

```
Plaintext: "HELLO" (5 byte), block size 8
Padded:    "HELLO" + 0x03 0x03 0x03   → total 8 byte
```

Kalau plaintext **sudah pas** kelipatan block size, tetap ditambahkan **1 blok penuh padding**:
```
Padded (16 byte, blok 16): [16 byte data] + 0x10 * 16
```

```python
def pkcs7_pad(data: bytes, blocksize: int) -> bytes:
    pad_len = blocksize - (len(data) % blocksize)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > len(data) or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding tidak valid")
    return data[:-pad_len]
```

💡 **Tips:** Validasi padding yang **membocorkan info** (mis. error message beda antara "padding salah" vs "padding benar tapi isi salah") adalah pintu masuk **padding oracle attack** (§2.5) — salah satu serangan CBC paling populer di CTF.

---

## 2.5 Padding Oracle Attack (CBC)

Serangan yang memanfaatkan **oracle** (server/aplikasi) yang membocorkan info **valid/tidaknya padding** setelah dekripsi — **tanpa perlu tahu key** — attacker bisa dekripsi (dan bahkan enkripsi) ciphertext apa pun.

### Prinsip Dasar
Untuk 2 blok berurutan `C_{i-1}, C_i`:
```
P_i = D(K, C_i) XOR C_{i-1}
```

Attacker memanipulasi byte terakhir `C_{i-1}` (sebut `C'_{i-1}`), kirim ke oracle, dan amati apakah padding hasil dekripsi valid.

**Langkah per byte (dari byte terakhir ke awal blok):**
1. Untuk byte target ke-`k` dari akhir, coba semua 256 nilai byte pengganti di posisi tersebut pada `C_{i-1}` yang dimodifikasi
2. Cari nilai yang membuat oracle bilang **"padding valid"** → itu berarti byte plaintext hasil dekripsi = `pad_value` (biasanya `0x01` untuk byte terakhir)
3. Dari situ, hitung: `intermediate_byte = pad_value XOR modified_C_byte`
4. `real_plaintext_byte = intermediate_byte XOR original_C_byte`
5. Set byte-byte berikutnya di `C'_{i-1}` supaya padding target naik jadi `0x02 0x02`, lalu `0x03 0x03 0x03`, dst., ulangi untuk seluruh blok
6. Ulangi untuk semua blok → **seluruh plaintext bisa didekripsi tanpa tahu key**

```python
# Kerangka konsep (bukan implementasi lengkap — sesuaikan dengan oracle target)
def padding_oracle_attack(ciphertext: bytes, blocksize: int, oracle_check):
    blocks = [ciphertext[i:i+blocksize] for i in range(0, len(ciphertext), blocksize)]
    plaintext = b""
    for bi in range(1, len(blocks)):
        prev, cur = bytearray(blocks[bi-1]), blocks[bi]
        intermediate = bytearray(blocksize)
        recovered = bytearray(blocksize)
        for pad_val in range(1, blocksize + 1):
            padpos = blocksize - pad_val
            for guess in range(256):
                prev[padpos] = guess
                for k in range(padpos + 1, blocksize):
                    prev[k] = intermediate[k] ^ pad_val
                if oracle_check(bytes(prev) + cur):
                    intermediate[padpos] = guess ^ pad_val
                    recovered[padpos] = intermediate[padpos] ^ blocks[bi-1][padpos]
                    break
        plaintext += bytes(recovered)
    return plaintext
```

💡 **Tips CTF:** Cari tool siap pakai dulu sebelum implementasi manual — jauh lebih cepat:
```bash
# padbuster (Perl) — klasik, banyak dipakai di writeup CTF
padbuster http://target/decrypt?ct=%s <cipher_hex> <blocksize> -encoding 0

# PadBuster alternatif Python
pip install poracle  # atau tulis sendiri pakai kerangka di atas
```

⚠️ **Warning:** Padding oracle **juga bisa dipakai untuk ENKRIPSI** ciphertext arbitrary (bukan cuma dekripsi) — teknik ini disebut *"encrypt via padding oracle"*, berguna kalau soal minta kamu membuat ciphertext valid baru (mis. forge token admin) tanpa tahu key sama sekali.

### Contoh kasus nyata yang relevan
- **POODLE (2014)** — padding oracle pada SSL 3.0 CBC
- **Lucky 13** — timing-based padding oracle pada TLS CBC
- ASP.NET **ViewState** padding oracle (CVE lama, banyak dipakai di soal web+crypto CTF)

---

## 2.6 Meet-in-the-Middle (MITM) Attack — konsep untuk Multi-Encryption

Relevan untuk memahami kenapa 3DES tidak 3x lebih kuat dari DES (§2.2).

Untuk `C = E(K2, E(K1, P))` (double encryption), MITM attack:
1. Hitung `E(K1, P)` untuk **semua** kemungkinan `K1`, simpan di tabel (hash map)
2. Hitung `D(K2, C)` untuk **semua** kemungkinan `K2`, cari yang match dengan tabel di langkah 1
3. Kompleksitas turun dari `O(2^(2n))` (brute force naif) jadi `O(2^n)` **waktu** + `O(2^n)` **memori**

⚠️ **Warning:** Ini alasan **Double DES tidak dipakai** di dunia nyata (MITM membuatnya cuma sedikit lebih kuat dari DES tunggal) — makanya langsung loncat ke **Triple DES**.

---

## 2.7 Referensi Silang & Alur Identifikasi Cepat

```
Panjang ciphertext = kelipatan 8 byte?
 └─ Kemungkinan DES/3DES (§2.2)

Panjang ciphertext = kelipatan 16 byte?
 └─ Kemungkinan AES (lihat bab Symmetric-Key Modern — terpisah)

Ada blok berulang identik di ciphertext?
 └─ Mode ECB (§2.3) → cek pattern leakage / byte-at-a-time

Ada oracle yang membedakan error "padding invalid" vs error lain?
 └─ Padding Oracle Attack (§2.5)

Bisa mengubah ciphertext dan sistem tetap "berhasil" decode
tapi field tertentu berubah (mis. role/admin)?
 └─ Bit-flipping attack pada CBC (§2.3)

Skema pakai 2 lapis enkripsi (double DES-like)?
 └─ Pertimbangkan Meet-in-the-Middle (§2.6)
```

**Terhubung dengan bab lain dalam seri:**
- Symmetric-key → *Stream Cipher Klasik/Legacy* (§1 — bab sebelumnya)
- Symmetric-key → *Block Cipher Modern* (AES, GCM/AEAD, nonce misuse) — bab terpisah
- Cryptanalysis → *Padding & Oracle-based Attacks* (padding oracle, MAC oracle, timing attack) — bisa dipisah jadi bab sendiri kalau seri makin dalam

---

## 2.8 Mini Checklist — Soal CTF "Block Cipher Klasik"

- [ ] Cek panjang blok ciphertext (8 byte → DES-family, 16 byte → AES-family)
- [ ] Cek blok duplikat → indikasi ECB (§2.3)
- [ ] Cek apakah ada IV terpisah yang dikirim → indikasi CBC/CFB/OFB
- [ ] Kalau ada endpoint yang mengembalikan error berbeda untuk padding invalid → coba padding oracle (§2.5)
- [ ] Kalau soal minta ubah field plaintext tanpa tahu key → cek kemungkinan bit-flipping CBC (§2.3)
- [ ] Kalau "3DES" tapi terasa lemah → cek kemungkinan Keying Option 3 (K1=K2=K3)
- [ ] Selalu cek dulu apakah library/tool siap pakai ada (`padbuster`, `pycryptodome`) sebelum implementasi manual dari nol

---

*Catatan gaya: bab ini melanjutkan format seri kamu (§X.Y, 💡 Tips, ⚠️ Warning, tabel perbandingan, checklist), sebagai Bab 2 setelah Stream Cipher Klasik/Legacy (Bab 1). Lanjutan berikutnya bisa ke Stream Cipher Modern (ChaCha20/Salsa20, nonce misuse) atau Block Cipher Modern (AES-GCM, AEAD) — tinggal bilang urutan yang kamu mau.*
