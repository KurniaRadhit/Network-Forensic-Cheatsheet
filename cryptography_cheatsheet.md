# Cheatsheet Cryptography — Symmetric-Key: Stream Cipher Klasik/Legacy

> Bagian dari seri Cryptography CTF Cheatsheet. Fokus bab ini: **stream cipher klasik/legacy** (XOR, LFSR-based, RC4, A5/1, dsb). Sesuaikan penomoran Bab dengan seri utama kamu (mis. jika ini "Bab 1", ubah referensi silang di bawah sesuai struktur akhir).

---

## 1.1 Konsep Dasar Stream Cipher

Stream cipher mengenkripsi plaintext **bit-per-bit atau byte-per-byte** dengan meng-XOR-kan dengan **keystream** yang dihasilkan dari key (dan kadang IV/nonce).

```
ciphertext[i] = plaintext[i] XOR keystream[i]
```

Karena operasinya XOR, dekripsi = enkripsi lagi dengan keystream yang sama:

```
plaintext[i] = ciphertext[i] XOR keystream[i]
```

**Dua tipe utama:**

| Tipe | Keystream bergantung pada | Contoh |
|---|---|---|
| Synchronous (SSC) | Key + posisi saja, tidak pada ciphertext | RC4, A5/1, Salsa20 |
| Self-Synchronizing (SSSC) | Key + N ciphertext sebelumnya | CFB mode (bukan stream cipher murni) |

💡 **Tips:** Di soal CTF, kalau kamu melihat ciphertext yang panjangnya sama persis dengan plaintext dan tidak ada blok/padding — curigai **stream cipher** atau **XOR encryption**, bukan block cipher.

⚠️ **Warning:** Stream cipher **TIDAK BOLEH** memakai key/keystream yang sama dua kali (lihat §1.5 — Many-Time Pad Attack). Ini adalah bug klasik yang jadi sumber hampir semua soal CTF kategori ini.

---

## 1.2 One-Time Pad (OTP) — Fondasi Teoretis

OTP adalah stream cipher "ideal": keystream **benar-benar random**, **sepanjang plaintext**, dan **hanya dipakai sekali**.

- Jika 3 syarat itu dipenuhi → **perfect secrecy** (Shannon), tidak bisa dibobol secara matematis.
- Kalau salah satu dilanggar → bukan OTP lagi, jadi rentan.

Pelanggaran umum di CTF:
1. **Key reuse** (paling sering) → §1.5
2. **Key tidak random** (mis. keystream dari RNG lemah / seed diketahui) → recovery via crib/known-plaintext
3. **Key lebih pendek dari plaintext dan diulang (repeating-key XOR)** → mirip Vigenère, bisa dipecah pakai analisis frekuensi + Kasiski/index of coincidence

### Repeating-Key XOR (mirip Vigenère klasik)

```python
def xor_repeat(data: bytes, key: bytes) -> bytes:
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))
```

**Cara serang (key panjang tidak diketahui):**
1. Tebak panjang key `n` (uji beberapa nilai, cari Index of Coincidence tertinggi / Hamming distance terkecil antar blok bergeser `n`)
2. Pecah ciphertext jadi `n` kolom (byte ke-0, n, 2n, ... di kolom 1, dst.)
3. Setiap kolom = single-byte XOR → brute force 256 kemungkinan, pilih yang menghasilkan teks paling "masuk akal" (scoring frekuensi huruf/ASCII printable)

```python
from itertools import cycle

def break_repeating_xor(ct: bytes, max_keylen=40):
    def hamming(a, b):
        return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

    best_len, best_score = 1, float("inf")
    for klen in range(2, max_keylen):
        chunks = [ct[i:i+klen] for i in range(0, len(ct) - klen, klen)][:4]
        dist = sum(hamming(chunks[i], chunks[i+1]) for i in range(len(chunks)-1))
        norm = dist / klen / (len(chunks) - 1)
        if norm < best_score:
            best_score, best_len = norm, klen

    key = b""
    for i in range(best_len):
        column = ct[i::best_len]
        best_byte, best_s = 0, -1
        for k in range(256):
            xored = bytes(c ^ k for c in column)
            score = sum(chr(b).isalpha() or b == 32 for b in xored)
            if score > best_s:
                best_s, best_byte = score, k
        key += bytes([best_byte])
    return key
```

💡 **Tips:** Untuk key pendek (≤4 byte), brute force penuh (256^n) sering lebih cepat dan lebih akurat daripada IC/Kasiski jika kamu tahu sepotong plaintext (mis. flag format `FLAG{` atau header file).

---

## 1.3 LFSR (Linear Feedback Shift Register)

Komponen dasar banyak stream cipher legacy (A5/1, A5/2, E0 Bluetooth, dll).

- Register geser dengan **tap positions** tertentu; bit output di-XOR-kan balik ke input (feedback).
- Ditentukan oleh **polinomial feedback** dan **initial state (seed)**.
- **Linear** → bisa direkonstruksi penuh dari `2n` bit output berurutan via **Berlekamp-Massey algorithm**, jika `n` = degree LFSR.

```python
def lfsr_stream(seed: int, taps: list, nbits: int):
    state = seed
    out = []
    for _ in range(nbits):
        bit = state & 1
        out.append(bit)
        fb = 0
        for t in taps:
            fb ^= (state >> t) & 1
        state = (state >> 1) | (fb << (state.bit_length() - 1))
    return out
```

⚠️ **Warning:** LFSR **murni** (tanpa nonlinear combining) tidak aman untuk kripto sendirian — selalu dikombinasikan dengan fungsi nonlinear (§1.4). Kalau soal CTF cuma pakai LFSR polos, biasanya solusinya = Berlekamp-Massey untuk recover polinomial + state dari keystream yang diketahui.

### Serangan umum terhadap LFSR
| Serangan | Syarat | Tool |
|---|---|---|
| Berlekamp-Massey | ≥2n bit keystream diketahui | SageMath `berlekamp_massey()` |
| Correlation attack | Kombinasi beberapa LFSR nonlinear, ada korelasi statistik | Custom / SageMath |
| Algebraic attack | Fungsi kombinasi derajat rendah | Sage, custom solver |

---

## 1.4 Nonlinear Combiner: Geffe Generator & Sejenisnya

Karena LFSR tunggal terlalu linear, cipher klasik mengombinasikan beberapa LFSR dengan fungsi nonlinear.

**Geffe Generator** — 3 LFSR (LFSR1, LFSR2, LFSR3), output:
```
output = (LFSR1 AND LFSR2) XOR ((NOT LFSR1) AND LFSR3)
```

⚠️ **Warning:** Geffe generator rentan **correlation attack** — output berkorelasi kuat dengan LFSR1 dan LFSR3 (masing-masing ~75% match), sehingga tiap LFSR bisa direkonstruksi terpisah (divide-and-conquer), bukan brute force gabungan.

**Varian lain yang mungkin muncul di CTF:**
- **Shrinking Generator** — 2 LFSR, satu jadi "selector" untuk men-drop output LFSR lain
- **Alternating Step Generator** — mirip shrinking, tapi clock kedua LFSR diatur bergantian
- **A5/1** — 3 LFSR (19, 22, 23 bit) dengan *majority clocking* (dipakai di enkripsi GSM 2G)
- **A5/2** — versi lemah A5/1 (untuk ekspor), sudah dipatahkan sepenuhnya secara real-time

💡 **Tips:** Kalau nama soal menyebut "A5", "GSM stream cipher", atau kamu lihat 3 LFSR dengan clocking berbeda — cari paper *"Real Time Cryptanalysis of A5/1"* atau *"Real Time Cryptanalysis of A5/2"* sebagai referensi teknik.

---

## 1.5 Many-Time Pad / Keystream Reuse Attack

Kasus **paling umum** di CTF kategori stream cipher: keystream (atau key OTP) dipakai ulang untuk 2+ pesan.

Kalau `C1 = P1 XOR K` dan `C2 = P2 XOR K`, maka:
```
C1 XOR C2 = P1 XOR P2   (K hilang!)
```

Karena `P1 XOR P2` tidak bergantung pada key sama sekali, kita bisa menyerang langsung tanpa tahu key.

### Teknik: Crib Dragging
"Geser" kata yang diduga ada di salah satu plaintext (crib, mis. `" the "`, `"FLAG{"`, `" and "`) di sepanjang `P1 XOR P2`, XOR-kan, dan lihat apakah hasilnya menghasilkan teks yang masuk akal di posisi lain.

```python
def crib_drag(xored: bytes, crib: bytes):
    results = []
    for i in range(len(xored) - len(crib) + 1):
        guess = bytes(x ^ c for x, c in zip(xored[i:i+len(crib)], crib))
        if all(32 <= b < 127 for b in guess):
            results.append((i, guess))
    return results
```

Kalau ada **≥3 ciphertext** dengan key sama (klasik "many-time pad"), gunakan pendekatan statistik: setiap posisi byte, ambil semua `Ci XOR Cj`, tebak byte spasi (0x20) karena huruf kapital/lowercase XOR spasi menghasilkan swap-case yang mudah dideteksi secara visual/printable-check — lalu propagate ke seluruh ciphertext.

💡 **Tips:** Kalau di soal ada banyak file ciphertext dengan nama mirip (`ct1.bin`, `ct2.bin`, ...) yang dienkripsi cipher stream sederhana → 90% itu many-time pad. Cek dulu XOR panjang file — kalau sama, hampir pasti reuse key/nonce.

⚠️ **Warning:** Ini juga akar dari bug real-world terkenal: **WEP** (RC4 dengan IV pendek yang sering collide) dan beberapa implementasi **AES-CTR/ChaCha20 dengan nonce statis** — walau CTR/ChaCha20 bukan "legacy", prinsip seranganya identik.

---

## 1.6 RC4 (Rivest Cipher 4)

Stream cipher legacy paling terkenal — dipakai di WEP, WPA (TKIP), SSL/TLS lama. **Sudah dianggap broken**, dilarang di TLS sejak 2015 (RFC 7465).

### Algoritma

**Key Scheduling Algorithm (KSA)** — inisialisasi S-box 256 byte dari key:
```python
def KSA(key: bytes):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S
```

**Pseudo-Random Generation Algorithm (PRGA)** — hasilkan keystream:
```python
def PRGA(S, n):
    i = j = 0
    out = []
    for _ in range(n):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) % 256])
    return out

def rc4_encrypt(key: bytes, data: bytes) -> bytes:
    S = KSA(key)
    keystream = PRGA(S, len(data))
    return bytes(d ^ k for d, k in zip(data, keystream))
```

### Kelemahan Terkenal (relevan untuk CTF & sejarah)

| Kelemahan | Deskripsi | Dampak |
|---|---|---|
| **Fluhrer-Mantin-Shamir (FMS) attack** | Byte pertama key (IV) yang "lemah" membocorkan info key permanen | Dipakai memecahkan **WEP** |
| **Byte pertama keystream bias** | Beberapa byte awal PRGA punya distribusi tidak uniform (mis. byte ke-2 sering 0x00) | Bisa dipakai attack di TLS-RC4 (RC4 NOMORE) |
| **Related-key / IV reuse** | IV pendek (WEP: 24-bit) → collide dalam jumlah paket wajar | Many-time pad attack (§1.5) |
| **Key length pendek diperbolehkan** | RC4 menerima key 1–256 byte | Brute force lebih mudah kalau key pendek |

💡 **Tips CTF:** Kalau soal minta kamu **mengenali** implementasi RC4 dari pcap/kode, ciri khasnya: loop KSA 256 iterasi + swap array 256 elemen, lalu PRGA dengan pola `i = (i+1) % 256; j = (j+S[i]) % 256`. Sering muncul di **soal WEP cracking** (pakai `aircrack-ng`) atau **soal reversing** yang menyembunyikan RC4 custom.

⚠️ **Warning:** Jangan bingung RC4 dengan **ARC4/ARCFOUR** — nama beda, algoritma sama (RC4 nama dagang RSA Security).

### Tools praktis
```bash
# WEP cracking (real network / pcap)
aircrack-ng -w wordlist.txt capture.cap

# RC4 manual di Python (lihat kode di atas), atau via pycryptodome:
pip install pycryptodome
```
```python
from Crypto.Cipher import ARC4
cipher = ARC4.new(key)
plaintext = cipher.decrypt(ciphertext)
```

---

## 1.7 Referensi Silang & Alur Identifikasi Cepat

```
Ciphertext panjang = plaintext, tidak ada blok?
 ├─ Ada beberapa ciphertext, dicurigai key sama?
 │    └─ Coba XOR antar ciphertext → crib drag (§1.5)
 ├─ Ada S-box 256 byte / swap array di kode/reversing?
 │    └─ Kemungkinan RC4 (§1.6)
 ├─ Ada LFSR / shift register di deskripsi soal?
 │    └─ Berlekamp-Massey kalau linear (§1.3),
 │       correlation attack kalau nonlinear combiner (§1.4)
 └─ Key pendek diulang sepanjang plaintext?
      └─ Repeating-key XOR breaking (§1.2)
```

**Terhubung dengan bab lain dalam seri:**
- Symmetric-key → *Block Cipher Klasik/Legacy* (DES, mode ECB/CBC) — bab terpisah
- Symmetric-key → *Stream Cipher Modern* (Salsa20/ChaCha20, nonce misuse) — bab terpisah
- Cryptanalysis umum → *Frequency Analysis & Classical Ciphers* (Caesar, Vigenère murni tanpa XOR)

---

## 1.8 Mini Checklist — Soal CTF "Stream Cipher Klasik"

- [ ] Cek apakah panjang ciphertext = panjang plaintext (indikasi stream cipher)
- [ ] Cek apakah ada **banyak ciphertext** → curigai key/nonce reuse (§1.5)
- [ ] Cari S-box 256 elemen di source/binary → curigai RC4 (§1.6)
- [ ] Cari struktur shift-register / polinomial feedback → curigai LFSR (§1.3–1.4)
- [ ] Kalau key pendek & diulang → coba repeating-key XOR breaker (§1.2)
- [ ] Selalu coba **known-plaintext / crib** dulu (format flag, header file, kata umum) sebelum brute force penuh
- [ ] Kalau butuh linear algebra atas GF(2) (LFSR, MT19937-related) → pertimbangkan SageMath, bukan Python murni

---

*Catatan gaya: bab ini mengikuti format seri DFIR kamu (§X.Y, 💡 Tips, ⚠️ Warning, tabel perbandingan, checklist). Kalau mau, aku bisa lanjutkan ke Bab berikutnya: Block Cipher Klasik/Legacy (DES/3DES, mode ECB/CBC padding oracle) atau Stream Cipher Modern (ChaCha20/Salsa20 nonce reuse) — tinggal bilang urutan yang kamu mau.*
