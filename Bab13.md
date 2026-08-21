# Bab 13 — Cryptography-in-Traffic

## §13.0 Pendahuluan

Bab ini fokus ke situasi di mana data di dalam traffic sudah dipastikan terenkripsi atau ter-encode dengan skema kriptografi (bukan cuma base64/hex biasa), dan soal mengharapkan kamu melakukan cryptanalysis atau memanfaatkan kelemahan implementasi untuk mendapatkan plaintext. Ini adalah irisan antara network forensics dan CTF kategori crypto — payload-nya kamu temukan lewat teknik di bab-bab sebelumnya (§2–§12), tapi untuk membongkarnya kamu butuh pemahaman crypto dasar-menengah.

⚠️ **Batasan penting**: Bab ini membahas pola-pola kelemahan implementasi yang **umum dijadikan soal CTF** (misalnya reuse key, mode operasi yang lemah, parameter yang bocor) — bukan cara membangun serangan terhadap sistem produksi nyata. Fokusnya pada pengenalan pola dan alat analisis, sesuai konteks kompetisi.

---

## §13.1 Identifikasi Awal — Terenkripsi, Terkompresi, atau Ter-encode?

Sebelum asumsi "ini terenkripsi dan harus di-crack", pastikan dulu bukan sekadar layer encoding/kompresi yang lebih mudah dibalik (lihat juga §12.6).

```python
import math
from collections import Counter

def entropy(data):
    if not data:
        return 0
    counts = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

print(entropy(payload))
```

| Entropy | Kemungkinan |
|---|---|
| ~8.0 (byte data) | Terenkripsi dengan cipher modern, atau data terkompresi dengan baik |
| 4–7 | Terkompresi ringan, encoding seperti base64 (entropy base64 sekitar 6 karena terbatas 64 karakter set), atau XOR dengan key pendek |
| < 4 | Kemungkinan bukan crypto sama sekali — data terstruktur biasa (§12) |

```python
# selalu coba decompress dulu sebelum asumsi enkripsi
import zlib, gzip, bz2, lzma

for name, fn in [("zlib", zlib.decompress), ("gzip", gzip.decompress),
                  ("bz2", bz2.decompress), ("lzma", lzma.decompress)]:
    try:
        result = fn(payload)
        print(f"Berhasil decompress dengan {name}: {result[:50]}")
        break
    except Exception:
        continue
```

💡 **Tip**: Base64/hex encoding punya karakteristik yang mudah dikenali: base64 hanya berisi karakter `A-Za-z0-9+/=`, hex hanya `0-9a-fA-F`. Kalau payload "terlihat acak" tapi ternyata hanya berisi subset karakter terbatas seperti itu, itu **encoding, bukan enkripsi** — decode dulu sebelum analisis lebih lanjut.

---

## §13.2 XOR — Cipher Paling Umum di CTF Level Awal-Menengah

### 13.2.1 XOR dengan Single-Byte Key

```python
def xor_single_byte(data, key):
    return bytes(b ^ key for b in data)

# brute-force semua kemungkinan key 1 byte (256 kemungkinan)
for key in range(256):
    result = xor_single_byte(payload, key)
    if b"flag{" in result or b"FLAG{" in result:
        print(f"Key: {key:#x} -> {result}")
```

### 13.2.2 XOR dengan Multi-Byte Key (Repeating Key)

```python
def xor_repeating(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

# kalau key sudah diketahui (misal ditemukan di source code/config bocor)
result = xor_repeating(payload, b"secretkey")
```

⚠️ **Jebakan umum — Key Reuse**: Kalau XOR key dipakai berulang untuk banyak pesan berbeda (classic mistake: "one-time pad" yang bukan benar-benar one-time), dua ciphertext yang di-XOR bersama akan menghasilkan XOR dari kedua plaintext (`C1 XOR C2 = P1 XOR P2`), yang bisa dianalisis lebih lanjut (crib dragging) tanpa perlu tahu key aslinya.

```python
# kalau ada 2+ paket yang dicurigai pakai key sama
c1 = payload1
c2 = payload2
min_len = min(len(c1), len(c2))
xored = bytes(c1[i] ^ c2[i] for i in range(min_len))
print(xored)  # ini adalah P1 XOR P2 — analisis manual/crib dragging dari sini
```

### 13.2.3 Deteksi Panjang Key XOR (Kalau Key Multi-Byte Tidak Diketahui)

Teknik mirip cryptanalysis Vigenère — cari panjang key dengan index of coincidence, lalu solve tiap posisi sebagai single-byte XOR.

```python
def find_key_length(data, max_len=40):
    from itertools import combinations
    best_len, best_score = 1, 0
    for keylen in range(1, max_len):
        chunks = [data[i::keylen] for i in range(keylen)]
        score = sum(len(set(c)) for c in chunks) / keylen
        # heuristik sederhana; untuk soal serius pakai Hamming distance normalisasi
    return best_len
```

💡 **Tip**: Untuk soal XOR multi-byte yang lebih kompleks, tools siap pakai seperti `xortool` (`pip install xortool`) bisa langsung dipakai untuk brute-force panjang key dan key-nya sekaligus, tidak perlu tulis dari nol kecuali soal memang menguji pemahaman algoritmanya.

```bash
xortool payload.bin -c 20   # -c: karakter yang paling sering muncul (biasanya spasi 0x20)
```

---

## §13.3 Kelemahan Mode Operasi Block Cipher (AES, dsb)

### 13.3.1 ECB Mode — Pola Berulang

ECB (Electronic Codebook) mengenkripsi tiap block independen — kalau ada dua block plaintext yang sama, hasil ciphertext-nya juga sama. Ini terlihat jelas di data yang punya struktur berulang.

```python
def detect_ecb(ciphertext, block_size=16):
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))  # True kalau ada block duplikat

if detect_ecb(payload):
    print("Kemungkinan besar mode ECB dipakai")
```

⚠️ **Jebakan umum**: Kalau capture menunjukkan traffic terenkripsi dengan pola block berulang yang mencolok (apalagi kalau divisualisasikan sebagai gambar dan terlihat pola seperti logo/gambar aslinya — "ECB penguin" effect), itu ciri khas ECB yang lemah, bukan cipher yang aman.

### 13.3.2 CBC Padding Oracle (Kalau Soal Menyediakan Oracle)

Kalau protokol dalam capture menunjukkan server membalas error berbeda untuk padding valid vs invalid setelah menerima ciphertext yang dimodifikasi (bagian dari desain soal, bukan traffic capture pasif biasa), itu indikasi padding oracle attack — teknik ini biasanya dikombinasikan dengan interaksi live ke service, bukan cuma analisis pcap statis. Kalau soal forensik pcap-mu menunjukkan pola request berulang dengan ciphertext yang sedikit dimodifikasi tiap kali dan response error yang berbeda-beda, itu jejak dari padding oracle attack yang sudah dilakukan — rekonstruksi dari pcap untuk paham apa yang terjadi, bukan menjalankan attack-nya dari awal.

```python
# rekonstruksi pola request untuk analisis (bukan eksekusi attack)
tshark_cmd = "tshark -r cap.pcap -Y http.request -T fields -e http.request.uri -e frame.time"
```

💡 **Tip**: Kalau soal ini muncul, biasanya fokus forensik adalah **merekonstruksi apa yang dilakukan attacker** dari pola trafficnya (berapa banyak request, apa yang berubah tiap kali) — bukan menjalankan padding oracle attack itu sendiri dari nol, karena itu masuk domain exploitation/crypto CTF kategori terpisah dari forensics murni.

---

## §13.4 RSA — Parameter Bocor di Traffic

Kadang parameter kunci publik RSA (modulus `n`, exponent `e`) terlihat di traffic (misal dikirim saat handshake custom protocol, bukan TLS standar yang sudah punya validasi ketat).

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from math import gcd

# kalau n kecil/vulnerable (bukan RSA production-grade), coba faktorisasi
# untuk n yang benar-benar besar, ini tidak feasible tanpa kelemahan spesifik
def try_factor_small(n):
    for i in range(2, 100000):
        if n % i == 0:
            return i, n // i
    return None
```

Kelemahan RSA yang sering jadi tema soal CTF (relevan kalau parameter-nya terlihat di traffic):

| Kelemahan | Ciri |
|---|---|
| `n` kecil (bisa difaktorisasi cepat) | Modulus tidak sebesar seharusnya |
| Common modulus attack | Dua ciphertext pakai `n` sama, `e` beda |
| Low exponent (`e=3`) tanpa padding | Vulnerable ke cube root attack kalau pesan pendek |
| Shared prime antar dua public key | Dua modulus beda punya faktor prima sama, bisa dicari lewat GCD |

```python
# common modulus attack (kalau dua ciphertext ditemukan pakai n sama, e beda)
# butuh implementasi extended Euclidean algorithm untuk solve
```

💡 **Tip**: Kalau soal forensik network menampilkan handshake custom yang membawa parameter RSA mentah (bukan lewat TLS standar), itu hampir pasti disengaja sebagai bagian dari soal crypto — ekstrak parameternya dulu lewat teknik di §12 (custom protocol parsing), baru analisis kriptografinya secara terpisah (biasanya butuh library seperti `pycryptodome` atau `sympy`).

---

## §13.5 Stream Cipher & Nonce Reuse

Mirip prinsip XOR key reuse (§13.2.2) tapi untuk stream cipher modern (RC4, ChaCha20, dsb) — kalau nonce/IV dipakai berulang dengan key yang sama, keystream yang dihasilkan sama, sehingga dua ciphertext bisa di-XOR untuk menghilangkan keystream (sama seperti prinsip §13.2.2).

```bash
# cek apakah ada nonce/IV yang terlihat berulang di traffic (biasanya dikirim plaintext di awal pesan)
tshark -r capture.pcap -Y "tcp.dstport==1337" -T fields -e data.data | cut -c1-24 | sort | uniq -c
```

⚠️ **Jebakan umum**: Nonce/IV **seharusnya** unik per pesan — kalau di traffic terlihat sama berulang, itu bug implementasi yang disengaja soal, bukan hal normal di sistem yang aman. Selalu cek beberapa byte pertama payload (biasanya di situ nonce/IV ditempatkan, tergantung desain protokol) untuk pola berulang sebelum asumsi cipher-nya "aman total".

---

## §13.6 Kombinasi Crypto + Forensic — Alur Kerja Umum

1. Temukan payload terenkripsi lewat teknik bab sebelumnya (§2–§12)
2. Cek entropy dan coba decompress dulu (§13.1) — jangan langsung asumsi harus crack
3. Identifikasi kemungkinan algoritma (ukuran block 16 byte → kemungkinan AES; ukuran bervariasi bebas → kemungkinan stream cipher/XOR)
4. Cek indikasi kelemahan implementasi: key/nonce reuse, mode lemah (ECB), parameter bocor
5. Kalau ada beberapa sampel ciphertext (dari beberapa paket berbeda), bandingkan untuk pola reuse (§13.2.2, §13.5)
6. Kalau perlu, gunakan tools bantu: `xortool`, CyberChef (untuk eksplorasi cepat berbagai transformasi), `pycryptodome`/`sympy` untuk RSA

💡 **Tip**: CyberChef (tersedia offline atau online) sangat berguna untuk eksplorasi cepat "coba banyak kemungkinan transformasi" (base64, XOR, berbagai cipher sederhana) sebelum menulis script Python spesifik — bisa mempercepat proses trial-and-error di awal investigasi.

---

## §13.7 tshark Filter & One-Liner Terkait

```bash
# ekstrak payload untuk analisis crypto offline
tshark -r cap.pcap -Y "tcp.dstport==1337" -T fields -e data.data > payloads_hex.txt

# bandingkan payload antar paket untuk cek key/nonce reuse — lihat beberapa byte pertama tiap paket
tshark -r cap.pcap -Y "tcp.dstport==1337" -T fields -e data.data | awk '{print substr($0,1,32)}' | sort | uniq -c

# cek panjang payload — konsisten dengan block cipher (kelipatan 16) atau bebas (stream cipher)?
tshark -r cap.pcap -Y "tcp.dstport==1337" -T fields -e tcp.len | sort -n | uniq -c
```

---

## §13.8 Mini Checklist — Cryptography-in-Traffic

- [ ] Entropy sudah dicek — bukan sekadar base64/hex/kompresi yang lebih mudah dibalik
- [ ] Sudah dicoba decompress (zlib/gzip/bz2/lzma) sebelum asumsi enkripsi
- [ ] Ukuran payload sudah dicek — kelipatan block size tertentu (indikasi block cipher) atau bebas (stream cipher/XOR)
- [ ] Kalau ada beberapa sampel ciphertext, sudah dicek kemungkinan key/nonce reuse
- [ ] Kalau block cipher, sudah dicek pola block berulang (indikasi ECB)
- [ ] Kalau ada parameter kunci publik terlihat mentah di traffic, sudah diekstrak untuk analisis terpisah (RSA, dsb)

---

## §13.9 Decision Tree — Cryptography-in-Traffic

```
Payload dicurigai terenkripsi (entropy tinggi)
│
├─ Bisa di-decompress? ───────────────────────→ bukan enkripsi, lanjut sebagai data biasa (§12)
│
├─ Hanya berisi karakter base64/hex terbatas? ─→ decode dulu, cek ulang entropy hasil decode
│
├─ Ukuran payload kelipatan 16 byte
│  (indikasi block cipher)? ──────────────────→ cek pola block berulang → ECB? (§13.3.1)
│
├─ Ada beberapa sampel ciphertext dengan
│  key/nonce yang terlihat sama? ─────────────→ XOR antar ciphertext, crib dragging (§13.2.2, §13.5)
│
├─ Ada parameter RSA (n, e) terlihat mentah
│  di traffic? ────────────────────────────────→ analisis kelemahan RSA terpisah (§13.4)
│
└─ Tidak ada indikasi kelemahan jelas? ────────→ kemungkinan bukan fokus soal,
                                                   cek ulang apakah ada informasi lain
                                                   (metadata, timing) yang lebih relevan
```

---

**Selanjutnya**: §14 — Wireless (802.11), membahas analisis handshake WiFi, kombinasi aircrack-ng + tshark, dan decrypt traffic dengan PSK.
