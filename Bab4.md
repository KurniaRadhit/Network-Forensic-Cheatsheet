# Bab 4 — HTTP/HTTPS

## §4.0 Pendahuluan

HTTP adalah protokol paling umum muncul di soal CTF forensik jaringan, karena paling fleksibel untuk menyembunyikan data — di header, body, cookie, URL parameter, bahkan di method/status code yang tidak lazim. HTTPS menambah satu lapis tantangan: traffic terenkripsi TLS, yang hanya bisa dibaca kalau soal menyediakan key material atau ada kelemahan yang bisa dieksploitasi.

Sebelum masuk bab ini, pastikan sudah lewat triase §1.2–§1.4 — kalau Export Objects (§1.4) sudah langsung memberi flag, tidak perlu baca lebih jauh. Bab ini untuk kasus yang lebih tersembunyi.

---

## §4.1 Follow HTTP Stream — Langkah Pertama

### GUI
Klik kanan paket HTTP → `Follow > HTTP Stream`

### CLI
```bash
tshark -r capture.pcap -q -z follow,http,ascii,0
```

Baca request dan response secara berurutan. Perhatikan:
- Method tidak lazim (`PUT`, `PATCH`, `TRACE`, custom method)
- Header custom (`X-Flag`, `X-Secret`, atau nama header yang dibuat khusus untuk soal)
- Status code tidak umum yang membawa pesan di body

💡 **Tip**: Gunakan filter `http.request || http.response` untuk hanya melihat paket HTTP tanpa TCP handshake yang mengganggu alur baca.

---

## §4.2 Ekstraksi Semua Request/Response Sekaligus

Kalau jumlah request banyak, jangan follow satu-satu. Ekstrak semua ke fields dulu:

```bash
tshark -r capture.pcap -Y "http.request" -T fields \
  -e frame.number -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri
```

```bash
tshark -r capture.pcap -Y "http.response" -T fields \
  -e frame.number -e http.response.code -e http.content_type
```

Lalu cari pola: request yang berulang dengan parameter berubah sedikit-sedikit (indikasi exfiltration per-chunk), atau satu request yang menyimpang dari pola lainnya.

---

## §4.3 Export File dari HTTP

```bash
tshark -r capture.pcap --export-objects http,./extracted_http/
```

Setelah diekstrak, jangan lupa cek tipe file sebenarnya (kadang ekstensi di URL menipu):

```bash
file extracted_http/*
```

⚠️ **Jebakan umum**: File yang diekstrak bisa jadi punya double-layer — misal file `.jpg` yang sebenarnya adalah ZIP dengan magic byte disembunyikan setelah data gambar asli (steganografi container). Cek dengan `binwalk` atau `foremost` kalau curiga ada data tersembunyi di dalam file yang sudah diekstrak.

```bash
binwalk extracted_http/suspicious.jpg
binwalk -e extracted_http/suspicious.jpg
```

---

## §4.4 Data Tersembunyi di Header, Cookie, dan Parameter URL

Tempat umum menyembunyikan data selain body:

| Lokasi | Cara cek |
|---|---|
| Custom header | `tshark -r cap.pcap -Y http -T fields -e http.request.line` |
| Cookie | `-Y "http.cookie"` lalu decode base64 jika perlu |
| User-Agent | Sering dipakai untuk C2/exfil, cek yang tidak standar |
| URL parameter (query string) | `-e http.request.uri.query` |
| Referer header | Kadang membawa data dari halaman sebelumnya |
| Basic Auth header | `Authorization: Basic <base64>` → decode langsung |

```bash
# decode Basic Auth
echo "<base64_string>" | base64 -d
```

💡 **Tip**: Kalau melihat string base64-looking di parameter/header/cookie yang panjangnya tidak lazim (bukan token session biasa), coba decode langsung — banyak soal CTF level mudah-menengah menyembunyikan flag hanya dengan satu layer base64/URL-encoding.

```bash
# kalau data di-URL-encode dulu baru base64
python3 -c "import urllib.parse, base64; print(base64.b64decode(urllib.parse.unquote('<data>')))"
```

---

## §4.5 Reassembly Data yang Dipecah ke Banyak Request

Pola umum: flag/data dipecah jadi beberapa bagian, dikirim lewat parameter berbeda di request berurutan (mirip pola exfiltration).

```python
import subprocess, json

result = subprocess.run(
    ["tshark", "-r", "capture.pcap", "-Y", "http.request", "-T", "json",
     "-e", "http.request.uri.query"],
    capture_output=True, text=True
)
data = json.loads(result.stdout)

chunks = []
for pkt in data:
    layers = pkt["_source"]["layers"]
    if "http.request.uri.query" in layers:
        chunks.append(layers["http.request.uri.query"][0])

print("".join(chunks))
```

Sesuaikan field yang diambil (`http.cookie`, header custom, dsb) tergantung di mana data disembunyikan.

⚠️ **Jebakan umum**: Urutan paket di file capture tidak selalu sama dengan urutan logis data (kalau ada retransmission atau multiple TCP stream paralel). Selalu urutkan berdasarkan timestamp (`frame.time_epoch`) atau nomor sequence eksplisit kalau soal menyediakannya, jangan asumsikan urutan capture = urutan data.

---

## §4.6 HTTPS/TLS — Decrypt dengan Keylog File

Kalau soal menyediakan file keylog (`sslkeylog.txt` atau sejenisnya — biasanya hasil dari environment variable `SSLKEYLOGFILE` saat traffic direkam):

### GUI
`Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename` → pilih file keylog

### CLI
```bash
tshark -r capture.pcap -o "tls.keylog_file:sslkeylog.txt" -Y http -T fields -e http.request.full_uri
```

Setelah keylog dipasang, traffic HTTPS akan otomatis ter-decrypt dan bisa diperlakukan sama seperti HTTP biasa (§4.1–§4.5).

⚠️ **Jebakan umum**: Keylog file hanya bekerja kalau **cipher suite yang dipakai mendukung logging** (umumnya TLS 1.2/1.3 modern sudah support). Kalau tidak ada keylog dan tidak ada private key server, traffic HTTPS **tidak bisa didekripsi** — dalam kasus ini, fokus investigasi harus pindah ke metadata (SNI, JA3 fingerprint, ukuran & timing paket) alih-alih isi payload.

### 4.6.1 Kalau Ada Private Key Server (bukan keylog)

```bash
tshark -r capture.pcap -o "tls.keys_list:0.0.0.0,443,http,server.key"
```

Ini hanya berfungsi untuk RSA key exchange (bukan cipher suite dengan Perfect Forward Secrecy seperti ECDHE), karena PFS membuat setiap sesi punya key unik yang tidak bisa direkonstruksi dari private key server saja.

---

## §4.7 Analisis Metadata TLS Tanpa Decrypt

Kalau tidak ada keylog/private key, masih banyak yang bisa digali dari metadata TLS:

```bash
# lihat SNI (server name) dari setiap TLS handshake — bocorkan domain tujuan walau isi terenkripsi
tshark -r capture.pcap -Y "tls.handshake.type==1" -T fields -e ip.dst -e tls.handshake.extensions_server_name

# JA3 fingerprint client (butuh plugin/script tambahan di Wireshark versi lama, built-in di versi baru)
tshark -r capture.pcap -Y "tls.handshake.type==1" -T fields -e tls.handshake.ja3
```

JA3/JA3S fingerprint berguna untuk **identifikasi tool/malware family** dari pola TLS handshake-nya, walau isi traffic tetap terenkripsi — relevan kalau soal tentang malware C2 traffic analysis (lihat juga §5 kalau ada kombinasi dengan protokol lain).

---

## §4.8 Mini Checklist — HTTP/HTTPS

- [ ] Follow HTTP stream sudah dilihat untuk request/response mencurigakan
- [ ] Export Objects sudah dijalankan, file hasil ekstraksi sudah dicek dengan `file` dan `binwalk`
- [ ] Header custom, cookie, User-Agent, dan URL parameter sudah dicek satu per satu
- [ ] Kalau ada base64/URL-encoded string yang tidak lazim, sudah dicoba decode
- [ ] Kalau ada banyak request berpola serupa, sudah dicoba reassembly (kemungkinan exfiltration)
- [ ] Kalau HTTPS: sudah dicek apakah ada keylog file atau private key yang disediakan soal
- [ ] Kalau tidak bisa didekripsi: SNI dan JA3 fingerprint sudah dicek sebagai alternatif

---

## §4.9 Decision Tree — HTTP/HTTPS

```
Traffic HTTP/HTTPS terdeteksi
│
├─ HTTPS?
│  ├─ Ada keylog/private key? → decrypt (§4.6) → lanjut sebagai HTTP biasa
│  └─ Tidak ada? → analisis metadata saja (§4.7), atau cek apakah
│                   flag tersembunyi di layer lain (DNS §3, protokol lain)
│
└─ HTTP (atau sudah didekripsi)
   ├─ Ada file ditransfer? → Export Objects (§4.3) → cek dengan binwalk
   ├─ Flag terlihat langsung di body? → selesai
   ├─ Ada encoding mencurigakan di header/cookie/URL? → decode (§4.4)
   └─ Data terpecah di banyak request? → reassembly (§4.5)
```

---

**Selanjutnya**: §5 — DNS, membahas deteksi DNS tunneling, reassembly data dari TXT/CNAME record, dan pola DGA.
