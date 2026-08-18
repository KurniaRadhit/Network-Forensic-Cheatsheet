# Bab 11 — VoIP/SIP & RTP

## §11.0 Pendahuluan

VoIP forensics melibatkan dua lapisan protokol yang bekerja sama: **SIP** (Session Initiation Protocol) untuk signaling — negosiasi, setup, dan teardown panggilan — dan **RTP** (Real-time Transport Protocol) untuk transport data audio/video aktual. Di soal CTF, tema umumnya adalah merekonstruksi percakapan (siapa telepon siapa, kapan) atau mengekstrak dan memutar ulang audio dari RTP stream untuk menemukan informasi yang diucapkan (kadang termasuk flag yang "diucapkan" dalam audio).

---

## §11.1 SIP — Signaling & Call Setup

### 11.1.1 Struktur Dasar SIP

SIP mirip HTTP dari segi format (request/response berbasis teks dengan header), jadi follow stream cukup mudah dibaca.

```bash
tshark -r capture.pcap -q -z follow,tcp,ascii,0
# atau untuk UDP (SIP juga sering jalan di atas UDP)
tshark -r capture.pcap -q -z follow,udp,ascii,0
```

Method SIP penting:

| Method | Fungsi |
|---|---|
| `INVITE` | Memulai panggilan (berisi info negosiasi codec via SDP) |
| `ACK` | Konfirmasi terima response ke INVITE |
| `BYE` | Mengakhiri panggilan |
| `REGISTER` | Registrasi user ke SIP server |
| `CANCEL` | Membatalkan request yang belum selesai |

```bash
tshark -r capture.pcap -Y "sip.Method" -T fields -e sip.Method -e sip.From -e sip.To
```

### 11.1.2 Rekonstruksi Timeline Panggilan

```bash
tshark -r capture.pcap -Y "sip" -T fields -e frame.time -e sip.Method -e sip.Status-Line -e sip.From -e sip.To -e sip.Call-ID
```

💡 **Tip**: Field `sip.Call-ID` unik per sesi panggilan — pakai ini untuk mengelompokkan semua pesan SIP dan RTP stream yang terkait dengan satu panggilan spesifik kalau ada banyak panggilan tercampur dalam satu capture.

```bash
# filter semua traffic terkait satu Call-ID spesifik
tshark -r capture.pcap -Y "sip.Call-ID==\"abc123@host\""
```

### 11.1.3 SDP — Negosiasi Codec & Port RTP

Body dari `INVITE` (dan response `200 OK`) berisi SDP (Session Description Protocol) yang menentukan codec audio yang dipakai dan **port RTP** yang akan dipakai untuk transport audio aktual — ini krusial untuk tahu paket mana yang harus dicari untuk ekstraksi audio.

```bash
tshark -r capture.pcap -Y "sip.Method==\"INVITE\"" -T fields -e sip.Method -e sdp.media -e sdp.media.port
```

Contoh isi SDP yang perlu diperhatikan:
```
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
```
Baris ini artinya: audio akan dikirim di port 49170, memakai codec PCMU (G.711 µ-law) dengan sample rate 8000Hz.

⚠️ **Jebakan umum**: Port RTP **tidak sama** dengan port SIP (SIP biasanya port 5060, RTP bisa di port berapa saja yang dinegosiasikan lewat SDP). Jangan asumsikan traffic di port 5060 saja yang relevan — selalu cek SDP dulu untuk tahu port RTP sebenarnya sebelum mencari paket audio.

### 11.1.4 Autentikasi SIP

```bash
tshark -r capture.pcap -Y "sip.auth"
```

SIP autentikasi biasanya pakai Digest Authentication (mirip HTTP Digest) — hash MD5 dari kombinasi username, realm, password, dan beberapa parameter lain. Bisa jadi target cracking offline kalau soal butuh recover password.

---

## §11.2 RTP — Ekstraksi & Playback Audio

### 11.2.1 Identifikasi RTP Stream

```bash
# Wireshark bisa auto-decode RTP kalau sudah tahu port dari SDP
tshark -r capture.pcap -q -z rtp,streams
```

Ini menampilkan daftar semua RTP stream yang terdeteksi beserta info dasar (SSRC, source/dest, codec, jumlah paket, packet loss).

### 11.2.2 Ekstraksi Audio via Wireshark GUI

Cara paling mudah untuk CTF: `Telephony > RTP > RTP Streams` di Wireshark GUI, pilih stream yang relevan, lalu `Analyze` dan gunakan opsi export/save as audio.

Alternatif via `Telephony > VoIP Calls` untuk melihat daftar panggilan lengkap dengan opsi playback langsung.

### 11.2.3 Ekstraksi via CLI/Scripting

```bash
# ekstrak payload RTP mentah
tshark -r capture.pcap -Y "rtp" -T fields -e rtp.ssrc -e rtp.seq -e rtp.payload
```

Untuk konversi jadi file audio yang bisa diputar, umumnya butuh tool tambahan karena payload RTP masih dalam format codec mentah (bukan file WAV/MP3 langsung):

```bash
# menggunakan tool seperti rtpbreak atau tshark decode audio
# tshark punya fitur built-in untuk save RTP as .au (untuk codec umum seperti PCMU/PCMA)
tshark -r capture.pcap -Y "rtp.ssrc==0x12345678" -T fields -e rtp.payload | xxd -r -p > raw_audio.ulaw
```

Konversi dari raw codec (misal G.711 µ-law) ke WAV yang bisa diputar player biasa:

```bash
# menggunakan sox untuk konversi u-law raw ke WAV
sox -t ul -r 8000 -c 1 raw_audio.ulaw output.wav
```

💡 **Tip**: Codec paling umum di CTF adalah PCMU/PCMA (G.711) karena tidak butuh lisensi dan simpel untuk direkonstruksi manual kalau perlu. Kalau codec lebih kompleks (G.729, Opus, dsb), lebih baik andalkan fitur decode audio built-in Wireshark (`Telephony > RTP > RTP Streams > Play Streams`) daripada mencoba decode manual.

⚠️ **Jebakan umum**: RTP timestamp dan sequence number **wajib** dipakai untuk menyusun ulang urutan audio yang benar — paket bisa datang out-of-order di jaringan asli. Wireshark otomatis menangani ini kalau pakai fitur built-in RTP player, tapi kalau ekstraksi manual, jangan asumsikan urutan capture = urutan audio; selalu sort berdasarkan `rtp.seq`.

```python
from scapy.all import *

packets = rdpcap("capture.pcap")
rtp_packets = []
for pkt in packets:
    if pkt.haslayer(UDP) and pkt.haslayer(Raw):
        # RTP header minimal 12 byte, cek versi RTP di 2 bit pertama byte pertama (harus 0b10)
        raw = bytes(pkt[Raw].load)
        if len(raw) > 12 and (raw[0] >> 6) == 2:
            seq = int.from_bytes(raw[2:4], 'big')
            payload = raw[12:]
            rtp_packets.append((seq, payload))

rtp_packets.sort(key=lambda x: x[0])
audio_data = b"".join(p[1] for p in rtp_packets)

with open("reassembled_audio.raw", "wb") as f:
    f.write(audio_data)
```

---

## §11.3 Kombinasi SIP + RTP untuk Rekonstruksi Panggilan Lengkap

Untuk merekonstruksi satu panggilan penuh (siapa telepon siapa, kapan, isi percakapan apa):

1. Cari `INVITE` dengan `sip.Call-ID` target → dapatkan `From`, `To`, waktu mulai
2. Parse SDP di `INVITE`/`200 OK` → dapatkan port RTP dan codec
3. Filter RTP stream berdasarkan port yang ditemukan
4. Ekstrak dan konversi audio (§11.2)
5. Cari `BYE` dengan `Call-ID` sama → dapatkan waktu selesai panggilan

```bash
# contoh rangkaian filter untuk satu Call-ID
tshark -r capture.pcap -Y "sip.Call-ID==\"target-call-id\"" -T fields -e frame.time -e sip.Method -e sip.From -e sip.To
```

---

## §11.4 tshark Filter & One-Liner Ringkasan SIP/RTP

```bash
# semua panggilan (INVITE) beserta info dasar
tshark -r capture.pcap -Y "sip.Method==\"INVITE\"" -T fields -e frame.time -e sip.From -e sip.To -e sip.Call-ID

# ringkasan semua RTP stream terdeteksi
tshark -r capture.pcap -q -z rtp,streams

# semua registrasi SIP (siapa saja yang terdaftar di server)
tshark -r capture.pcap -Y "sip.Method==\"REGISTER\""

# cek response code SIP — panggilan gagal/ditolak
tshark -r capture.pcap -Y "sip.Status-Line" -T fields -e sip.Status-Line

# jumlah paket RTP per SSRC — bantu identifikasi stream mana yang paling relevan (durasi terpanjang, dsb)
tshark -r capture.pcap -Y "rtp" -T fields -e rtp.ssrc | sort | uniq -c | sort -rn
```

---

## §11.5 Mini Checklist — VoIP/SIP & RTP

- [ ] SIP method (`INVITE`, `BYE`, dsb) sudah dicek untuk rekonstruksi timeline panggilan
- [ ] SDP di dalam `INVITE`/`200 OK` sudah dicek untuk tahu port dan codec RTP
- [ ] RTP stream sudah diidentifikasi dan dipisahkan berdasarkan `Call-ID`/SSRC kalau ada banyak panggilan
- [ ] Audio sudah diekstrak (via Wireshark GUI atau scripting) dan dikonversi ke format yang bisa diputar
- [ ] Kalau ada autentikasi SIP, sudah dicek untuk kemungkinan cracking offline

---

## §11.6 Decision Tree — VoIP/SIP & RTP

```
Traffic SIP/RTP terdeteksi
│
├─ Soal minta info panggilan (siapa/kapan)? ──→ rekonstruksi dari SIP method + Call-ID (§11.1.2)
│
├─ Soal minta isi percakapan/audio? ──────────→ cari port RTP dari SDP (§11.1.3),
│                                                 ekstrak & convert audio (§11.2)
│
├─ Banyak panggilan tercampur dalam
│  satu capture? ──────────────────────────────→ pisahkan berdasarkan Call-ID/SSRC (§11.3)
│
└─ Ada autentikasi SIP? ───────────────────────→ ekstrak Digest untuk cracking offline (§11.1.4)
```

---

**Selanjutnya**: §12 — Custom/Unknown Binary Protocol, membahas pendekatan raw hex analysis, penulisan dissector/parser custom, dan strategi umum untuk protokol yang tidak dikenali Wireshark.
