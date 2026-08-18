# Bab 10 — SMTP/POP3/IMAP

## §10.0 Pendahuluan

Protokol email — SMTP untuk mengirim, POP3/IMAP untuk mengambil/membaca — sama seperti FTP/Telnet (§6): defaultnya plaintext kalau tidak dibungkus TLS (STARTTLS atau implicit TLS di port terpisah). Di soal CTF, ini biasanya berarti kredensial, isi email, dan attachment bisa langsung dibaca dari traffic tanpa decode rumit, selama tidak terenkripsi.

Tema umum soal: phishing email reconstruction, extract attachment berbahaya, atau deteksi header spoofing sebagai bagian dari investigasi social engineering/BEC (Business Email Compromise).

---

## §10.1 SMTP — Pengiriman Email

### 10.1.1 Follow Stream Command SMTP

```bash
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

SMTP command dasar yang perlu dikenali:

| Command | Fungsi |
|---|---|
| `EHLO`/`HELO` | Identifikasi client ke server |
| `MAIL FROM` | Alamat pengirim |
| `RCPT TO` | Alamat penerima |
| `DATA` | Mulai isi email (header + body), diakhiri baris `.` sendiri |
| `AUTH LOGIN`/`AUTH PLAIN` | Autentikasi (kredensial biasanya base64-encoded, bukan enkripsi asli) |
| `STARTTLS` | Upgrade koneksi ke TLS di tengah sesi |

```bash
tshark -r capture.pcap -Y "smtp.req.command" -T fields -e smtp.req.command -e smtp.req.parameter
```

### 10.1.2 Decode Kredensial AUTH

```bash
tshark -r capture.pcap -Y "smtp" -T fields -e smtp.data.fragment
```

Kredensial di `AUTH LOGIN`/`AUTH PLAIN` **selalu base64-encoded, bukan terenkripsi** — jadi selalu bisa didecode langsung kalau traffic tidak diamankan STARTTLS.

```bash
echo "<base64_string_username_atau_password>" | base64 -d
```

⚠️ **Jebakan umum**: Base64 encoding **bukan enkripsi**. Banyak orang salah kira `AUTH LOGIN` itu "aman" karena tidak terlihat plaintext langsung — padahal cuma satu langkah decode. Kalau soal CTF menyediakan traffic SMTP dengan `AUTH LOGIN`/`AUTH PLAIN` tanpa STARTTLS mendahului, kredensial pasti bisa diambil.

### 10.1.3 Cek STARTTLS

```bash
tshark -r capture.pcap -Y "smtp.req.command==\"STARTTLS\""
```

Kalau `STARTTLS` muncul, traffic setelahnya terenkripsi TLS — perlakukan sama seperti §4.6 (decrypt dengan keylog file kalau tersedia). Kalau tidak ada keylog, traffic setelah STARTTLS tidak bisa dibaca.

---

## §10.2 Rekonstruksi Isi Email Lengkap

Wireshark bisa export email SMTP langsung sebagai file `.eml`:

```bash
tshark -r capture.pcap --export-objects smtp,./extracted_emails/
```

File `.eml` yang dihasilkan bisa dibuka dengan mail client biasa, atau dibaca langsung sebagai teks (format MIME):

```bash
cat extracted_emails/*.eml
```

Struktur email MIME yang perlu dipahami untuk baca manual:

```
From: ...
To: ...
Subject: ...
Date: ...
Content-Type: multipart/mixed; boundary="XXXX"

--XXXX
Content-Type: text/plain

(isi email plaintext)
--XXXX
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="file.exe"
Content-Transfer-Encoding: base64

(data attachment dalam base64)
--XXXX--
```

💡 **Tip**: Kalau Export Objects tidak berhasil menangkap email dengan baik (misal capture tidak lengkap atau format tidak standar), rekonstruksi manual dengan follow TCP stream lalu cari boundary MIME secara manual — cari `Content-Type: multipart` di header untuk tahu delimiter/boundary string yang dipakai.

---

## §10.3 Ekstraksi Attachment

Kalau attachment tidak otomatis terekstrak lewat Export Objects, ekstraksi manual dari base64 di body MIME:

```python
import re, base64

with open("extracted_emails/email1.eml", "r") as f:
    content = f.read()

# cari bagian attachment berdasarkan Content-Disposition
match = re.search(
    r'Content-Disposition: attachment; filename="(.+?)".*?\n\n(.*?)\n--',
    content, re.DOTALL
)
if match:
    filename, b64data = match.groups()
    b64data_clean = b64data.replace("\n", "").replace("\r", "")
    with open(filename, "wb") as out:
        out.write(base64.b64decode(b64data_clean))
    print(f"Attachment '{filename}' berhasil diekstrak")
```

⚠️ **Jebakan umum**: Base64 di body email biasanya di-wrap ke banyak baris pendek (umumnya 76 karakter per baris sesuai standar MIME) — pastikan semua newline dihapus sebelum decode, jangan decode per baris terpisah karena base64 butuh data utuh untuk decode dengan benar (kecuali memang di-split di boundary byte yang pas, yang jarang terjadi kebetulan).

Setelah diekstrak, cek tipe file sebenarnya dan analisis lebih lanjut kalau dicurigai malware:
```bash
file extracted_attachment
binwalk extracted_attachment
```

---

## §10.4 POP3/IMAP — Mengambil/Membaca Email

Beda dengan SMTP (mengirim), POP3 dan IMAP dipakai client untuk **mengambil** email dari server. Kalau capture menangkap sesi ini, isinya bisa jadi bukti email apa saja yang dibaca/diunduh user.

### 10.4.1 POP3

```bash
tshark -r capture.pcap -Y "pop.request.command" -T fields -e pop.request.command -e pop.request.parameter
```

Command POP3 penting:

| Command | Fungsi |
|---|---|
| `USER`/`PASS` | Kredensial (plaintext kalau tidak TLS) |
| `LIST` | Daftar email di mailbox |
| `RETR <n>` | Ambil/download email nomor n |
| `DELE <n>` | Hapus email nomor n |

```bash
tshark -r capture.pcap -Y "pop.request.command==\"USER\" || pop.request.command==\"PASS\""
```

### 10.4.2 IMAP

IMAP lebih kompleks dari POP3 (mendukung folder, search di server, partial fetch), jadi command-nya lebih beragam.

```bash
tshark -r capture.pcap -Y "imap.request" -T fields -e imap.request
```

Command IMAP penting:

| Command | Fungsi |
|---|---|
| `LOGIN` | Kredensial |
| `SELECT`/`EXAMINE` | Pilih folder/mailbox |
| `FETCH` | Ambil isi email (bisa partial — header saja, body saja, dsb) |
| `SEARCH` | Cari email berdasarkan kriteria |

```bash
tshark -r capture.pcap -Y "imap.request contains \"LOGIN\""
```

💡 **Tip**: Karena IMAP mendukung `FETCH` parsial, isi email bisa saja terpecah di beberapa response berbeda (header dulu, baru body, baru attachment). Follow full TCP stream untuk sesi IMAP biasanya lebih efektif daripada coba parsing field per field, karena kompleksitas protokolnya.

---

## §10.5 Deteksi Header Spoofing

Email header punya banyak field yang bisa dipalsukan (`From` yang terlihat di client) vs yang sulit dipalsukan (`Received` chain yang mencatat jejak server relay).

```bash
# ekstrak semua header Received untuk rekonstruksi jalur pengiriman email
grep -i "^Received:" extracted_emails/email1.eml
```

Yang perlu dibandingkan untuk deteksi spoofing:

| Field | Kemudahan Dipalsukan |
|---|---|
| `From` (header) | Sangat mudah dipalsukan, ditulis bebas oleh pengirim |
| `Return-Path` | Sedikit lebih sulit, biasanya diisi server pengirim asli |
| `Received` chain | Sulit dipalsukan penuh, tiap server relay menambahkan baris ini |
| SPF/DKIM/DMARC record (kalau ada di header) | Hasil validasi otomatis oleh server penerima, indikasi kuat apakah email legit |

💡 **Tip**: Kalau soal minta "buktikan email ini spoofed", bandingkan domain di `From` dengan IP/hostname di baris `Received` paling awal (paling bawah secara kronologis, karena `Received` chain ditulis top-down dari yang terbaru). Kalau `From` mengklaim domain resmi tapi `Received` pertama menunjukkan server yang tidak terkait dengan domain tersebut, itu indikasi spoofing.

```bash
# cek hasil validasi SPF/DKIM kalau ada di header (biasanya di Authentication-Results)
grep -i "^Authentication-Results:" extracted_emails/email1.eml
```

⚠️ **Jebakan umum**: SMTP secara desain **tidak memvalidasi** `MAIL FROM` cocok dengan identitas pengirim sebenarnya — jadi kemunculan `MAIL FROM` yang "meyakinkan" di traffic bukan bukti legitimasi. Selalu cross-check dengan `Received` chain dan hasil autentikasi (SPF/DKIM) kalau tersedia, jangan simpulkan dari `From`/`MAIL FROM` saja.

---

## §10.6 tshark Filter & One-Liner Ringkasan

```bash
# semua command SMTP beserta parameter
tshark -r capture.pcap -Y "smtp.req.command" -T fields -e frame.time -e smtp.req.command -e smtp.req.parameter

# ekstrak semua alamat MAIL FROM dan RCPT TO
tshark -r capture.pcap -Y "smtp.req.command==\"MAIL\" || smtp.req.command==\"RCPT\"" -T fields -e smtp.req.parameter

# kredensial POP3
tshark -r capture.pcap -Y "pop.request.command==\"USER\" || pop.request.command==\"PASS\"" -T fields -e pop.request.parameter

# semua LOGIN command IMAP
tshark -r capture.pcap -Y "imap.request contains \"LOGIN\"" -T fields -e imap.request

# cek keberadaan STARTTLS di semua protokol email sekaligus
tshark -r capture.pcap -Y "smtp.req.command==\"STARTTLS\" || pop.request.command==\"STLS\" || imap.request contains \"STARTTLS\""
```

---

## §10.7 Mini Checklist — SMTP/POP3/IMAP

- [ ] Sudah dicek apakah traffic pakai STARTTLS — kalau ya, sisanya terenkripsi (butuh keylog)
- [ ] Kredensial (SMTP AUTH, POP3 USER/PASS, IMAP LOGIN) sudah diekstrak dan didecode kalau base64
- [ ] Email sudah diekstrak via Export Objects, atau manual kalau tidak berhasil
- [ ] Attachment sudah diekstrak dan dicek tipe file sebenarnya
- [ ] Header `Received` chain sudah dicek untuk deteksi spoofing
- [ ] SPF/DKIM/Authentication-Results sudah dicek kalau tersedia di header

---

## §10.8 Decision Tree — SMTP/POP3/IMAP

```
Traffic email (SMTP/POP3/IMAP) terdeteksi
│
├─ STARTTLS ditemukan? ──────────────────────→ traffic setelahnya terenkripsi,
│                                                cek keylog (§4.6), kalau tidak ada
│                                                hanya metadata yang bisa dianalisis
│
├─ Kredensial base64 di AUTH/USER/PASS/LOGIN? → decode langsung (§10.1.2, §10.4)
│
├─ Email/attachment perlu diekstrak? ────────→ Export Objects (§10.2) atau
│                                                manual dari MIME (§10.3)
│
└─ Soal minta bukti spoofing/phishing? ──────→ bandingkan From vs Received chain,
                                                 cek SPF/DKIM (§10.5)
```

---

**Selanjutnya**: §11 — VoIP/SIP & RTP, membahas rekonstruksi panggilan, ekstraksi audio dari RTP stream, dan analisis signaling SIP.
