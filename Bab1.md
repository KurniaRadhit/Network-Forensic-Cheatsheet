# Bab 1 — Workflow Umum & Recon PCAP

## §1.0 Pendahuluan

Setiap soal CTF forensik jaringan hampir selalu dimulai dengan hal yang sama: kamu dikasih satu file `.pcap` atau `.pcapng`, tanpa konteks lain selain judul soal dan mungkin deskripsi singkat. Bab ini adalah titik masuk untuk seluruh series — sebelum lompat ke bab protokol spesifik (§2–§12), kamu harus tahu dulu **protokol apa yang ada di dalam capture**, **di mana anomalinya**, dan **bab mana yang relevan**.

Filosofi bab ini: jangan langsung buka Wireshark dan scroll manual dari packet 1. PCAP CTF sering berisi ribuan hingga jutaan paket — kamu butuh triase cepat berbasis statistik dulu, baru masuk ke detail.

💡 **Tip**: Selalu asumsikan flag/kunci tersembunyi ada di salah satu dari tiga tempat: (1) payload aplikasi yang tidak biasa, (2) metadata yang seharusnya kosong tapi terisi, atau (3) protokol yang jarang muncul di traffic normal (jadi langsung mencolok di Protocol Hierarchy).

---

## §1.1 Persiapan Environment

### 1.1.1 Tools Wajib

| Tool | Fungsi | Instalasi |
|---|---|---|
| Wireshark | GUI analysis, deep packet inspection | `apt install wireshark` |
| tshark | CLI Wireshark, scripting & automation | included dengan Wireshark |
| tcpdump | Capture & filter cepat via CLI | `apt install tcpdump` |
| Zeek (Bro) | Log-based traffic analysis, high-level summary | `apt install zeek` |
| NetworkMiner | Auto file/credential extraction (GUI, Windows-friendly) | networkminer.com |
| scapy | Python packet crafting/parsing untuk protokol custom | `pip install scapy` |
| capinfos | Info cepat soal file capture | included dengan Wireshark |
| editcap/mergecap | Split/gabung pcap | included dengan Wireshark |

⚠️ **Jebakan umum**: Jangan langsung buka file PCAP besar (>500MB) di Wireshark GUI tanpa filter — bisa hang. Gunakan `tshark` atau `capinfos` dulu untuk profiling awal, baru buka bagian yang relevan di GUI kalau perlu.

### 1.1.2 Cek Integritas & Info Dasar File

```bash
file capture.pcap
capinfos capture.pcap
```

`capinfos` memberi info krusial di awal: jumlah paket, durasi capture, ukuran rata-rata paket, dan yang penting — **apakah ada paket corrupt/truncated**. Kalau soal CTF sengaja merusak file (butuh `pcapfix` untuk reparasi), ini akan terlihat di sini.

```bash
# kalau file rusak/butuh reparasi
pcapfix -o fixed.pcap corrupt.pcap
```

---

## §1.2 Triase Cepat — Protocol Hierarchy

Ini adalah **langkah pertama tanpa kecuali** di setiap soal PCAP CTF.

### GUI (Wireshark)
`Statistics > Protocol Hierarchy`

### CLI (tshark) — lebih cepat untuk automation
```bash
tshark -r capture.pcap -q -z io,phs
```

Yang perlu diperhatikan dari output ini:

1. **Protokol yang tidak biasa muncul di traffic normal** → biasanya jadi fokus soal. Contoh: kalau ada `ICMP` dengan jumlah paket besar padahal soal bukan tentang ping, atau ada custom protocol di atas TCP/UDP yang tidak dikenali Wireshark (`Data`).
2. **Persentase byte vs jumlah paket yang timpang** → banyak paket kecil-kecil di protokol tertentu bisa indikasi tunneling/exfiltration (lihat §3 untuk DNS, §5 untuk ICMP).
3. **Port tidak standar** → misal HTTP di port selain 80/8080, atau SSH-looking traffic di port aneh.

💡 **Tip**: Kalau `Protocol Hierarchy` menunjukkan banyak `Data` (unparsed) di bawah TCP/UDP, itu sinyal kuat untuk protokol custom/binary → langsung lompat ke §10 (Custom/Unknown Binary Protocol).

---

## §1.3 Conversations & Endpoints

`Statistics > Conversations` (GUI) menunjukkan siapa bicara dengan siapa, berapa banyak data, dan berapa lama.

```bash
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap -q -z conv,udp
tshark -r capture.pcap -q -z endpoints,ip
```

Yang dicari:

- **IP/port yang paling banyak transfer data** → biasanya jadi titik fokus (server C2, exfil target, dsb).
- **Koneksi berdurasi sangat lama** dengan data kecil → bisa indikasi beaconing/C2 (lihat §11 kalau ada unsur crypto, atau protokol spesifik lainnya).
- **Koneksi berdurasi sangat singkat tapi berulang** → pola scanning atau tunneling per-request kecil (khas DNS tunneling, §3).

⚠️ **Jebakan umum**: Jangan fokus hanya ke koneksi dengan volume data terbesar. Soal CTF sering menyembunyikan flag di koneksi yang justru kecil dan gampang terlewat — misal satu paket ICMP yang menyimpang dari pola normal di antara ribuan paket ICMP standar.

---

## §1.4 Export Objects — Cek File Cepat

Kalau ada kemungkinan file ditransfer (HTTP, FTP, SMB, email), cek dulu sebelum analisis manual:

```bash
# GUI: File > Export Objects > HTTP/DICOM/SMB/TFTP
```

CLI dengan tshark:
```bash
tshark -r capture.pcap --export-objects http,./extracted_http/
tshark -r capture.pcap --export-objects smb,./extracted_smb/
```

Ini sering langsung memberikan flag kalau soalnya sesederhana "file ditransfer via HTTP, extract dan baca isinya."

---

## §1.5 Follow Stream — Alat Serbaguna

`Follow > TCP Stream` / `UDP Stream` di Wireshark, atau via CLI:

```bash
tshark -r capture.pcap -q -z follow,tcp,ascii,0   # stream index 0
tshark -r capture.pcap -q -z follow,tcp,hex,0      # kalau butuh raw hex
```

Berguna untuk hampir semua protokol berbasis teks (HTTP, FTP, SMTP, Telnet) dan sebagai langkah awal investigasi manual sebelum masuk ke tool protokol spesifik di bab-bab berikutnya.

---

## §1.6 tshark Filter & One-Liner Umum (Lintas Protokol)

Filter-filter ini dipakai berulang di hampir semua bab protokol, jadi ditaruh di sini sebagai referensi umum:

```bash
# Ekstrak semua field tertentu dari seluruh paket (contoh: semua host HTTP)
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# Cari string tertentu di seluruh payload
tshark -r capture.pcap -Y "frame contains \"flag\""

# Output JSON untuk diproses lebih lanjut dengan python
tshark -r capture.pcap -T json > output.json

# Statistik ukuran paket per protokol (bantu spot anomali size)
tshark -r capture.pcap -q -z io,stat,1,"COUNT(dns)dns"

# Filter berdasarkan range waktu (kalau soal kasih hint waktu kejadian)
tshark -r capture.pcap -Y "frame.time >= \"2026-01-01 00:00:00\" && frame.time <= \"2026-01-01 01:00:00\""
```

💡 **Tip**: `frame contains "string"` sangat berguna untuk pencarian cepat kata kunci seperti `flag{`, `FLAG`, `password`, atau nama fungsi/variabel spesifik soal — tapi hati-hati, ini case-sensitive dan hanya cocok untuk data yang tidak terenkripsi/terenkode.

⚠️ **Jebakan umum**: `frame contains` mencari di representasi mentah paket, bukan payload yang sudah di-decode (misal base64 atau URL-encoded). Kalau flag disembunyikan dalam bentuk encoded, filter ini tidak akan menemukannya — perlu decode dulu (lihat pendekatan per-protokol di bab masing-masing).

---

## §1.7 Decision Tree — "Aku Lihat Protokol Ini, Lanjut ke Bab Mana?"

```
Buka capture → Protocol Hierarchy (§1.2)
│
├─ HTTP/HTTPS dominan? ──────────────→ Bab 2
├─ DNS dengan volume/pola aneh? ─────→ Bab 3
├─ FTP/Telnet/SSH terlihat? ─────────→ Bab 4
├─ ICMP dengan payload besar/aneh? ──→ Bab 5
├─ SMB/traffic Windows domain? ──────→ Bab 6
├─ USB capture (usbmon/USBPcap)? ────→ Bab 7
├─ SMTP/POP3/IMAP? ──────────────────→ Bab 8
├─ SIP/RTP? ──────────────────────────→ Bab 9
├─ Banyak "Data" tak dikenal? ───────→ Bab 10
├─ Ada indikasi data terenkripsi
│  (entropy tinggi, pola XOR, dsb)? ─→ Bab 11
└─ 802.11/WiFi capture? ─────────────→ Bab 12
```

💡 **Tip**: Soal CTF sering menggabungkan lebih dari satu bab sekaligus — misal DNS tunneling (§3) yang isinya ternyata data ter-XOR (§11), atau HTTP (§2) yang membawa custom binary protocol di body-nya (§10). Jangan berhenti di satu bab kalau hasil ekstraksi masih terlihat "acak" atau tidak langsung terbaca.

---

## §1.8 Checklist Awal Sebelum Deep-Dive

- [ ] `capinfos` sudah dicek — file tidak corrupt, durasi dan jumlah paket masuk akal
- [ ] Protocol Hierarchy sudah direview — sudah tahu protokol dominan dan yang mencolok
- [ ] Conversations/Endpoints sudah dicek — sudah tahu IP/port yang jadi fokus
- [ ] Export Objects sudah dicoba (kalau relevan) — file yang bisa diekstrak langsung sudah diambil
- [ ] Sudah ada hipotesis awal protokol mana yang jadi kunci soal, dan sudah tahu bab referensi mana yang harus dibuka

⚠️ **Jebakan umum paling sering**: langsung scroll manual packet-by-packet tanpa triase statistik dulu. Ini memboroskan waktu kompetisi dan sering membuat kamu melewatkan anomali yang justru langsung kelihatan di Protocol Hierarchy atau Conversations.

---

**Selanjutnya**: §2 — HTTP/HTTPS, membahas extract file, follow stream, decrypt TLS via keylog, dan credential/header hunting.
