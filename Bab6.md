# Bab 6 — FTP/Telnet/SSH

## §6.0 Pendahuluan

Bab ini membahas tiga protokol remote access/file transfer dengan karakter forensik yang berbeda jauh: FTP dan Telnet adalah **plaintext** (semua kredensial dan data terlihat langsung di traffic), sementara SSH terenkripsi end-to-end sehingga pendekatannya lebih ke analisis metadata/timing, bukan isi payload.

Di soal CTF, FTP/Telnet biasanya jadi "easy win" — credential dan data terbaca langsung tanpa perlu decode apapun. SSH lebih menantang, fokusnya bergeser ke pola koneksi dan kemungkinan tunneling.

---

## §6.1 FTP — Credential & File Transfer Extraction

### 6.1.1 Follow Stream untuk Command Channel

FTP command channel (port 21 default) selalu plaintext, termasuk username dan password.

```bash
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

Atau langsung filter command FTP:
```bash
tshark -r capture.pcap -Y "ftp.request.command==\"USER\" || ftp.request.command==\"PASS\""
```

```bash
# ekstrak semua command FTP sekaligus
tshark -r capture.pcap -Y "ftp.request" -T fields -e ftp.request.command -e ftp.request.arg
```

💡 **Tip**: Command FTP yang perlu diperhatikan selain USER/PASS: `RETR` (download file), `STOR` (upload file), `LIST`/`NLST` (listing direktori), `CWD` (ganti direktori). Urutan command ini bisa merekonstruksi apa yang dilakukan attacker/user selama sesi.

### 6.1.2 FTP Data Channel — Extract File

FTP menggunakan dua koneksi terpisah: command channel (kontrol) dan data channel (transfer file aktual). Wireshark otomatis mengenali relasi ini kalau capture lengkap.

```bash
tshark -r capture.pcap --export-objects ftp-data,./extracted_ftp/
```

⚠️ **Jebakan umum**: FTP punya dua mode — **Active** (server inisiasi koneksi balik ke client) dan **Passive** (client inisiasi ke port yang diberikan server lewat response `PASV`). Kalau capture tidak lengkap (misal hanya command channel yang ter-capture, data channel terlewat), file tidak akan bisa diekstrak otomatis. Cek dulu apakah ada response `227 Entering Passive Mode` di command channel untuk tahu port data channel yang harus dicari manual.

```bash
# cari response PASV untuk tahu port data channel
tshark -r capture.pcap -Y "ftp.response.code==227" -T fields -e ftp.response.arg
```

Format response PASV: `(h1,h2,h3,h4,p1,p2)` — IP dari h1.h2.h3.h4, port dihitung dari `p1*256 + p2`.

### 6.1.3 Rekonstruksi Sesi FTP Lengkap

```python
import subprocess, json

result = subprocess.run(
    ["tshark", "-r", "capture.pcap", "-Y", "ftp", "-T", "json",
     "-e", "frame.time", "-e", "ftp.request.command", "-e", "ftp.request.arg", "-e", "ftp.response.arg"],
    capture_output=True, text=True
)
data = json.loads(result.stdout)

for pkt in data:
    layers = pkt["_source"]["layers"]
    time = layers.get("frame.time", [""])[0]
    cmd = layers.get("ftp.request.command", [""])[0]
    arg = layers.get("ftp.request.arg", [""])[0]
    resp = layers.get("ftp.response.arg", [""])[0]
    if cmd:
        print(f"{time} → {cmd} {arg}")
    if resp:
        print(f"{time} ← {resp}")
```

Ini membantu bikin timeline sesi FTP lengkap, berguna kalau soal minta rekonstruksi "apa yang dilakukan attacker step by step."

---

## §6.2 Telnet — Credential & Session Reconstruction

Telnet lebih plaintext lagi dari FTP — bahkan **setiap keystroke** dikirim sebagai paket terpisah (karena Telnet awalnya didesain untuk character-at-a-time echo), jadi command yang diketik user bisa tersebar di banyak paket kecil.

### 6.2.1 Follow Stream

```bash
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

Follow stream biasanya sudah cukup karena Wireshark otomatis menggabungkan karakter-karakter jadi teks yang terbaca di tampilan follow stream.

### 6.2.2 Rekonstruksi Manual per-Karakter (Kalau Follow Stream Tidak Cukup)

Kalau soal butuh detail lebih (misal timing antar keystroke relevan, atau follow stream tercampur echo server), rekonstruksi manual:

```python
from scapy.all import *

packets = rdpcap("capture.pcap")
keystrokes = b""

for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt[TCP].dport == 23:  # client → server
        keystrokes += bytes(pkt[Raw].load)

print(keystrokes.decode(errors="replace"))
```

⚠️ **Jebakan umum**: Traffic Telnet punya dua arah — client mengirim keystroke (biasanya 1 byte per paket), server mengirim balik echo dari karakter yang sama plus output command. Kalau kamu gabungkan kedua arah tanpa memisahkan, hasilnya akan terlihat terduplikasi/berantakan. Filter berdasarkan port arah (`tcp.dstport==23` untuk yang dikirim client, `tcp.srcport==23` untuk balasan server) supaya bisa dipisah dengan jelas.

💡 **Tip**: Password di Telnet biasanya **tidak ditampilkan echo-nya** oleh server (mode no-echo untuk password prompt), tapi tetap terkirim di traffic karena Telnet tidak enkripsi apapun. Jadi walau di tampilan terminal password "tidak terlihat", di packet capture password itu tetap ada mentah-mentah — cari di traffic client → server tepat setelah prompt "Password:" muncul di traffic server → client.

---

## §6.3 SSH — Analisis Metadata (Tanpa Decrypt)

SSH terenkripsi penuh setelah key exchange, jadi kecuali soal menyediakan private key session (sangat jarang dan biasanya tidak feasible untuk didekripsi retroaktif seperti TLS), fokus analisis SSH adalah **metadata dan pola**, bukan isi payload.

### 6.3.1 Info yang Masih Terlihat dari SSH Handshake

```bash
tshark -r capture.pcap -Y "ssh.protocol" -T fields -e ip.src -e ip.dst -e ssh.protocol
```

Yang bisa digali tanpa decrypt:
- **Versi SSH client/server** (dari banner awal, plaintext) — bisa mengungkap software/OS yang dipakai
- **Waktu dan durasi sesi** — indikasi berapa lama attacker terkoneksi
- **Ukuran paket dan timing pattern** — dengan analisis statistik, panjang password/command kadang bisa ditebak dari timing antar keystroke (karena SSH interactive session juga kirim per-keystroke terenkripsi, tapi ukuran & timing paketnya masih observable)

```bash
# lihat versi SSH banner
tshark -r capture.pcap -Y "ssh.protocol" -T fields -e ssh.protocol
```

⚠️ **Jebakan umum**: Jangan buang waktu mencoba "decrypt" isi command SSH kalau tidak ada key material yang disediakan soal — ini secara kriptografis tidak feasible dengan cipher modern. Kalau soal temanya SSH, biasanya fokusnya ke metadata (siapa konek ke siapa, kapan, berapa lama) atau ke exploitasi kerentanan spesifik versi SSH, bukan dekripsi isi sesi.

### 6.3.2 Deteksi SSH Tunneling / Port Forwarding

SSH sering dipakai sebagai tunnel untuk protokol lain (SOCKS proxy, port forwarding). Indikasi dari traffic:

```bash
# koneksi SSH dengan volume data jauh lebih besar dari sesi interaktif biasa
tshark -r capture.pcap -q -z conv,tcp | grep ":22"
```

| Pola | Indikasi |
|---|---|
| Sesi SSH sangat lama dengan volume data besar dan konstan | Kemungkinan tunnel aktif (bukan sekadar shell interaktif) |
| Banyak koneksi TCP baru muncul segera setelah sesi SSH terbentuk, ke IP/port lain | Kemungkinan dynamic port forwarding (SOCKS) |
| Ukuran paket sangat konsisten dan besar (bukan pola keystroke kecil) | Data bulk ditransfer lewat tunnel, bukan interactive shell |

💡 **Tip**: Kalau curiga SSH dipakai untuk tunneling protokol lain, cek juga apakah ada koneksi lain di capture yang polanya "aneh" (misal traffic HTTP internal yang harusnya tidak bisa diakses langsung dari luar) — itu bisa jadi traffic yang sebenarnya lewat tunnel SSH tapi capture-nya diambil di titik yang berbeda.

---

## §6.4 tshark Filter & One-Liner Ringkasan

```bash
# semua kredensial FTP (username & password) sekaligus
tshark -r capture.pcap -Y "ftp.request.command==\"USER\" || ftp.request.command==\"PASS\"" -T fields -e ftp.request.command -e ftp.request.arg

# semua command FTP yang dieksekusi (urutan aktivitas)
tshark -r capture.pcap -Y "ftp.request" -T fields -e frame.time_relative -e ftp.request.command -e ftp.request.arg

# raw payload Telnet arah client → server saja
tshark -r capture.pcap -Y "tcp.dstport==23" -T fields -e data.data

# ringkasan semua sesi SSH — siapa konek ke siapa, durasi berapa lama
tshark -r capture.pcap -q -z conv,tcp | grep ":22"

# cek banner/versi SSH yang dipakai
tshark -r capture.pcap -Y "ssh" -T fields -e ip.src -e ip.dst -e ssh.protocol
```

---

## §6.5 Mini Checklist — FTP/Telnet/SSH

- [ ] FTP: username & password sudah diekstrak dari command channel
- [ ] FTP: cek apakah ada file di data channel (Active/Passive mode sudah dipastikan)
- [ ] FTP: command sequence sudah direkonstruksi jadi timeline aktivitas
- [ ] Telnet: follow stream sudah dicek, kalau tercampur, dipisah manual per-arah
- [ ] Telnet: sudah dicek traffic tepat setelah prompt "Password:" untuk kredensial yang tidak ter-echo
- [ ] SSH: sudah dipastikan tidak ada key material sebelum mencoba decrypt (kalau tidak ada, fokus ke metadata)
- [ ] SSH: durasi, volume data, dan pola koneksi sudah dicek untuk indikasi tunneling

---

## §6.6 Decision Tree

```
Traffic FTP/Telnet/SSH terdeteksi
│
├─ FTP?
│  ├─ Command channel → extract USER/PASS (§6.1.1)
│  └─ Data channel ada? → extract file (§6.1.2), kalau tidak
│                          cari manual via response PASV
│
├─ Telnet?
│  ├─ Follow stream cukup jelas? → baca langsung
│  └─ Tercampur/butuh detail? → rekonstruksi manual per-arah (§6.2.2)
│
└─ SSH?
   ├─ Ada key material disediakan soal? → (jarang) coba decrypt
   └─ Tidak ada? → fokus metadata: durasi, volume, pola koneksi (§6.3)
                    cek indikasi tunneling (§6.3.2)
```

---

**Selanjutnya**: §7 — ICMP, membahas payload anomali, covert channel, dan reassembly data custom dari paket ICMP.
