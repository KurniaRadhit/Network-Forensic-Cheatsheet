# Bab 5 — DNS

## §5.0 Pendahuluan

DNS adalah salah satu protokol favorit di soal CTF forensik jaringan untuk menyembunyikan data karena sifatnya yang "dipercaya" oleh kebanyakan firewall/monitoring — traffic DNS jarang diblokir, sehingga sering dipakai attacker (dan pembuat soal CTF) sebagai covert channel: DNS tunneling untuk exfiltrasi data atau bahkan C2 communication.

Ciri khas soal DNS di CTF: volume query yang tidak wajar ke satu domain, subdomain dengan string panjang/acak, atau data yang disisipkan di record type yang jarang dipakai (TXT, CNAME, NULL).

---

## §5.1 Baseline — DNS Normal vs Anomali

Sebelum curiga tunneling, pahami dulu pola DNS normal: query pendek, ke banyak domain berbeda, response cepat, tidak ada pola berulang mencurigakan.

```bash
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name -e dns.qry.type | sort | uniq -c | sort -rn | head -30
```

Yang dicari:

| Indikasi Anomali | Penjelasan |
|---|---|
| Satu domain menerima ratusan/ribuan query unik | Kemungkinan tunneling — setiap query membawa chunk data berbeda |
| Subdomain sangat panjang (mendekati limit 63 karakter per label) | Data disisipkan di subdomain |
| Query type TXT/NULL/CNAME dalam jumlah tidak wajar | Record type ini sering dipakai bawa data karena bisa menyimpan string bebas |
| Interval antar query sangat konsisten/mekanis | Beaconing otomatis, bukan browsing manusia |
| Entropy tinggi di subdomain (terlihat acak/base32/base64-like) | Data terenkode, bukan nama domain asli |

💡 **Tip**: DNS tunneling murni untuk transfer data biasanya pakai encoding base32 atau base64-url-safe di subdomain, karena DNS label hanya boleh berisi karakter alfanumerik dan `-`. Kalau melihat subdomain dengan karakter yang terlihat base32 (huruf besar + angka 2-7) itu sinyal kuat.

---

## §5.2 Deteksi DNS Tunneling — Filter & Statistik

```bash
# hitung jumlah query unik per domain — domain dengan query sangat banyak = curiga
tshark -r capture.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name | \
  awk -F. '{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head -10
```

```bash
# panjang rata-rata subdomain per domain — tunneling biasanya subdomain panjang & konsisten
tshark -r capture.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name | \
  awk '{print length, $0}' | sort -rn | head -20
```

```bash
# cek record type yang jarang dipakai di traffic normal
tshark -r capture.pcap -Y "dns.qry.type==16" -T fields -e dns.qry.name  # TXT
tshark -r capture.pcap -Y "dns.qry.type==10" -T fields -e dns.qry.name  # NULL
tshark -r capture.pcap -Y "dns.qry.type==5"  -T fields -e dns.qry.name  # CNAME
```

⚠️ **Jebakan umum**: Jangan langsung asumsikan semua TXT record mencurigakan — TXT record juga dipakai untuk hal legit (SPF, DKIM). Bedakan berdasarkan **volume dan pola**: SPF/DKIM biasanya satu-dua record per domain, bukan ratusan query berulang ke domain yang sama.

---

## §5.3 Reassembly Data dari Query DNS

Kalau sudah dikonfirmasi ada tunneling, langkah berikutnya adalah reassembly data dari seluruh query yang mengarah ke domain tunneling tersebut.

```python
import subprocess, json, base64

result = subprocess.run(
    ["tshark", "-r", "capture.pcap", "-Y", "dns.flags.response==0 && dns.qry.name contains \"evil.com\"",
     "-T", "json", "-e", "dns.qry.name", "-e", "frame.time_epoch"],
    capture_output=True, text=True
)
data = json.loads(result.stdout)

entries = []
for pkt in data:
    layers = pkt["_source"]["layers"]
    qname = layers["dns.qry.name"][0]
    ts = float(layers["frame.time_epoch"][0])
    # ambil label pertama sebagai chunk data (sebelum domain utama)
    chunk = qname.split(".")[0]
    entries.append((ts, chunk))

# urutkan berdasarkan waktu (atau berdasarkan index kalau ada di dalam chunk-nya sendiri)
entries.sort(key=lambda x: x[0])
raw = "".join(c for _, c in entries)

print("Raw concatenated:", raw)

# coba decode base32 (paling umum di DNS tunneling)
try:
    # tambahkan padding kalau perlu
    padded = raw.upper() + "=" * ((8 - len(raw) % 8) % 8)
    print("Base32 decoded:", base64.b32decode(padded))
except Exception as e:
    print("Base32 gagal:", e)
```

⚠️ **Jebakan umum**: Jangan hanya urutkan berdasarkan `frame.time_epoch` kalau query dikirim sangat cepat/paralel — bisa jadi urutan waktu tidak sama dengan urutan logis data. Cek apakah ada index eksplisit di dalam chunk itu sendiri (misal `chunk001.abc.evil.com`, `chunk002.xyz.evil.com`) — kalau ada, pakai itu untuk sorting, bukan timestamp.

### 5.3.1 Reassembly dari TXT Record Response

Kalau data disisipkan di **response** (bukan query) — misal server mengirim data lewat TXT record sebagai balasan:

```bash
tshark -r capture.pcap -Y "dns.flags.response==1 && dns.resp.type==16" -T fields -e dns.txt
```

```python
# gabungkan semua TXT record response jadi satu, lalu decode
import subprocess
result = subprocess.run(
    ["tshark", "-r", "capture.pcap", "-Y", "dns.resp.type==16",
     "-T", "fields", "-e", "dns.txt"],
    capture_output=True, text=True
)
txt_chunks = [line for line in result.stdout.splitlines() if line]
combined = "".join(txt_chunks)
print(combined)
```

---

## §5.4 DGA (Domain Generation Algorithm) Pattern

DGA dipakai malware untuk generate domain C2 secara algoritmik supaya sulit di-blocklist. Di CTF, ini biasanya muncul sebagai bagian dari analisis malware traffic.

Ciri-ciri domain hasil DGA:
- String terlihat acak, tidak membentuk kata yang bisa dibaca (`xkqjzpvmw.com` vs `google.com`)
- Panjang domain relatif konsisten (hasil algoritma dengan panjang tetap/range tertentu)
- Banyak domain berbeda dicoba resolve dalam waktu singkat, sebagian besar gagal (NXDOMAIN)
- TLD yang dipakai berulang dan terbatas (algoritma biasanya fix TLD)

```bash
# cari pola banyak NXDOMAIN berturut-turut dari satu host — indikasi DGA mencoba banyak domain
tshark -r capture.pcap -Y "dns.flags.rcode==3" -T fields -e ip.src -e dns.qry.name | sort | uniq -c | sort -rn | head -20
```

💡 **Tip**: Kalau soal minta identifikasi algoritma DGA-nya (bukan cuma domain listnya), kumpulkan semua domain yang berhasil di-resolve (bukan NXDOMAIN), lalu cari pola generation-nya secara manual atau brute-force kemungkinan seed/algoritma umum (banyak DGA CTF pakai algoritma sederhana seperti hash dari tanggal + counter).

---

## §5.5 DNS di Port Tidak Standar / Protokol Menyamar

```bash
# DNS biasanya port 53, cek kalau ada traffic serupa di port lain
tshark -r capture.pcap -Y "udp.port != 53 && dns"
```

Sebaliknya, cek juga kalau ada traffic di port 53 yang **bukan** DNS asli (protokol lain menyamar pakai port DNS supaya lolos firewall):

```bash
tshark -r capture.pcap -Y "udp.port==53 && !dns"
```

⚠️ **Jebakan umum**: Wireshark cukup pintar mendeteksi DNS berdasarkan struktur paket, bukan cuma port — tapi kalau soal sengaja bikin traffic custom yang benar-benar menyamar sebagai DNS packet (bukan cuma pakai port 53), Wireshark bisa saja tetap parse sebagai DNS walau isinya sudah dimodifikasi/disisipi data di field yang tidak biasa dipakai (misal Additional Records section). Cek raw hex kalau curiga ada data tersembunyi di field DNS yang jarang diperhatikan.

---

## §5.6 tshark Filter & One-Liner Ringkasan DNS

```bash
# semua query DNS unik beserta jumlah kemunculan
tshark -r capture.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# response time DNS — response lambat/tidak wajar bisa indikasi server custom (bukan resolver asli)
tshark -r capture.pcap -Y dns -T fields -e dns.time

# ekstrak semua record type yang muncul di capture
tshark -r capture.pcap -Y dns -T fields -e dns.qry.type | sort | uniq -c | sort -rn

# semua DNS response dengan lebih dari 1 answer (bisa indikasi data ekstra disisipkan)
tshark -r capture.pcap -Y "dns.count.answers>1"

# ekstrak IP address hasil resolusi — cek kalau IP-nya aneh/tidak valid (data disamarkan sebagai IP)
tshark -r capture.pcap -Y "dns.flags.response==1 && dns.a" -T fields -e dns.qry.name -e dns.a
```

💡 **Tip**: Trik lain yang kadang dipakai soal CTF adalah menyisipkan data di **A record** itu sendiri — IP hasil resolve terlihat valid secara format (4 oktet 0-255) tapi sebenarnya adalah data yang di-encode jadi representasi IP. Kalau daftar IP hasil resolusi terlihat aneh/tidak masuk akal secara geografis/jaringan, coba convert oktet-nya ke ASCII atau hex.

---

## §5.7 Mini Checklist — DNS

- [ ] Sudah cek distribusi query per domain — ada domain dengan volume tidak wajar?
- [ ] Sudah cek panjang & entropy subdomain — terlihat encoded/acak?
- [ ] Sudah cek record type yang dipakai — ada TXT/NULL/CNAME dalam jumlah tidak wajar?
- [ ] Kalau ada tunneling terkonfirmasi, sudah dicoba reassembly + decode (base32/base64)
- [ ] Sudah cek kemungkinan DGA (banyak NXDOMAIN, domain acak)
- [ ] Sudah cek DNS di port tidak standar, atau traffic non-DNS di port 53
- [ ] Sudah cek A record — apakah IP hasil resolve masuk akal atau kemungkinan encoding data

---

## §5.8 Decision Tree — DNS

```
Traffic DNS terdeteksi
│
├─ Volume query wajar, domain bervariasi? ───→ kemungkinan bukan fokus soal,
│                                                cek protokol lain
├─ Satu domain menerima banyak query unik,
│  subdomain panjang/acak? ──────────────────→ DNS tunneling → reassembly (§5.3)
├─ Banyak NXDOMAIN, domain terlihat acak? ───→ kemungkinan DGA (§5.4)
├─ TXT/NULL record tidak wajar jumlahnya? ───→ cek data di record tersebut (§5.2, §5.3.1)
└─ A record dengan IP hasil resolve
   terlihat janggal? ───────────────────────→ kemungkinan data di-encode sebagai IP (§5.6)
```

---

**Selanjutnya**: §6 — FTP/Telnet/SSH, membahas credential extraction dari plaintext protocol, file transfer reconstruction, dan deteksi SSH tunnel dari metadata.
