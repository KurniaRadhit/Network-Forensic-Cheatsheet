# Bab 7 — ICMP

## §7.0 Pendahuluan

ICMP secara desain hanya untuk pesan kontrol/diagnostik jaringan (ping, error reporting) — bukan untuk transfer data. Justru karena itu, ICMP jadi covert channel favorit: banyak firewall mengizinkan ICMP lewat tanpa inspeksi ketat, sehingga sering dipakai untuk exfiltrasi data atau bahkan C2 communication tersembunyi.

Bab ini relevan langsung dengan pengalaman kamu di challenge USB HID ICMP keylogger ("Typing") dan TEROWONGAN — pola custom ICMP payload adalah tema yang sering berulang di CTF forensik jaringan.

---

## §7.1 Baseline — ICMP Normal vs Anomali

### 7.1.1 Struktur Echo Request/Reply Normal

Ping standar (ICMP Type 8 Echo Request / Type 0 Echo Reply) punya payload yang **konsisten dan predictable** — biasanya pattern byte berurutan (`0x08 0x09 0x0a ...`) yang diulang untuk mengisi ukuran default (32 atau 56 byte tergantung OS).

```bash
tshark -r capture.pcap -Y "icmp.type==8 || icmp.type==0" -T fields -e frame.number -e icmp.type -e data.len
```

| Indikasi Anomali | Penjelasan |
|---|---|
| Payload size tidak konsisten antar paket (harusnya sama semua kalau ping biasa) | Kemungkinan data custom disisipkan |
| Payload tidak mengikuti pattern byte berurutan standar OS | Data asli, bukan padding ping normal |
| Volume Echo Request/Reply sangat tinggi ke satu tujuan | Covert channel aktif, bukan sekadar network testing |
| ICMP Type selain 0/8 muncul dalam jumlah besar (Type 3, 5, 11, dsb) | Bisa jadi disalahgunakan untuk channel data, bukan error reporting asli |

💡 **Tip**: Cara cepat baseline — ambil satu paket ping ICMP yang "terlihat normal" di awal capture, catat pattern payload defaultnya, lalu bandingkan dengan paket-paket lain. Kalau semua konsisten dengan pattern itu, kemungkinan besar traffic ICMP-nya legit. Begitu ada satu yang menyimpang, itu titik awal investigasi.

---

## §7.2 Ekstraksi Payload ICMP

```bash
# ekstrak semua payload ICMP dalam hex
tshark -r capture.pcap -Y "icmp" -T fields -e frame.number -e data.data
```

```python
from scapy.all import *

packets = rdpcap("capture.pcap")
for pkt in packets:
    if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
        icmp_type = pkt[ICMP].type
        payload = bytes(pkt[Raw].load)
        print(f"Frame {pkt.time} | Type {icmp_type} | Len {len(payload)} | {payload[:32]}")
```

⚠️ **Jebakan umum**: Payload ICMP Echo Request/Reply di Wireshark kadang ditampilkan sebagai "Data" biasa tanpa parsing lebih lanjut — pastikan kamu ambil raw bytes-nya, bukan representasi yang sudah di-truncate di tampilan GUI. Untuk payload besar, selalu gunakan CLI/scripting daripada baca manual di GUI.

---

## §7.3 Reassembly Data dari Rangkaian Paket ICMP

Data yang di-exfiltrate lewat ICMP biasanya dipecah ke banyak paket Echo Request berurutan (mirip pola chunking di DNS tunneling, §5.3, tapi tanpa struktur query name).

```python
from scapy.all import *

packets = rdpcap("capture.pcap")
chunks = []

for pkt in packets:
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt.haslayer(Raw):
        # ICMP punya field 'seq' bawaan yang sering dipakai apa adanya sebagai index
        seq = pkt[ICMP].seq
        payload = bytes(pkt[Raw].load)
        chunks.append((seq, payload))

chunks.sort(key=lambda x: x[0])
data = b"".join(c[1] for c in chunks)

with open("icmp_reassembled.bin", "wb") as f:
    f.write(data)

print(data)
```

💡 **Tip**: Berbeda dengan UDP yang tidak punya sequence number bawaan (§3.3), ICMP Echo punya field `id` dan `seq` di header-nya sendiri (dipakai normal untuk mencocokkan reply dengan request). Field `seq` ini sering "dipinjam" apa adanya oleh pembuat soal sebagai index chunk data — cek dulu field ini sebelum bikin sistem reassembly custom sendiri.

⚠️ **Jebakan umum**: Kalau `id` field ICMP berbeda-beda antar paket yang seharusnya satu rangkaian data, itu bisa jadi indikasi ada **beberapa sesi tunneling paralel** tercampur di satu capture. Kelompokkan dulu berdasarkan `icmp.id` sebelum reassembly per grup, jangan langsung gabung semua paket ICMP jadi satu.

```python
from collections import defaultdict

sessions = defaultdict(list)
for pkt in packets:
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt.haslayer(Raw):
        sessions[pkt[ICMP].id].append((pkt[ICMP].seq, bytes(pkt[Raw].load)))

for icmp_id, chunks in sessions.items():
    chunks.sort(key=lambda x: x[0])
    combined = b"".join(c[1] for c in chunks)
    print(f"Session ID {icmp_id}: {combined[:64]}...")
```

---

## §7.4 Kasus Khusus — Custom Binary Payload di ICMP

Kalau payload ICMP bukan berupa string/data biasa tapi struktur binary custom (seperti pengalaman kamu di challenge "Typing" — USB HID keylogger yang mengirim data lewat ICMP), pendekatannya:

1. **Kumpulkan semua payload** dengan urutan yang benar (§7.3)
2. **Cek header/struktur di awal tiap payload** — apakah ada magic bytes, tipe pesan, atau length field di beberapa byte pertama
3. **Cek apakah payload mengikuti struktur HID report** kalau soal terkait keylogger — biasanya 8 byte per keystroke dengan format modifier + reserved + keycode array
4. Parse sesuai struktur yang ditemukan

```python
# contoh parsing kalau payload ternyata HID keyboard report (8 byte per event)
HID_KEYCODES = {
    0x04: 'a', 0x05: 'b', 0x06: 'c',  # dst, mapping lengkap sesuai USB HID Usage Table
    0x2c: ' ', 0x28: '\n',
}

for i in range(0, len(data), 8):
    report = data[i:i+8]
    if len(report) < 8:
        break
    modifier, reserved, *keys = report
    for k in keys:
        if k in HID_KEYCODES:
            print(HID_KEYCODES[k], end='')
```

Untuk detail lengkap parsing USB HID report (termasu mapping keycode penuh dan handling shift/modifier), lihat §9 (USB Protocol).

---

## §7.5 ICMP Error Messages sebagai Sumber Info

Selain Echo Request/Reply, tipe ICMP lain bisa jadi sumber info forensik:

| Type | Nama | Kegunaan Forensik |
|---|---|---|
| 3 | Destination Unreachable | Indikasi port/host scanning (lihat §2, §3), atau firewall block |
| 5 | Redirect | Indikasi kemungkinan MITM/ARP spoofing di jaringan lokal |
| 11 | Time Exceeded | Byproduct dari traceroute, bisa mengungkap topologi jaringan yang dilalui data |
| 8/0 | Echo Request/Reply | Ping normal, atau covert channel (fokus utama bab ini) |

```bash
# traceroute reconstruction dari Time Exceeded messages
tshark -r capture.pcap -Y "icmp.type==11" -T fields -e ip.src -e ip.dst -e frame.time_relative
```

💡 **Tip**: Kalau soal ceritanya melibatkan investigasi topologi jaringan atau "bagaimana attacker sampai ke target", cek apakah ada traceroute traffic (Time Exceeded messages) di capture — bisa mengungkap hop-hop jaringan yang dilalui, berguna untuk membangun peta jaringan investigasi.

---

## §7.6 tshark Filter & One-Liner Ringkasan ICMP

```bash
# semua paket ICMP dengan info dasar
tshark -r capture.pcap -Y icmp -T fields -e frame.number -e icmp.type -e icmp.code -e icmp.seq -e data.len

# distribusi ukuran payload — bantu spot yang menyimpang dari default OS
tshark -r capture.pcap -Y "icmp.type==8" -T fields -e data.len | sort -n | uniq -c

# kelompokkan berdasarkan icmp.id untuk pisahkan sesi paralel
tshark -r capture.pcap -Y icmp -T fields -e icmp.id | sort | uniq -c

# statistik I/O ICMP per detik — bantu lihat pola beaconing
tshark -r capture.pcap -Y icmp -q -z io,stat,1

# ekspor raw payload semua paket ICMP ke file terpisah untuk diproses lebih lanjut
tshark -r capture.pcap -Y icmp -T fields -e data.data > icmp_payloads_hex.txt
```

---

## §7.7 Mini Checklist — ICMP

- [ ] Baseline payload ping normal sudah dicek — ada paket yang menyimpang dari pattern default?
- [ ] Payload size sudah dicek konsistensinya
- [ ] Sudah dikelompokkan berdasarkan `icmp.id` kalau curiga ada multiple session paralel
- [ ] Reassembly sudah dicoba berdasarkan `icmp.seq` (bukan cuma urutan capture/timestamp)
- [ ] Kalau payload berupa struktur binary custom, sudah dicek magic bytes/header di awal payload
- [ ] ICMP error message (Type 3, 5, 11) sudah dicek sebagai info tambahan kalau relevan dengan cerita soal

---

## §7.8 Decision Tree — ICMP

```
Traffic ICMP terdeteksi
│
├─ Payload konsisten dengan pattern ping default OS? ──→ kemungkinan traffic legit,
│                                                          cek protokol lain
├─ Payload size/isi menyimpang dari default? ───────────→ covert channel, lanjut reassembly (§7.3)
│  │
│  ├─ Payload terlihat seperti teks/data terstruktur? ──→ decode langsung
│  └─ Payload binary tanpa pola jelas? ──────────────────→ cek magic bytes/header custom (§7.4),
│                                                           kemungkinan HID report atau protokol lain
│
└─ Banyak ICMP Type 3/11 (bukan Echo)? ─────────────────→ scan detection (§2, §3) atau traceroute (§7.5)
```

---

**Selanjutnya**: §8 — SMB/Windows Network Protocols, membahas file share extraction, deteksi lateral movement, dan pola pass-the-hash.
