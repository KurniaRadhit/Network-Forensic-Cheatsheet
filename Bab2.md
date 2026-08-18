# Bab 2 — TCP

## §2.0 Pendahuluan

TCP adalah protokol transport paling umum jadi fondasi protokol aplikasi (HTTP, FTP, SMB, dsb). Banyak soal CTF forensik jaringan fokus di level ini sebelum masuk ke protokol aplikasi — pola handshake, TCP flag yang dimanipulasi untuk scanning/evasion, retransmission tidak wajar, atau reassembly stream mentah kalau protokol aplikasinya custom/tidak dikenali Wireshark.

Bab ini jadi fondasi untuk §12 (Custom/Unknown Binary Protocol) — kalau protokol aplikasi tidak dikenali, kamu akan bekerja langsung di level TCP payload seperti dibahas di sini.

---

## §2.1 TCP Handshake Forensik

### 2.1.1 Three-Way Handshake Normal
```
Client → Server: SYN
Server → Client: SYN, ACK
Client → Server: ACK
```

```bash
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0"
```

Yang dicari saat review handshake:

| Pola | Indikasi |
|---|---|
| Banyak SYN tanpa SYN-ACK balasan | Port scanning (SYN scan) |
| SYN diikuti langsung RST | Port tertutup, atau firewall block |
| Handshake berhasil tapi tidak ada data setelahnya | Koneksi test/beacon, bukan transfer data asli |
| Multiple SYN dari IP sama ke port berbeda-beda dalam waktu singkat | Port scan aktif (lihat §2.6) |

### 2.1.2 Cek Retransmission
```bash
tshark -r capture.pcap -Y "tcp.analysis.retransmission"
```

Retransmission wajar terjadi di jaringan asli (packet loss), tapi kalau soal CTF berbasis capture buatan/simulasi dan retransmission-nya banyak & berpola, ini bisa jadi sengaja dibuat — misal sebagai bagian dari covert timing channel (data disandikan lewat interval retransmisi).

---

## §2.2 TCP Flags & Red Flags Reconnaissance

Kombinasi TCP flag yang tidak normal sering dipakai untuk scanning stealth — penting dikenali karena soal CTF sering menampilkan pola scan sebagai bagian dari cerita/investigasi.

| Nama Scan | Flag yang Dipakai | Filter tshark |
|---|---|---|
| SYN scan | SYN saja | `tcp.flags.syn==1 && tcp.flags.ack==0` |
| FIN scan | FIN saja | `tcp.flags.fin==1 && tcp.flags==0x001` |
| NULL scan | Tidak ada flag sama sekali | `tcp.flags==0x000` |
| XMAS scan | FIN, PSH, URG bersamaan | `tcp.flags==0x029` |
| ACK scan | ACK saja (untuk deteksi firewall) | `tcp.flags.ack==1 && tcp.flags.syn==0` |

```bash
# cek semua kombinasi flag unik yang muncul di capture — cepat spot yang aneh
tshark -r capture.pcap -T fields -e tcp.flags | sort | uniq -c | sort -rn
```

💡 **Tip**: Kalau muncul satu IP yang mengirim banyak paket dengan berbagai kombinasi flag ke banyak port berbeda dalam waktu singkat, itu hampir pasti scanning tool (nmap, masscan, dsb). Cek `Statistics > Conversations` untuk konfirmasi jumlah port unik yang dituju.

⚠️ **Jebakan umum**: Jangan bingung antara "port scan" (reconnaissance, bagian dari cerita soal) dengan "protokol custom yang kebetulan pakai flag tidak umum" (bagian dari komunikasi data asli, relevan ke §12). Cek apakah ada payload data di paket-paket tersebut — scan murni biasanya tidak membawa data, komunikasi custom protocol biasanya membawa.

---

## §2.3 Stream Reassembly Manual

Untuk kasus di mana protokol aplikasi tidak dikenali Wireshark (custom protocol di atas TCP), kamu perlu reassembly manual dari raw TCP stream.

```bash
# reassembly stream index tertentu ke file mentah
tshark -r capture.pcap -q -z follow,tcp,raw,0 > stream0_raw.txt
```

Atau langsung ke hex/binary dengan scapy untuk diproses python:

```python
from scapy.all import *

packets = rdpcap("capture.pcap")
stream_data = b""

for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if pkt[TCP].sport == 1337 or pkt[TCP].dport == 1337:  # sesuaikan port
            stream_data += bytes(pkt[Raw].load)

with open("reassembled.bin", "wb") as f:
    f.write(stream_data)
```

⚠️ **Jebakan umum**: Reassembly manual harus memperhitungkan **sequence number**, bukan cuma urutan capture, karena paket bisa datang out-of-order (terutama di capture yang melibatkan multiple path atau retransmission). Untuk kasus sederhana urutan capture biasanya cukup, tapi kalau data hasil reassembly terlihat rusak/acak, cek ulang dengan sorting berdasarkan `tcp.seq`.

```python
# reassembly dengan sorting berdasarkan sequence number
packets_sorted = sorted(
    [p for p in packets if p.haslayer(TCP) and p.haslayer(Raw) and p[TCP].dport == 1337],
    key=lambda p: p[TCP].seq
)
stream_data = b"".join(bytes(p[Raw].load) for p in packets_sorted)
```

---

## §2.4 Sequence & ACK Number Analysis

Berguna untuk mendeteksi **session hijacking** atau **packet injection** — kadang muncul di soal CTF yang temanya MITM/traffic tampering.

```bash
tshark -r capture.pcap -Y "tcp.analysis.out_of_order"
tshark -r capture.pcap -Y "tcp.analysis.duplicate_ack"
tshark -r capture.pcap -Y "tcp.analysis.lost_segment"
```

💡 **Tip**: Wireshark punya built-in expert analysis yang otomatis flag anomali ini. Cek `Analyze > Expert Information` untuk ringkasan cepat semua warning/error yang terdeteksi di seluruh capture — sering langsung menunjuk ke paket yang jadi kunci soal.

```bash
tshark -r capture.pcap -q -z expert
```

---

## §2.5 Port Scanning Pattern (TCP)

```bash
# hitung jumlah port unik yang dituju per source IP — deteksi scan
tshark -r capture.pcap -T fields -e ip.src -e tcp.dstport | sort | uniq -c | sort -rn | head -20
```

```python
# python: deteksi IP yang scan banyak port dalam waktu singkat
from scapy.all import *
from collections import defaultdict

packets = rdpcap("capture.pcap")
scan_map = defaultdict(set)

for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        scan_map[pkt[IP].src].add(pkt[TCP].dport)

for ip, ports in scan_map.items():
    if len(ports) > 20:  # threshold, sesuaikan
        print(f"{ip} scanned {len(ports)} unique ports — kemungkinan port scan")
```

💡 **Tip**: Kalau soal ceritanya "attacker melakukan reconnaissance sebelum eksploitasi", cari dulu pola scanning ini untuk menentukan target/port yang jadi fokus serangan berikutnya — biasanya port yang "ditemukan terbuka" itulah yang relevan ke bagian soal selanjutnya (misal port HTTP custom, atau port protokol custom di §12).

---

## §2.6 tshark Filter & One-Liner Ringkasan TCP

```bash
# semua koneksi TCP yang berhasil handshake penuh (3-way complete)
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==1"

# koneksi TCP yang di-reset paksa
tshark -r capture.pcap -Y "tcp.flags.reset==1"

# distribusi ukuran payload TCP — bantu spot fixed-size custom protocol
tshark -r capture.pcap -Y "tcp.len>0" -T fields -e tcp.len | sort -n | uniq -c

# statistik I/O per detik — bantu lihat pola beaconing/timing channel
tshark -r capture.pcap -q -z io,stat,1
```

---

## §2.7 Mini Checklist — TCP

- [ ] Sudah cek pola handshake — ada indikasi scanning atau koneksi janggal?
- [ ] Sudah cek kombinasi TCP flags yang tidak umum (`tcp.flags` unique values)
- [ ] Expert Information sudah direview untuk anomali otomatis (retransmission, out-of-order, dsb)
- [ ] Kalau protokol aplikasi tidak dikenali Wireshark, sudah dicoba reassembly manual berdasarkan sequence number
- [ ] Sudah cek indikasi port scanning (jumlah port unik per source IP)

---

## §2.8 Decision Tree — TCP

```
Traffic TCP terdeteksi anomali di level ini
│
├─ Pola SYN/scan ke banyak port? ────────────→ reconnaissance,
│                                                catat target port untuk investigasi lanjut
├─ Flag kombinasi tidak umum tapi ada payload
│  data (bukan cuma scan)? ──────────────────→ kemungkinan custom protocol → Bab 12
├─ Retransmission/timing pattern berulang
│  & tidak wajar untuk jaringan normal? ─────→ kemungkinan covert timing channel
└─ Protokol aplikasi dikenali Wireshark
   (HTTP/FTP/SMB/dsb)? ───────────────────────→ lompat ke bab protokol terkait (§4 dst)
```

---

**Selanjutnya**: §3 — UDP, membahas karakteristik connectionless, deteksi port scan UDP, dan pola protokol terstruktur di atas UDP.
