# Bab 3 — UDP

## §3.0 Pendahuluan

UDP connectionless, tidak ada handshake, tidak ada guarantee delivery — analisisnya lebih sederhana dari sisi struktur dibanding TCP, tapi lebih sulit dari sisi "apakah data ini lengkap/berurutan" karena tidak ada sequence number bawaan. UDP jadi basis protokol seperti DNS (§5) dan berbagai custom protocol yang butuh latency rendah tanpa perlu reliability (streaming, game, IoT, dan — relevan untuk CTF — covert channel/exfiltration).

---

## §3.1 Karakteristik Dasar & Ekstraksi

```bash
tshark -r capture.pcap -Y "udp" -T fields -e ip.src -e ip.dst -e udp.srcport -e udp.dstport -e udp.length
```

Yang perlu dicek pertama kali:
- **Port UDP tidak standar** dengan payload berulang → kemungkinan custom protocol atau beacon (lihat §12)
- **Panjang payload konsisten** → kemungkinan protokol terstruktur (fixed-size packet, khas custom binary protocol atau game/IoT protocol)
- **DNS di port bukan 53, atau protokol lain menyamar sebagai DNS** → cek isi aktual payload, bukan cuma asumsi dari port

---

## §3.2 UDP Port Scanning Detection

Karena UDP tidak punya handshake, deteksi scan-nya berbeda dari TCP — mengandalkan respons ICMP dari host target.

```bash
# UDP port scan detection — banyak port dituju, tidak ada balasan (ICMP port unreachable)
tshark -r capture.pcap -Y "icmp.type==3 && icmp.code==3"
```

Paket ICMP type 3 code 3 (Destination Unreachable — Port Unreachable) yang banyak adalah indikasi kuat UDP port scan, karena ini respons standar OS ketika UDP packet dikirim ke port yang tidak listening.

```bash
# hitung jumlah port UDP unik yang dituju per source IP
tshark -r capture.pcap -T fields -e ip.src -e udp.dstport | sort | uniq -c | sort -rn | head -20
```

```python
# python: deteksi IP yang scan banyak port UDP dalam waktu singkat
from scapy.all import *
from collections import defaultdict

packets = rdpcap("capture.pcap")
scan_map = defaultdict(set)

for pkt in packets:
    if pkt.haslayer(UDP) and pkt.haslayer(IP):
        scan_map[pkt[IP].src].add(pkt[UDP].dport)

for ip, ports in scan_map.items():
    if len(ports) > 20:  # threshold, sesuaikan
        print(f"{ip} scanned {len(ports)} unique UDP ports — kemungkinan port scan")
```

⚠️ **Jebakan umum**: Tidak semua port UDP tertutup akan membalas ICMP unreachable — banyak firewall/host modern men-drop silent tanpa balasan. Jangan simpulkan "tidak ada ICMP unreachable = tidak ada scanning", cek juga pola banyak port dituju tanpa balasan sama sekali sebagai indikasi tambahan.

---

## §3.3 Payload Analysis & Reassembly

Karena UDP tidak reliable dan tidak ada sequence number bawaan seperti TCP, reassembly data yang terpecah ke banyak paket UDP (misal custom protocol atau exfiltration) butuh pendekatan berbeda — biasanya mengandalkan struktur payload itu sendiri (header custom dengan index/sequence buatan aplikasi).

```python
from scapy.all import *

packets = rdpcap("capture.pcap")
chunks = []

for pkt in packets:
    if pkt.haslayer(UDP) and pkt[UDP].dport == 9999 and pkt.haslayer(Raw):  # sesuaikan port
        chunks.append((pkt.time, bytes(pkt[Raw].load)))

# urutkan berdasarkan timestamp capture kalau tidak ada index eksplisit di payload
chunks.sort(key=lambda x: x[0])
data = b"".join(c[1] for c in chunks)

with open("udp_reassembled.bin", "wb") as f:
    f.write(data)
```

💡 **Tip**: Kalau payload UDP punya struktur fixed-size dengan beberapa byte awal yang terlihat seperti counter/index (misal `00 01`, `00 02`, `00 03`, ...), itu index buatan aplikasi untuk reassembly — pakai itu untuk sorting, bukan timestamp, karena lebih akurat kalau ada out-of-order delivery.

⚠️ **Jebakan umum**: Beda dengan TCP yang punya `tcp.seq` built-in di Wireshark, UDP tidak punya field sequence number di protokol itu sendiri. Jangan cari field seperti `udp.seq` — itu tidak ada. Sequence/index untuk reassembly (kalau ada) murni buatan protokol aplikasi di atasnya, harus di-parse manual dari payload.

---

## §3.4 tshark Filter & One-Liner Ringkasan UDP

```bash
# semua percakapan UDP dengan payload (bukan cuma header kosong)
tshark -r capture.pcap -Y "udp && data" -T fields -e ip.src -e ip.dst -e udp.dstport -e data.len

# distribusi ukuran payload UDP — bantu spot fixed-size custom protocol
tshark -r capture.pcap -Y "udp.length>8" -T fields -e udp.length | sort -n | uniq -c

# statistik I/O per detik untuk UDP — bantu lihat pola beaconing
tshark -r capture.pcap -Y udp -q -z io,stat,1

# lihat semua endpoint UDP unik beserta jumlah paketnya
tshark -r capture.pcap -q -z endpoints,udp
```

---

## §3.5 Mini Checklist — UDP

- [ ] Sudah cek apakah port yang dipakai standar (DNS, dsb) atau custom
- [ ] Sudah cek konsistensi ukuran payload — indikasi protokol terstruktur/fixed-size
- [ ] Sudah cek indikasi UDP port scan (ICMP port unreachable + jumlah port unik per IP)
- [ ] Kalau data terpecah ke banyak paket, sudah dicek apakah ada index/counter buatan aplikasi di payload untuk reassembly
- [ ] Kalau protokol tidak dikenali sama sekali, sudah dicatat untuk investigasi lanjut sebagai custom binary protocol

---

## §3.6 Decision Tree — UDP

```
Traffic UDP terdeteksi
│
├─ Port standar dikenali (53=DNS, dsb)? ─────→ lompat ke bab protokol terkait (§5 dst)
├─ Banyak ICMP port unreachable + banyak
│  port unik dituju? ────────────────────────→ UDP port scan (reconnaissance)
├─ Payload fixed-size, port custom,
│  berulang dengan pola tertentu? ───────────→ kemungkinan custom protocol → Bab 12
└─ Payload terlihat acak/tinggi entropy? ────→ kemungkinan data terenkripsi → Bab 13
```

---

**Selanjutnya**: §4 — HTTP/HTTPS, membahas extract file, follow stream, decrypt TLS via keylog, dan credential/header hunting.
