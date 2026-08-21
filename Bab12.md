# Bab 12 — Custom/Unknown Binary Protocol

## §12.0 Pendahuluan

Ini adalah bab paling "manual" di seluruh series — tidak ada tool yang otomatis mem-parse protokol yang Wireshark sendiri tidak kenali. Soal CTF forensik jaringan level menengah-atas sering sengaja membuat protokol custom (baik di atas TCP maupun UDP) untuk menguji kemampuan reverse engineering traffic dari nol, bukan sekadar pakai tool yang sudah ada.

Bab ini menyatukan teknik dari bab-bab sebelumnya (§2 TCP reassembly, §3 UDP payload analysis) dan menambahkan pendekatan sistematis untuk mem-parsing sesuatu yang benar-benar tidak dikenal.

---

## §12.1 Identifikasi Awal — Kapan Protokol Dianggap "Custom"

Sinyal dari §1.2 (Protocol Hierarchy) yang menunjukkan protokol custom:
- Muncul sebagai `Data` polos di bawah TCP/UDP tanpa parsing lebih lanjut
- Port tidak standar dan tidak dikenali dissector Wireshark manapun
- Ukuran payload konsisten (indikasi struktur fixed-size) atau ada pola byte berulang di awal tiap paket (indikasi header/magic bytes)

```bash
tshark -r capture.pcap -Y "tcp.len>0 && !http && !ftp && !smtp" -T fields -e tcp.dstport | sort | uniq -c | sort -rn
```

---

## §12.2 Raw Hex Analysis — Langkah Pertama

```bash
# lihat raw hex payload untuk sample beberapa paket pertama
tshark -r capture.pcap -Y "tcp.port==1337" -x | head -100
```

```python
from scapy.all import *

packets = rdpcap("capture.pcap")
custom_packets = [p for p in packets if p.haslayer(TCP) and p[TCP].dport == 1337 and p.haslayer(Raw)]

for pkt in custom_packets[:10]:
    print(bytes(pkt[Raw].load).hex())
```

Yang dicari saat membandingkan beberapa paket berdampingan:

| Pola | Kemungkinan Arti |
|---|---|
| Beberapa byte pertama sama persis di semua paket | Magic bytes / protocol identifier |
| Byte tertentu berubah secara predictable (increment) | Sequence number / counter buatan aplikasi |
| Beberapa byte mengikuti panjang payload yang bervariasi sesuai isi | Length field |
| Byte acak yang berubah tiap paket tanpa pola jelas | Kemungkinan data terenkripsi, timestamp, atau nonce |

💡 **Tip**: Bikin tabel perbandingan manual dari 5-10 paket pertama, sejajarkan byte-by-byte (pakai spreadsheet atau print rapi di terminal) untuk mempercepat spotting pola. Ini investasi waktu yang worth it di awal, karena struktur yang berhasil diidentifikasi di sini menentukan seluruh pendekatan parsing berikutnya.

```python
for pkt in custom_packets[:5]:
    data = bytes(pkt[Raw].load)
    print(" ".join(f"{b:02x}" for b in data[:20]))
```

---

## §12.3 Mencari Magic Bytes / Header Signature

```bash
# cek apakah ada pola byte yang konsisten di awal payload seluruh paket ke port tertentu
tshark -r capture.pcap -Y "tcp.dstport==1337" -T fields -e data.data | cut -c1-8 | sort | uniq -c
```

Kalau ditemukan magic bytes konsisten (misal selalu `41 42 43 44` / `ABCD` di 4 byte pertama), itu bisa dipakai sebagai:
1. **Konfirmasi** bahwa paket tersebut memang bagian dari protokol yang sama (filter out noise)
2. **Anchor** untuk parsing byte-byte setelahnya sesuai posisi relatif

💡 **Tip**: Coba cari magic bytes tersebut di search engine atau di database file signature (seperti yang dipakai `binwalk`/`file` command) — kadang "protokol custom" ternyata reuse struktur dari sesuatu yang sudah dikenal (misal format serialisasi umum seperti Protobuf, MessagePack, atau bahkan struktur file yang di-tunnel).

---

## §12.4 Menulis Parser Manual dengan Python/Scapy

Setelah struktur diketahui (atau dihipotesiskan), tulis parser eksplisit:

```python
import struct
from scapy.all import *

def parse_custom_packet(payload):
    if len(payload) < 8:
        return None
    magic, seq, length = struct.unpack(">4sHH", payload[:8])
    if magic != b"ABCD":
        return None
    data = payload[8:8+length]
    return {"seq": seq, "length": length, "data": data}

packets = rdpcap("capture.pcap")
parsed = []
for pkt in packets:
    if pkt.haslayer(TCP) and pkt[TCP].dport == 1337 and pkt.haslayer(Raw):
        result = parse_custom_packet(bytes(pkt[Raw].load))
        if result:
            parsed.append(result)

parsed.sort(key=lambda x: x["seq"])
full_data = b"".join(p["data"] for p in parsed)
print(full_data)
```

⚠️ **Jebakan umum**: Endianness (byte order) sering jadi sumber bug saat parsing manual. Field yang terlihat "salah" (angka aneh/tidak masuk akal) sering karena salah asumsi big-endian (`>`) vs little-endian (`<`) di `struct.unpack`. Coba kedua kemungkinan kalau hasil parsing pertama terlihat tidak masuk akal.

```python
# coba kedua endianness kalau ragu
struct.unpack(">H", data[:2])  # big-endian
struct.unpack("<H", data[:2])  # little-endian
```

---

## §12.5 Menulis Dissector Wireshark Sederhana (Opsional, Lua)

Untuk kasus yang butuh analisis berulang atau visual di Wireshark GUI (bukan cuma sekali ekstrak lewat script), menulis dissector Lua sederhana bisa mempercepat kerja, terutama kalau capture-nya besar dan perlu explore interaktif.

```lua
-- custom_protocol.lua
local custom_proto = Proto("custom", "Custom CTF Protocol")

local f_magic = ProtoField.bytes("custom.magic", "Magic")
local f_seq = ProtoField.uint16("custom.seq", "Sequence")
local f_length = ProtoField.uint16("custom.length", "Length")
local f_data = ProtoField.bytes("custom.data", "Data")

custom_proto.fields = {f_magic, f_seq, f_length, f_data}

function custom_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "CUSTOM"
    local subtree = tree:add(custom_proto, buffer(), "Custom Protocol Data")
    subtree:add(f_magic, buffer(0,4))
    subtree:add(f_seq, buffer(4,2))
    subtree:add(f_length, buffer(6,2))
    local len = buffer(6,2):uint()
    if buffer:len() >= 8 + len then
        subtree:add(f_data, buffer(8, len))
    end
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(1337, custom_proto)
```

Cara pakai: taruh file `.lua` ini di folder plugin Wireshark (`Help > About Wireshark > Folders > Personal Lua Plugins`), lalu reload capture — traffic di port yang didaftarkan akan otomatis ter-parse sesuai struktur yang ditulis.

💡 **Tip**: Menulis dissector Lua **tidak selalu worth it** untuk soal CTF yang sifatnya one-off — kalau cuma butuh extract data sekali untuk dapat flag, script Python biasa (§12.4) jauh lebih cepat. Pertimbangkan dissector Lua hanya kalau capture besar dan butuh eksplorasi berulang-ulang secara visual.

---

## §12.6 Strategi Kalau Struktur Sama Sekali Tidak Jelas

Kadang tidak ada pola byte yang langsung terlihat. Pendekatan sistematis:

1. **Cek entropy payload** — payload dengan entropy tinggi mendekati random biasanya terenkripsi/terkompresi (lanjut ke §13), bukan struktur binary biasa yang bisa langsung dibaca.
2. **Bandingkan ukuran payload antar paket** — variasi ukuran bisa menunjukkan apakah ada length-prefixed field atau delimiter tertentu.
3. **Cek apakah komunikasi bidirectional simetris** — apakah client dan server pakai struktur yang sama, atau beda (request vs response biasanya beda struktur).
4. **Cari string readable di antara byte binary** — walau sebagian besar biner, sering ada fragmen string (nama fungsi, path, error message) yang bisa jadi petunjuk konteks protokol.

```bash
# ekstrak semua string yang bisa dibaca dari payload biner
tshark -r capture.pcap -Y "tcp.dstport==1337" -T fields -e data.data | xxd -r -p | strings
```

```python
# hitung entropy payload — bantu menentukan apakah data terenkripsi
import math
from collections import Counter

def entropy(data):
    if not data:
        return 0
    counts = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

# entropy mendekati 8 (untuk byte data) = kemungkinan terenkripsi/terkompresi
# entropy jauh di bawah 8 = kemungkinan ada struktur yang bisa dianalisis
print(entropy(bytes(pkt[Raw].load)))
```

⚠️ **Jebakan umum**: Entropy tinggi tidak selalu berarti "terenkripsi dengan aman" — bisa juga cuma terkompresi (gzip, zlib) yang jauh lebih mudah di-reverse daripada enkripsi asli. Coba dulu decompress dengan algoritma umum sebelum menyimpulkan itu harus di-crack sebagai enkripsi.

```python
import zlib, gzip

try:
    decompressed = zlib.decompress(data)
except Exception:
    pass

try:
    decompressed = gzip.decompress(data)
except Exception:
    pass
```

---

## §12.7 tshark Filter & One-Liner Ringkasan

```bash
# semua "Data" tidak dikenal Wireshark
tshark -r capture.pcap -Y "data && !http && !dns && !ftp"

# distribusi ukuran payload per port custom — bantu identifikasi fixed vs variable structure
tshark -r capture.pcap -Y "tcp.dstport==1337" -T fields -e tcp.len | sort -n | uniq -c

# ekstrak semua payload biner sekaligus ke file untuk analisis offline
tshark -r capture.pcap -Y "tcp.dstport==1337" -T fields -e data.data > raw_payloads_hex.txt

# bandingkan payload direction client→server vs server→client
tshark -r capture.pcap -Y "tcp.srcport==1337"  # server → client
tshark -r capture.pcap -Y "tcp.dstport==1337"  # client → server
```

---

## §12.8 Mini Checklist — Custom/Unknown Binary Protocol

- [ ] Sudah kumpulkan sample beberapa paket dan bandingkan byte-by-byte
- [ ] Sudah dicek apakah ada magic bytes/header signature konsisten
- [ ] Sudah dicoba hipotesis struktur (magic, seq/length field, data) dan divalidasi dengan parser sederhana
- [ ] Kalau parsing awal terlihat salah, sudah dicoba endianness alternatif
- [ ] Kalau tidak ada pola byte jelas, sudah dicek entropy untuk membedakan terenkripsi vs terkompresi vs terstruktur
- [ ] Sudah dicoba ekstrak string readable dari payload biner sebagai petunjuk konteks

---

## §12.9 Decision Tree — Custom/Unknown Binary Protocol

```
Protokol tidak dikenali Wireshark
│
├─ Ada magic bytes/pola konsisten di header? ─→ hipotesiskan struktur, tulis parser (§12.4)
│                                                 validasi dengan endianness yang benar
│
├─ Payload entropy tinggi (mendekati random)? ─→ coba decompress dulu (§12.6),
│                                                 kalau gagal → kemungkinan terenkripsi → Bab 13
│
├─ Ada string readable di antara byte biner? ──→ pakai sebagai petunjuk konteks/fungsi protokol
│
└─ Butuh eksplorasi visual berulang di
   capture besar? ────────────────────────────→ pertimbangkan tulis dissector Lua (§12.5)
```

---

**Selanjutnya**: §13 — Cryptography-in-Traffic, membahas cara spot dan extract data terenkripsi dari traffic, pola XOR key reuse, dan kombinasi soal crypto+forensic.
