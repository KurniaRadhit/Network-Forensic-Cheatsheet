# Cheatsheet — Wireshark Display Filter, tshark CLI, & Scapy

## §A.0 Pendahuluan

Dokumen ini adalah referensi pendamping (companion reference) untuk seluruh series Network Forensics CTF Cheatsheet (Bab 1–14). Isinya kumpulan filter/command yang paling sering dipakai, disusun per kategori supaya cepat dicari saat kompetisi — bukan pengganti bab per-protokol, tapi rujukan cepat kalau lupa syntax persis.

---

## §A.1 Sintaks Dasar Wireshark Display Filter

| Operator | Arti | Contoh |
|---|---|---|
| `==` / `eq` | Sama dengan | `ip.addr == 192.168.1.1` |
| `!=` / `ne` | Tidak sama dengan | `ip.addr != 192.168.1.1` |
| `>` `<` `>=` `<=` | Perbandingan numerik | `tcp.len > 100` |
| `&&` / `and` | DAN | `ip.src==1.1.1.1 && tcp.port==80` |
| `\|\|` / `or` | ATAU | `tcp.port==80 \|\| tcp.port==443` |
| `!` / `not` | Negasi | `!arp` |
| `contains` | Substring match | `http.host contains "evil"` |
| `matches` | Regex match | `http.host matches "^evil.*\\.com$"` |
| `in {}` | Cek keanggotaan set | `tcp.port in {80,443,8080}` |
| `[]` | Slice byte tertentu | `eth.src[0:3] == 00:1a:2b` |

💡 **Tip**: `contains` lebih cepat dari `matches` karena tidak butuh regex engine — pakai `contains` kalau cukup, simpan `matches` untuk pola yang benar-benar butuh regex.

⚠️ **Jebakan umum**: Display filter (`-Y` di tshark, kolom filter di GUI) berbeda dari **capture filter** (`-f` di tshark/tcpdump, dipakai saat capture live). Capture filter pakai sintaks BPF (`tcp port 80`), bukan sintaks display filter (`tcp.port==80`) — dua sintaks ini tidak bisa ditukar.

---

## §A.2 Filter Umum Lintas Protokol

```
frame.number == 100                     # paket nomor spesifik
frame.time >= "2026-01-01 00:00:00"     # filter waktu
frame.len > 1000                        # ukuran frame
ip.addr == 10.0.0.1                     # IP src ATAU dst
ip.src == 10.0.0.1                      # IP src saja
ip.dst == 10.0.0.1                      # IP dst saja
eth.addr == aa:bb:cc:dd:ee:ff           # MAC address
!(ip.addr == 10.0.0.1)                  # kecualikan IP tertentu
frame contains "flag"                    # cari string di raw frame
tcp.stream == 0                         # semua paket dalam satu TCP stream
udp.stream == 0                         # semua paket dalam satu UDP stream
```

---

## §A.3 Filter per Protokol (Ringkasan Lintas Bab)

### TCP (§2)
```
tcp.flags.syn==1 && tcp.flags.ack==0     # SYN saja (scan/handshake awal)
tcp.flags.reset==1                       # RST
tcp.flags==0x029                         # XMAS scan (FIN+PSH+URG)
tcp.flags==0x000                         # NULL scan
tcp.analysis.retransmission              # retransmisi
tcp.analysis.out_of_order                # paket out-of-order
tcp.analysis.duplicate_ack               # duplicate ACK
tcp.analysis.lost_segment                # segmen hilang
tcp.len > 0                              # TCP dengan payload
tcp.port in {21,22,23,80,443}            # multi-port
```

### UDP (§3)
```
udp && data                              # UDP dengan payload
udp.length > 8                           # payload lebih dari header kosong
icmp.type==3 && icmp.code==3             # ICMP port unreachable (indikasi UDP scan)
```

### HTTP/HTTPS (§4)
```
http.request                             # semua HTTP request
http.response                            # semua HTTP response
http.request.method == "POST"            # method tertentu
http.request.uri contains "admin"        # URI mengandung string
http.host == "example.com"               # host tertentu
http.cookie                              # ada cookie
http.authorization                       # ada Authorization header
http.content_type contains "image"       # tipe konten
tls.handshake.type == 1                  # TLS Client Hello
tls.handshake.extensions_server_name     # SNI
```

### DNS (§5)
```
dns                                      # semua traffic DNS
dns.flags.response == 0                  # query saja
dns.flags.response == 1                  # response saja
dns.qry.name contains "evil.com"         # query ke domain tertentu
dns.qry.type == 16                       # TXT record
dns.qry.type == 5                        # CNAME record
dns.qry.type == 10                       # NULL record
dns.flags.rcode == 3                     # NXDOMAIN
dns.count.answers > 1                    # response dengan banyak answer
```

### FTP/Telnet/SSH (§6)
```
ftp.request.command == "USER"            # command USER
ftp.request.command == "PASS"            # command PASS
ftp.request.command == "RETR"            # download file
ftp.request.command == "STOR"            # upload file
ftp.response.code == 227                 # PASV mode response
tcp.port == 23                           # Telnet
ssh.protocol                             # SSH banner/handshake
```

### ICMP (§7)
```
icmp.type == 8                           # Echo Request
icmp.type == 0                           # Echo Reply
icmp.type == 3                           # Destination Unreachable
icmp.type == 11                          # Time Exceeded (traceroute)
icmp.seq == 1                            # sequence number tertentu
icmp.id == 0x1234                        # ICMP session ID tertentu
```

### SMB (§8)
```
smb || smb2                              # semua traffic SMB
smb2.cmd == 3                            # Tree Connect
smb2.cmd == 5                            # Create
smb2.cmd == 8                            # Read
smb2.cmd == 9                            # Write
smb2.tree contains "ADMIN$"              # akses admin share
smb2.filename contains ".exe"            # transfer file executable
ntlmssp.auth                             # autentikasi NTLM
kerberos                                 # traffic Kerberos
kerberos.msg_type == 12                  # TGS-REQ (Kerberoasting check)
```

### USB (§9)
```
usb.transfer_type == 0x01                # Interrupt transfer (HID)
usb.transfer_type == 0x03                # Bulk transfer (Mass Storage)
usb.device_address == 5                  # device tertentu
usb.endpoint_address.direction == 1      # arah IN (device→host)
usb.bDescriptorType == 1                 # device descriptor (enumeration)
usb.data_len == 8                        # payload 8 byte (khas HID keyboard report)
```

### SMTP/POP3/IMAP (§10)
```
smtp.req.command == "MAIL"               # MAIL FROM
smtp.req.command == "RCPT"               # RCPT TO
smtp.req.command == "STARTTLS"           # upgrade ke TLS
pop.request.command == "USER"            # kredensial POP3
pop.request.command == "RETR"            # ambil email
imap.request contains "LOGIN"            # kredensial IMAP
imap.request contains "FETCH"            # ambil isi email
```

### SIP/RTP (§11)
```
sip.Method == "INVITE"                   # mulai panggilan
sip.Method == "BYE"                      # akhiri panggilan
sip.Call-ID == "abc123@host"             # filter satu sesi panggilan
sdp.media.port                           # port RTP dari SDP
rtp                                      # semua traffic RTP
rtp.ssrc == 0x12345678                   # satu RTP stream spesifik
```

### Custom/Encrypted (§12–13)
```
data && !http && !dns && !ftp            # payload tak dikenal dissector
tcp.port == 1337                         # port custom
```

### Wireless 802.11 (§14)
```
wlan.fc.type_subtype == 0x08             # Beacon frame
wlan.fc.type_subtype == 0x0c             # Deauthentication frame
eapol                                    # WPA handshake (EAPOL)
wlan.ssid == "TargetNetwork"             # SSID tertentu
```

---

## §A.4 tshark — Struktur Command Umum

```bash
tshark -r <file.pcap> [opsi]
```

| Opsi | Fungsi |
|---|---|
| `-r <file>` | Baca dari file pcap |
| `-Y "<filter>"` | Display filter (post-capture) |
| `-f "<filter>"` | Capture filter (BPF syntax, saat live capture) |
| `-T fields -e <field>` | Output field spesifik |
| `-T json` | Output JSON (untuk parsing lebih lanjut) |
| `-q` | Quiet, tanpa print tiap paket (dipakai bareng `-z`) |
| `-z <statistik>` | Statistik bawaan (io,phs / conv,tcp / dsb) |
| `-x` | Print raw hex + ASCII |
| `-c <n>` | Batasi jumlah paket diproses |
| `-2` | Two-pass analysis (aktifkan sebelum pakai beberapa fitur seperti reassembly penuh) |
| `--export-objects <proto>,<dir>` | Export file dari protokol tertentu |

### A.4.1 Kombinasi Field Extraction Umum
```bash
# ekstrak beberapa field sekaligus, output tab-separated
tshark -r cap.pcap -Y "http.request" -T fields -e frame.number -e ip.src -e http.host -e http.request.uri

# output ke CSV
tshark -r cap.pcap -Y "dns" -T fields -E separator=, -E quote=d -e frame.time -e dns.qry.name > output.csv
```

### A.4.2 Statistik Bawaan (-z)
```bash
tshark -r cap.pcap -q -z io,phs                 # Protocol Hierarchy
tshark -r cap.pcap -q -z conv,tcp                # TCP conversations
tshark -r cap.pcap -q -z conv,udp                # UDP conversations
tshark -r cap.pcap -q -z endpoints,ip             # daftar endpoint IP
tshark -r cap.pcap -q -z expert                  # expert info (warning/error otomatis)
tshark -r cap.pcap -q -z io,stat,1                # statistik I/O per 1 detik
tshark -r cap.pcap -q -z http,tree                # breakdown request HTTP per host/URI
tshark -r cap.pcap -q -z rtp,streams              # daftar RTP stream
tshark -r cap.pcap -q -z follow,tcp,ascii,0       # follow TCP stream index 0 (ascii)
tshark -r cap.pcap -q -z follow,tcp,raw,0         # follow TCP stream index 0 (raw hex)
```

### A.4.3 Export Objects per Protokol
```bash
tshark -r cap.pcap --export-objects http,./out_http/
tshark -r cap.pcap --export-objects smb,./out_smb/
tshark -r cap.pcap --export-objects smb2,./out_smb2/
tshark -r cap.pcap --export-objects ftp-data,./out_ftp/
tshark -r cap.pcap --export-objects smtp,./out_email/
tshark -r cap.pcap --export-objects tftp,./out_tftp/
tshark -r cap.pcap --export-objects dicom,./out_dicom/
```

### A.4.4 Utility Terkait
```bash
capinfos cap.pcap                        # info dasar file capture
editcap -A "2026-01-01 00:00:00" -B "2026-01-01 01:00:00" cap.pcap sliced.pcap  # potong berdasarkan waktu
mergecap -w merged.pcap file1.pcap file2.pcap  # gabung beberapa pcap
tshark -r cap.pcap -w filtered.pcap -Y "ip.addr==10.0.0.1"  # simpan hasil filter ke pcap baru
```

---

## §A.5 Scapy — Script Reference Cepat

### A.5.1 Baca & Iterasi Paket
```python
from scapy.all import *

packets = rdpcap("capture.pcap")
print(f"Total paket: {len(packets)}")

for pkt in packets:
    if pkt.haslayer(IP):
        print(pkt[IP].src, "->", pkt[IP].dst)
```

### A.5.2 Filter Paket berdasarkan Layer/Field
```python
tcp_pkts = [p for p in packets if p.haslayer(TCP)]
udp_pkts = [p for p in packets if p.haslayer(UDP)]
http_like = [p for p in packets if p.haslayer(TCP) and (p[TCP].sport == 80 or p[TCP].dport == 80)]
with_payload = [p for p in packets if p.haslayer(Raw)]
```

### A.5.3 Ekstraksi Raw Payload
```python
data = b"".join(bytes(p[Raw].load) for p in packets if p.haslayer(Raw))
with open("extracted.bin", "wb") as f:
    f.write(data)
```

### A.5.4 Reassembly Berdasarkan Sequence (TCP)
```python
target_port = 1337
pkts = sorted(
    [p for p in packets if p.haslayer(TCP) and p[TCP].dport == target_port and p.haslayer(Raw)],
    key=lambda p: p[TCP].seq
)
stream = b"".join(bytes(p[Raw].load) for p in pkts)
```

### A.5.5 Reassembly ICMP Berdasarkan Sequence (§7)
```python
icmp_pkts = sorted(
    [p for p in packets if p.haslayer(ICMP) and p[ICMP].type == 8 and p.haslayer(Raw)],
    key=lambda p: p[ICMP].seq
)
data = b"".join(bytes(p[Raw].load) for p in icmp_pkts)
```

### A.5.6 Grouping Berdasarkan Session ID (§7.3, §11)
```python
from collections import defaultdict

sessions = defaultdict(list)
for pkt in packets:
    if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
        sessions[pkt[ICMP].id].append((pkt[ICMP].seq, bytes(pkt[Raw].load)))

for sid, chunks in sessions.items():
    chunks.sort(key=lambda x: x[0])
    combined = b"".join(c[1] for c in chunks)
    print(f"Session {sid}: {combined[:50]}")
```

### A.5.7 Deteksi Port Scan (§2.5, §3.2)
```python
from collections import defaultdict

scan_map = defaultdict(set)
for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        scan_map[pkt[IP].src].add(pkt[TCP].dport)

for ip, ports in scan_map.items():
    if len(ports) > 20:
        print(f"{ip} scanned {len(ports)} ports")
```

### A.5.8 Parsing Struktur Custom dengan struct (§12.4)
```python
import struct

def parse(payload):
    if len(payload) < 8:
        return None
    magic, seq, length = struct.unpack(">4sHH", payload[:8])
    if magic != b"ABCD":
        return None
    return {"seq": seq, "data": payload[8:8+length]}

results = []
for pkt in packets:
    if pkt.haslayer(Raw):
        r = parse(bytes(pkt[Raw].load))
        if r:
            results.append(r)
results.sort(key=lambda x: x["seq"])
final = b"".join(r["data"] for r in results)
```

### A.5.9 Menulis Paket Baru / Filter ke File Baru
```python
filtered = [p for p in packets if p.haslayer(IP) and p[IP].src == "10.0.0.1"]
wrpcap("filtered.pcap", filtered)
```

### A.5.10 Live Sniffing (Kalau Butuh Capture Sendiri, Jarang Dipakai di CTF)
```python
def handle(pkt):
    if pkt.haslayer(Raw):
        print(bytes(pkt[Raw].load))

sniff(iface="eth0", prn=handle, filter="tcp port 1337", count=100)
```

### A.5.11 Entropy Check untuk Deteksi Data Terenkripsi (§12.6)
```python
import math
from collections import Counter

def entropy(data):
    if not data:
        return 0
    counts = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

for pkt in packets:
    if pkt.haslayer(Raw):
        e = entropy(bytes(pkt[Raw].load))
        if e > 7.5:
            print(f"Payload entropy tinggi ({e:.2f}) — kemungkinan terenkripsi/terkompresi")
```

---

## §A.6 Kombinasi tshark + Python (Pipeline Umum)

Pola paling sering dipakai: tshark untuk ekstraksi field cepat via JSON, lalu diproses lebih lanjut di Python.

```python
import subprocess, json

def tshark_json(pcap, display_filter, fields):
    cmd = ["tshark", "-r", pcap, "-Y", display_filter, "-T", "json"]
    for f in fields:
        cmd += ["-e", f]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout.strip() else []

data = tshark_json("capture.pcap", "http.request", ["http.host", "http.request.uri"])
for pkt in data:
    layers = pkt["_source"]["layers"]
    print(layers.get("http.host"), layers.get("http.request.uri"))
```

💡 **Tip**: Untuk dataset besar, tshark jauh lebih cepat dari scapy karena scapy me-load semua paket ke memori (`rdpcap`) sedangkan tshark bisa streaming. Kalau file pcap besar (ratusan MB+) dan cuma butuh ekstraksi field sederhana, prioritaskan tshark. Kalau butuh manipulasi struktur paket kompleks (reassembly custom, parsing struct manual), scapy lebih fleksibel.

---

## §A.7 Referensi Cepat — "Aku Butuh X, Command Apa?"

| Kebutuhan | Command |
|---|---|
| Lihat semua protokol yang ada di capture | `tshark -r cap.pcap -q -z io,phs` |
| Lihat siapa komunikasi paling banyak data | `tshark -r cap.pcap -q -z conv,tcp` |
| Baca isi percakapan TCP tertentu | `tshark -r cap.pcap -q -z follow,tcp,ascii,<stream_index>` |
| Extract semua file dari HTTP | `tshark -r cap.pcap --export-objects http,./out/` |
| Cari string tertentu di semua paket | `tshark -r cap.pcap -Y 'frame contains "flag"'` |
| Lihat warning/anomali otomatis | `tshark -r cap.pcap -q -z expert` |
| Simpan hasil filter ke pcap baru | `tshark -r cap.pcap -w out.pcap -Y "<filter>"` |
| Reassembly custom protocol | Scapy manual (§A.5.4, §A.5.8) |
| Decode base64 dari terminal | `echo "<str>" \| base64 -d` |
| Cek entropy payload (curiga enkripsi) | Python `entropy()` (§A.5.11) |

---

Cheatsheet ini akan terus relevan seiring bab-bab lain di series ditulis — kalau ada filter/command yang sering dipakai di Bab 13 (Cryptography-in-Traffic) atau Bab 14 (Wireless) nanti, bisa ditambahkan ke sini juga.
