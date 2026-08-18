# Bab 9 — USB Protocol

## §9.0 Pendahuluan

USB forensics sedikit berbeda dari bab-bab sebelumnya karena bukan traffic jaringan TCP/IP murni — tapi capture USB (`.pcap` hasil USBPcap di Windows atau `usbmon` di Linux) dianalisis dengan tool yang sama (Wireshark/tshark), jadi tetap masuk lingkup network forensics untuk keperluan CTF.

Dua skenario paling umum di CTF: **USB HID** (keyboard/mouse — rekonstruksi input yang diketik/diklik user) dan **USB Mass Storage** (file yang ditransfer via flashdisk — rekonstruksi file dari traffic block-level). Bab ini relevan langsung dengan pengalaman kamu membuat challenge "Typing" (USB HID keylogger).

---

## §9.1 Struktur Capture USB

### 9.1.1 Sumber Capture

| Platform | Tool Capture | Format |
|---|---|---|
| Windows | USBPcap (built-in di Wireshark for Windows) | `.pcapng` |
| Linux | usbmon (kernel module) | `.pcap` via `tshark -i usbmon0` |

```bash
# capinfos untuk cek info dasar file USB capture — sama seperti PCAP biasa
capinfos usb_capture.pcapng
```

### 9.1.2 Protocol Hierarchy USB

```bash
tshark -r usb_capture.pcapng -q -z io,phs
```

Field penting yang membedakan capture USB dari network biasa:

| Field | Kegunaan |
|---|---|
| `usb.transfer_type` | Jenis transfer: Control, Isochronous, Bulk, Interrupt |
| `usb.device_address` | Alamat device di bus USB |
| `usb.endpoint_address` | Endpoint tujuan/sumber data |
| `usb.data_len` | Panjang data payload |

💡 **Tip**: HID (keyboard/mouse) memakai **Interrupt transfer**, sedangkan Mass Storage memakai **Bulk transfer**. Filter berdasarkan `usb.transfer_type` di awal analisis untuk langsung fokus ke jenis device yang relevan dengan soal.

```bash
tshark -r usb_capture.pcapng -Y "usb.transfer_type==0x01"  # Interrupt (HID)
tshark -r usb_capture.pcapng -Y "usb.transfer_type==0x03"  # Bulk (Mass Storage)
```

---

## §9.2 Device Enumeration — Identifikasi Device

Sebelum device bisa dipakai, USB melewati proses enumeration (deskripsi device dikirim ke host). Ini berguna untuk tahu device apa saja yang terhubung selama capture.

```bash
tshark -r usb_capture.pcapng -Y "usb.bDescriptorType==1" -T fields -e usb.idVendor -e usb.idProduct
```

```bash
# lihat semua device address unik yang muncul — tiap device fisik dapat address berbeda
tshark -r usb_capture.pcapng -T fields -e usb.device_address | sort -un
```

💡 **Tip**: Cari `idVendor`/`idProduct` di database VID/PID online (misal linux-usb.org) untuk identifikasi merek/tipe device — berguna kalau soal minta "device apa yang dipakai attacker" sebagai bagian jawaban.

⚠️ **Jebakan umum**: Satu capture USB bisa berisi traffic dari **banyak device sekaligus** kalau semua terhubung ke controller yang sama (misal keyboard + mouse + flashdisk semua ke satu USB hub). Selalu filter berdasarkan `usb.device_address` untuk memisahkan traffic per-device sebelum analisis lebih lanjut, supaya tidak tercampur.

---

## §9.3 USB HID — Rekonstruksi Keystroke

### 9.3.1 Struktur HID Keyboard Report

Setiap keystroke keyboard dikirim sebagai **8-byte HID report**:

```
Byte 0: Modifier keys (Ctrl, Shift, Alt, Win — bitmask)
Byte 1: Reserved (selalu 0x00)
Byte 2-7: Up to 6 keycode yang sedang ditekan bersamaan (rollover)
```

```bash
# ekstrak data payload dari Interrupt transfer keyboard
tshark -r usb_capture.pcapng -Y "usb.transfer_type==0x01 && usb.data_len==8" -T fields -e usb.capdata
```

⚠️ **Jebakan umum**: Ada dua arah data di traffic HID — **IN** (device → host, ini yang berisi keystroke aktual) dan **OUT** (host → device, biasanya untuk LED status seperti Caps Lock/Num Lock, jarang relevan). Pastikan filter hanya mengambil arah IN (`usb.endpoint_address` dengan bit tertinggi set / `usb.src=="host"` dicek terbalik — cek di Wireshark field `usb.endpoint_address.direction==1` untuk IN).

```bash
tshark -r usb_capture.pcapng -Y "usb.transfer_type==0x01 && usb.endpoint_address.direction==1" -T fields -e usb.capdata
```

### 9.3.2 Decode Report Jadi Karakter

```python
import subprocess

# Mapping keycode HID Usage Table (subset umum, extend sesuai kebutuhan)
HID_KEYCODES = {
    0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x0b:'h',
    0x0c:'i',0x0d:'j',0x0e:'k',0x0f:'l',0x10:'m',0x11:'n',0x12:'o',0x13:'p',
    0x14:'q',0x15:'r',0x16:'s',0x17:'t',0x18:'u',0x19:'v',0x1a:'w',0x1b:'x',
    0x1c:'y',0x1d:'z',
    0x1e:'1',0x1f:'2',0x20:'3',0x21:'4',0x22:'5',0x23:'6',0x24:'7',0x25:'8',0x26:'9',0x27:'0',
    0x28:'\n',0x2c:' ',0x2d:'-',0x2e:'=',
}

# versi dengan shift ditekan (modifier bit 0x02 atau 0x20)
HID_KEYCODES_SHIFT = {
    0x1e:'!',0x1f:'@',0x20:'#',0x21:'$',0x22:'%',0x23:'^',0x24:'&',0x25:'*',0x26:'(',0x27:')',
    0x2d:'_',0x2e:'+',
}
HID_KEYCODES_SHIFT.update({k: v.upper() for k, v in HID_KEYCODES.items() if v.isalpha()})

result = subprocess.run(
    ["tshark", "-r", "usb_capture.pcapng",
     "-Y", "usb.transfer_type==0x01 && usb.endpoint_address.direction==1 && usb.data_len==8",
     "-T", "fields", "-e", "usb.capdata"],
    capture_output=True, text=True
)

output = ""
for line in result.stdout.splitlines():
    raw = bytes.fromhex(line.replace(":", ""))
    if len(raw) < 3:
        continue
    modifier = raw[0]
    keycode = raw[2]  # ambil key pertama yang ditekan
    if keycode == 0:
        continue  # key release / no key
    shift = bool(modifier & 0x22)
    table = HID_KEYCODES_SHIFT if shift else HID_KEYCODES
    output += table.get(keycode, f"[{keycode:02x}]")

print(output)
```

💡 **Tip**: Report dengan semua byte `0x00` berarti "tidak ada tombol ditekan" (key release event) — ini normal muncul di antara setiap keystroke karena HID mengirim laporan setiap kali status keyboard berubah, termasuk saat tombol dilepas. Filter/skip report kosong ini saat decode supaya hasil tidak ada spasi/karakter kosong berlebih.

⚠️ **Jebakan umum**: Kalau ada 2 report identik berturut-turut untuk tombol yang sama (bukan release di antaranya), itu bisa jadi **key repeat** dari auto-repeat OS, bukan user menekan dua kali. Perlu logic tambahan untuk membedakan repeat vs tekan ulang manual kalau soal butuh akurasi tinggi (biasanya tidak terlalu kritis untuk CTF, tapi perlu diperhatikan kalau hasil decode terlihat ada duplikasi aneh).

### 9.3.3 HID Mouse

Struktur laporan mouse berbeda dari keyboard (biasanya 3-4 byte: button state, delta X, delta Y, kadang scroll wheel). Kurang umum jadi fokus CTF dibanding keyboard, tapi kalau soal minta rekonstruksi gerakan/klik mouse, pendekatannya sama: ekstrak `usb.capdata` dari Interrupt transfer, lalu parse byte sesuai struktur HID mouse report descriptor.

---

## §9.4 USB Mass Storage — Ekstraksi File

USB flashdisk/storage memakai protokol **Bulk-Only Transport (BOT)** yang membawa perintah SCSI di dalamnya. Ini jauh lebih kompleks dari HID karena melibatkan command block, data transfer, dan status response.

```bash
# lihat command SCSI yang dikirim ke device storage
tshark -r usb_capture.pcapng -Y "usb.transfer_type==0x03" -T fields -e usb.capdata
```

Command SCSI yang relevan untuk forensik:

| SCSI Opcode | Command | Kegunaan |
|---|---|---|
| 0x28 | READ(10) | Baca block data — file yang dibaca dari flashdisk |
| 0x2A | WRITE(10) | Tulis block data — file yang ditulis ke flashdisk |
| 0x25 | READ CAPACITY | Info kapasitas device |
| 0x12 | INQUIRY | Info device (vendor, model) |

💡 **Tip**: Untuk kasus sederhana, cara paling efektif merekonstruksi file dari USB Mass Storage capture adalah dengan **merekonstruksi block-block data mentah** (bukan parsing command SCSI satu-satu secara manual), lalu treat hasilnya sebagai raw disk image dan analisis dengan tools forensik disk biasa (`mmls`, `fls` dari Sleuth Kit — lihat cross-reference ke series Windows DFIR Bab 1-2 soal disk forensics).

```python
from scapy.all import *

packets = rdpcap("usb_capture.pcapng")
# kumpulkan semua data response (Bulk IN dari device storage)
blocks = []
for pkt in packets:
    if pkt.haslayer(Raw):
        blocks.append(bytes(pkt[Raw].load))

with open("reconstructed_disk.img", "wb") as f:
    for b in blocks:
        f.write(b)
```

⚠️ **Jebakan umum**: Rekonstruksi manual block-by-block sangat rawan salah urutan atau kelewat command status (CSW — Command Status Wrapper) yang bukan bagian dari data file. Kalau soal capture-nya kompleks, pertimbangkan pakai tool khusus seperti `usbrip` atau parsing library USB BOT yang sudah menangani command/data/status wrapper dengan benar, daripada full manual dari scratch.

```bash
# setelah rekonstruksi jadi image, cek dengan tools disk forensik standar
file reconstructed_disk.img
mmls reconstructed_disk.img
```

---

## §9.5 tshark Filter & One-Liner Ringkasan USB

```bash
# semua device yang enumerate di capture
tshark -r usb_capture.pcapng -Y "usb.bDescriptorType==1" -T fields -e usb.idVendor -e usb.idProduct -e usb.device_address

# semua Interrupt transfer (HID) beserta payload
tshark -r usb_capture.pcapng -Y "usb.transfer_type==0x01" -T fields -e usb.device_address -e usb.capdata

# semua Bulk transfer (Mass Storage) beserta payload
tshark -r usb_capture.pcapng -Y "usb.transfer_type==0x03" -T fields -e usb.device_address -e usb.capdata

# hanya arah IN (device → host) — arah yang biasanya membawa data aktual
tshark -r usb_capture.pcapng -Y "usb.endpoint_address.direction==1" -T fields -e usb.capdata

# statistik jumlah paket per device address — bantu identifikasi device paling aktif
tshark -r usb_capture.pcapng -T fields -e usb.device_address | sort | uniq -c | sort -rn
```

---

## §9.6 Mini Checklist — USB Protocol

- [ ] Device enumeration sudah dicek — tahu device apa saja yang terhubung
- [ ] Traffic sudah dipisah per `usb.device_address` kalau ada banyak device
- [ ] Transfer type sudah diidentifikasi (Interrupt untuk HID, Bulk untuk Mass Storage)
- [ ] Kalau HID keyboard: report kosong (key release) sudah di-skip saat decode
- [ ] Kalau HID keyboard: modifier byte (shift) sudah diperhitungkan untuk karakter yang benar
- [ ] Kalau Mass Storage: sudah dicoba rekonstruksi jadi disk image, lalu dianalisis dengan tools disk forensik standar

---

## §9.7 Decision Tree — USB Protocol

```
Capture USB (USBPcap/usbmon) terdeteksi
│
├─ Device enumeration dulu ────→ identifikasi device (VID/PID)
│
├─ Interrupt transfer (HID)?
│  ├─ 8-byte report? ──────────→ kemungkinan keyboard → decode keystroke (§9.3.1-9.3.2)
│  └─ Report lebih pendek? ────→ kemungkinan mouse → parse sesuai HID mouse report (§9.3.3)
│
└─ Bulk transfer?
   └─ SCSI command terlihat
      (READ/WRITE)? ───────────→ Mass Storage → rekonstruksi disk image (§9.4),
                                   lanjut analisis dengan tools disk forensik standar
```

---

**Selanjutnya**: §10 — SMTP/POP3/IMAP, membahas extract email dari traffic, pemulihan attachment, dan deteksi header spoofing.
