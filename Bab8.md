# Bab 8 — SMB/Windows Network Protocols

## §8.0 Pendahuluan

SMB (Server Message Block) adalah protokol file sharing dan komunikasi antar-host khas lingkungan Windows/Active Directory. Di soal CTF forensik jaringan, SMB biasanya muncul dalam konteks: file share yang bisa diekstrak, lateral movement antar host, atau credential relay/pass-the-hash yang jadi bukti serangan.

Bab ini melengkapi materi Active Directory & Enterprise Windows Forensics di series Windows DFIR kamu (Bab 10) — kalau bab itu fokus ke artefak host (EVTX, registry), bab ini fokus ke apa yang terlihat **di traffic jaringan** saat aktivitas SMB/AD terjadi.

---

## §8.1 Baseline — Versi SMB & Struktur Dasar

SMB punya beberapa versi (SMBv1, SMBv2, SMBv3) dengan karakteristik berbeda. SMBv1 sudah deprecated karena rentan (EternalBlue/WannaCry memanfaatkan SMBv1), jadi kalau muncul di capture modern, itu sendiri sudah jadi red flag.

```bash
tshark -r capture.pcap -Y "smb || smb2" -T fields -e frame.number -e ip.src -e ip.dst
```

```bash
# cek versi SMB yang dipakai
tshark -r capture.pcap -Y "smb" -T fields -e smb.cmd     # SMBv1
tshark -r capture.pcap -Y "smb2" -T fields -e smb2.cmd   # SMBv2/v3
```

⚠️ **Jebakan umum**: Kalau soal capture menunjukkan SMBv1 di jaringan modern, ini bisa jadi petunjuk kuat cerita soal (misal eksploitasi kerentanan SMBv1) — jangan lewatkan begitu saja dengan asumsi "cuma versi lama".

---

## §8.2 Autentikasi SMB & Credential Extraction

### 8.2.1 NTLM Authentication

SMB umumnya pakai NTLM (atau Kerberos di lingkungan AD) untuk autentikasi. NTLM handshake terlihat di traffic sebagai beberapa pesan berurutan.

```bash
tshark -r capture.pcap -Y "ntlmssp"
```

```bash
# ekstrak NTLM challenge/response untuk keperluan cracking offline
tshark -r capture.pcap -Y "ntlmssp.auth" -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain -e ntlmssp.ntlmv2_response
```

💡 **Tip**: NTLM tidak mengirim password plaintext, tapi challenge-response yang **bisa di-crack offline** dengan tools seperti `hashcat` atau `john`, kalau format hash-nya berhasil direkonstruksi dari traffic. Format umum untuk hashcat: `username::domain:challenge:HMAC-MD5:blob`. Untuk ekstraksi otomatis, gunakan tool seperti `ntlmssp-extractor` atau parsing manual dari field-field di atas.

### 8.2.2 Kerberos (Lingkungan AD)

```bash
tshark -r capture.pcap -Y "kerberos"
```

```bash
# ekstrak AS-REQ/AS-REP untuk analisis (misal AS-REP roasting scenario)
tshark -r capture.pcap -Y "kerberos.msg_type==10 || kerberos.msg_type==11" -T fields -e kerberos.CNameString -e kerberos.realm
```

⚠️ **Jebakan umum**: Kerberos ticket (TGT/TGS) tidak bisa dibaca isinya tanpa key yang sesuai (biasanya derivasi dari password/hash akun servis atau krbtgt), jadi jangan berharap bisa "baca isi tiket" langsung dari traffic. Yang bisa digali dari traffic adalah **metadata** — siapa request ticket untuk servis apa, kapan, dan pola request yang bisa mengindikasikan serangan seperti Kerberoasting (banyak TGS-REQ untuk servis berbeda dalam waktu singkat) atau AS-REP Roasting (request AS-REQ untuk akun dengan pre-authentication disabled).

```bash
# deteksi pola Kerberoasting — banyak TGS-REQ dari satu source dalam waktu singkat
tshark -r capture.pcap -Y "kerberos.msg_type==12" -T fields -e ip.src -e kerberos.SNameString | sort | uniq -c | sort -rn
```

---

## §8.3 File Share Extraction

```bash
# export file yang ditransfer lewat SMB
tshark -r capture.pcap --export-objects smb,./extracted_smb/
tshark -r capture.pcap --export-objects smb2,./extracted_smb2/
```

```bash
# lihat operasi file (Create, Read, Write, Close) untuk rekonstruksi aktivitas
tshark -r capture.pcap -Y "smb2.cmd==5" -T fields -e smb2.filename   # Create
```

| SMB2 Command Code | Operasi |
|---|---|
| 0 | Negotiate Protocol |
| 1 | Session Setup |
| 3 | Tree Connect (akses ke share tertentu) |
| 5 | Create (buka/buat file) |
| 8 | Read |
| 9 | Write |
| 6 | Close |

```bash
# lihat share mana saja yang diakses
tshark -r capture.pcap -Y "smb2.cmd==3" -T fields -e smb2.tree
```

💡 **Tip**: Kalau file tidak bisa diekstrak otomatis lewat Export Objects (misal file besar yang datanya terpecah di banyak Read response), rekonstruksi manual dengan mengumpulkan semua `smb2.cmd==8` (Read Response) untuk file/handle yang sama, urutkan berdasarkan offset yang diminta di Read Request-nya.

---

## §8.4 Deteksi Lateral Movement

Lateral movement lewat SMB biasanya melibatkan admin share (`C$`, `ADMIN$`, `IPC$`) dan sering dikombinasikan dengan eksekusi remote command (PsExec-style) atau penempatan file executable.

```bash
# cek akses ke admin share — indikasi kuat aktivitas administratif/lateral movement
tshark -r capture.pcap -Y "smb2.tree contains \"C$\" || smb2.tree contains \"ADMIN$\" || smb2.tree contains \"IPC$\""
```

```bash
# cek file .exe/.dll/.bat yang ditransfer lewat SMB — kemungkinan payload
tshark -r capture.pcap -Y "smb2.filename contains \".exe\" || smb2.filename contains \".dll\" || smb2.filename contains \".bat\""
```

| Pola | Indikasi |
|---|---|
| Akses ke `ADMIN$` diikuti transfer file `.exe` | Kemungkinan PsExec/remote execution |
| Named pipe access (`\\PIPE\\svcctl`, `\\PIPE\\atsvc`) | Kemungkinan remote service creation atau scheduled task (khas tools lateral movement) |
| Satu host mengakses share di banyak host lain dalam waktu singkat | Kemungkinan scanning/spreading otomatis |

```bash
# cek akses named pipe spesifik yang sering dipakai tools lateral movement
tshark -r capture.pcap -Y "smb2.tree contains \"IPC$\"" -Y "smb2.filename contains \"svcctl\" || smb2.filename contains \"atsvc\" || smb2.filename contains \"winreg\""
```

⚠️ **Jebakan umum**: Akses ke admin share dan named pipe **tidak selalu berarti serangan** — banyak tool administrasi legit (Group Policy, monitoring tools) juga memakainya. Cek konteks: apakah aktivitas ini datang dari host yang seharusnya punya akses administratif, apakah waktunya masuk akal (jam kerja vs tengah malam), dan apakah diikuti pola mencurigakan lain (transfer file executable tidak dikenal, dsb).

---

## §8.5 Pass-the-Hash Pattern

Pass-the-hash memakai NTLM hash langsung untuk autentikasi tanpa perlu tahu password plaintext. Dari sisi traffic, ini terlihat sebagai autentikasi NTLM yang berhasil tanpa didahului aktivitas yang biasanya menyertai login normal (misal tidak ada interactive logon event terkait di host, kalau dikombinasikan dengan analisis EVTX — lihat series Windows DFIR Bab 10).

```bash
# ekstrak semua sesi autentikasi NTLM yang berhasil, untuk cross-reference dengan log host
tshark -r capture.pcap -Y "ntlmssp.auth" -T fields -e frame.time -e ip.src -e ip.dst -e ntlmssp.auth.username
```

💡 **Tip**: Deteksi pass-the-hash murni dari network traffic saja terbatas — traffic-nya terlihat sama seperti autentikasi NTLM normal. Indikasi kuat biasanya datang dari **kombinasi** dengan info lain: user yang sama login dari banyak host berbeda dalam waktu singkat, atau host yang login tidak pernah dipakai user tersebut sebelumnya (butuh baseline/cross-reference, sering dikombinasikan dengan analisis log Windows di luar PCAP).

---

## §8.6 tshark Filter & One-Liner Ringkasan SMB

```bash
# semua tree connect (share yang diakses) beserta source IP
tshark -r capture.pcap -Y "smb2.cmd==3 && smb2.flags.response==0" -T fields -e ip.src -e smb2.tree

# semua file yang dibuat/dibuka
tshark -r capture.pcap -Y "smb2.cmd==5 && smb2.flags.response==0" -T fields -e ip.src -e smb2.filename

# ringkasan sesi autentikasi NTLM
tshark -r capture.pcap -Y "ntlmssp.auth" -T fields -e ip.src -e ip.dst -e ntlmssp.auth.username -e ntlmssp.auth.domain

# ringkasan aktivitas Kerberos
tshark -r capture.pcap -Y "kerberos" -T fields -e ip.src -e ip.dst -e kerberos.msg_type

# statistik conversation SMB — siapa paling banyak transfer data
tshark -r capture.pcap -q -z conv,tcp | grep ":445"
```

---

## §8.7 Mini Checklist — SMB/Windows Network Protocols

- [ ] Versi SMB sudah dicek — ada SMBv1 yang mencurigakan?
- [ ] Kredensial/hash NTLM sudah diekstrak untuk kemungkinan cracking offline
- [ ] Kalau ada Kerberos, sudah dicek pola Kerberoasting/AS-REP Roasting
- [ ] File share sudah diekstrak (Export Objects atau manual dari Read Response)
- [ ] Akses admin share (`C$`, `ADMIN$`, `IPC$`) sudah dicek
- [ ] File executable yang ditransfer lewat SMB sudah diidentifikasi
- [ ] Named pipe access yang khas lateral movement tools sudah dicek
- [ ] Pola login yang tidak wajar (host/user kombinasi aneh) sudah dicek untuk indikasi pass-the-hash

---

## §8.8 Decision Tree — SMB/Windows Network Protocols

```
Traffic SMB terdeteksi
│
├─ Ada file transfer? ───────────────────────→ extract (§8.3), cek tipe file
│  └─ File executable/script? ───────────────→ kemungkinan payload lateral movement
│
├─ Akses admin share / named pipe khas
│  lateral movement tools? ──────────────────→ investigasi lebih dalam (§8.4)
│
├─ Autentikasi NTLM terdeteksi? ─────────────→ extract hash untuk cracking (§8.2.1)
│
├─ Kerberos traffic ada? ────────────────────→ cek pola Kerberoasting/AS-REP Roasting (§8.2.2)
│
└─ Login pattern tidak wajar
   (user sama, banyak host, waktu singkat)? ─→ kemungkinan pass-the-hash (§8.5),
                                                cross-reference dengan log host jika tersedia
```

---

**Selanjutnya**: §9 — USB Protocol, membahas analisis capture USBPcap/usbmon, rekonstruksi keystroke HID, dan ekstraksi file dari USB Mass Storage traffic.
