# Step-by-Step: Analisa Stripped ELF Binary (x86 32-bit & x86_64) dengan pwndbg

> Format: setiap Langkah = command konkret → apa yang harus dicari di output → keputusan selanjutnya. Perbedaan 32-bit vs 64-bit ditandai eksplisit di tiap langkah karena **calling convention beda total** (stack-based vs register-based) — ini sumber kebingungan #1 saat pindah dari 64-bit ke 32-bit.

---

## Langkah 0 — Perbedaan Fundamental 32-bit vs 64-bit (baca dulu sebelum mulai)

| Aspek | x86 (32-bit) | x86_64 |
|---|---|---|
| Register general purpose | `eax, ebx, ecx, edx, esi, edi, ebp, esp` | `rax, rbx, ..., r8-r15` |
| Ukuran pointer | 4 byte | 8 byte |
| Calling convention (default) | **cdecl** — semua argumen lewat **stack** | **SysV AMD64** — 6 argumen pertama lewat **register** (`rdi,rsi,rdx,rcx,r8,r9`), sisanya stack |
| Return value | `eax` | `rax` |
| Syscall langsung | `int 0x80`, nomor syscall di `eax` | `syscall`, nomor syscall di `rax` (nomor **beda** dari 32-bit!) |
| Return address di stack | `esp+0` saat masuk fungsi | `rsp+0` saat masuk fungsi |
| Alignment stack sebelum `call` | 4-byte | wajib 16-byte aligned sebelum `call` (SysV ABI) |

🔴 Konsekuensi paling penting: di **32-bit**, argumen fungsi (termasuk `strcmp`, `printf`, dst) harus dibaca dari **stack** (`[esp+0x4]`, `[esp+0x8]`, ...), **bukan** dari register seperti di 64-bit. Command pwndbg untuk print argumen jadi beda (lihat Langkah 6).

---

## Langkah 1 — Baseline Recon (belum buka debugger)

```bash
file ./binary
```
Cari kata **"ELF 32-bit"** atau **"ELF 64-bit"** dan **"stripped"** di output ini — ini menentukan semua langkah setelahnya.

```bash
checksec ./binary
```
Catat 4 hal: **PIE** (Yes/No), **Canary** (Yes/No), **NX**, **RELRO**. Ini menentukan strategi eksploitasi kalau tujuannya bukan sekadar reversing logic tapi juga pwn.

```bash
readelf -d ./binary
```
Kalau ada baris `NEEDED libc.so.*` → **dynamically linked**, artinya PLT masih ada nama fungsi libc (lanjut Langkah 4 jalur A). Kalau kosong → **statically linked**, PLT tidak ada (lanjut jalur B, lebih sulit).

```bash
objdump -d -j .plt ./binary | grep '@plt' | head -30
```
List semua fungsi libc yang dipanggil binary — kasih gambaran awal apa yang dilakukan program (`scanf`, `strcmp`, `malloc`, `system`, dst) sebelum masuk debugger sama sekali.

---

## Langkah 2 — Buka pwndbg & Verifikasi Arsitektur Terdeteksi Benar

```bash
gdb ./binary
```
```gdb
pwndbg> context
```
Panel `REGISTERS` di atas akan menunjukkan set register yang sesuai arsitektur (`eax/ebx/...` untuk 32-bit, `rax/rbx/...` untuk 64-bit). Kalau binary 32-bit dijalankan di sistem 64-bit dan gdb salah detect arsitektur, jalankan manual:
```gdb
pwndbg> set architecture i386      # paksa 32-bit
pwndbg> set architecture i386:x86-64  # paksa 64-bit
```

⚠️ Untuk binary 32-bit di sistem Linux 64-bit, pastikan dependency 32-bit ter-install (`sudo apt install libc6-dbg:i386` atau `gdb-multiarch`), kalau tidak proses gagal `run` dengan error linker.

---

## Langkah 3 — Temukan Entry Point & Base Address (PIE-aware)

```gdb
pwndbg> entry
```
Ini setara `start` — break otomatis di `_start`, proses jalan sampai instruksi pertama.

```gdb
pwndbg> vmmap
```
Baris pertama yang match nama binary → ini **base address runtime**. Kalau binary **PIE**, alamat ini random tiap run (bandingkan 2x `run` untuk konfirmasi). Kalau **No PIE**, alamat selalu sama (biasanya `0x08048000` untuk 32-bit, `0x400000` untuk 64-bit).

```gdb
pwndbg> nearpc 15
```
Lihat 15 instruksi dari `_start`. Cari instruksi `call` pertama yang menuju fungsi besar — biasanya ini `__libc_start_main` (dynamically linked) atau langsung logic program (static/minimal binary).

---

## Langkah 4 — Temukan `main()` — JALUR A (Dynamically Linked)

### 4a. x86_64
```gdb
pwndbg> break __libc_start_main
pwndbg> run
pwndbg> print $rdi
```
`$rdi` = alamat `main()`. Langsung disas:
```gdb
pwndbg> x/30i $rdi
```

### 4b. x86 (32-bit) — BEDA! Argumen lewat stack, bukan register
```gdb
pwndbg> break __libc_start_main
pwndbg> run
pwndbg> x/4wx $esp
```
Argumen pertama `__libc_start_main` (alamat `main`) ada di **`[esp+0x4]`**, bukan di register manapun (cdecl: argumen didorong ke stack sebelum `call`, jadi urutan di stack adalah argumen 1, 2, 3, ... dari alamat rendah ke tinggi setelah return address di `[esp+0]`).
```gdb
pwndbg> print *(void**)($esp+0x4)
pwndbg> x/30i *(void**)($esp+0x4)
```

💡 Kalau `__libc_start_main` tidak ada (binary di-strip lebih agresif atau versi glibc berbeda), fallback: breakpoint di `entry`, lalu `nearpc 20`, cari pola `call` terakhir sebelum program benar-benar mulai baca input — itu kandidat kuat `main`.

---

## Langkah 5 — Temukan `main()` — JALUR B (Statically Linked, tanpa PLT)

Tidak bisa `break __libc_start_main` karena namanya juga hilang (fungsi ikut ter-inline/stripped). Strategi:

1. **Ghidra dulu (wajib untuk kasus ini):** jalankan auto-analysis + FID (Function ID) untuk match signature libc yang sudah dikenal. Ini akan auto-rename `main`, `malloc`, `printf`, dst meski file binary sendiri stripped.
2. Catat offset `main` dari Ghidra (alamat statis, biasanya berbasis `0x400000` atau `0x0` tergantung base image Ghidra).
3. Kembali ke pwndbg:
```gdb
pwndbg> break *$rebase(0xOFFSET_MAIN_DARI_GHIDRA)
pwndbg> run
```
`$rebase()` otomatis menjumlahkan base runtime (dari `vmmap`) + offset statis — command ini bekerja sama persis di 32-bit maupun 64-bit, tidak perlu hitung manual.

---

## Langkah 6 — Identifikasi Fungsi Validasi/Logic Inti

Setelah berhenti di `main`, scan isinya untuk `call` ke alamat non-PLT (fungsi buatan user, biasanya di range dekat `main` sendiri):

```gdb
pwndbg> nearpc 40
```
Cari pola: `call <alamat_dekat_main>` yang **bukan** menuju `.plt` (fungsi libc biasanya sudah ketahuan namanya di disas kalau dynamically linked — yang tanpa nama itulah kandidat fungsi user, mis. `check_password`).

Set breakpoint di situ:
```gdb
pwndbg> break *0x<alamat_fungsi_user>
pwndbg> continue
```

### 6a. Print argumen saat masuk fungsi — x86_64 (register)
```gdb
pwndbg> print $rdi     # argumen 1
pwndbg> print $rsi     # argumen 2
pwndbg> print $rdx     # argumen 3
```

### 6b. Print argumen saat masuk fungsi — x86 32-bit (stack)
```gdb
pwndbg> x/4wx $esp
```
Interpretasi hasil `x/4wx $esp`:
```
0xffffd000: 0xRETADDR  0xARG1  0xARG2  0xARG3
```
`[esp+0x0]` = return address, `[esp+0x4]` = argumen 1, `[esp+0x8]` = argumen 2, dst.
```gdb
pwndbg> print *(char**)($esp+0x4)     # kalau argumen 1 berupa pointer string
```

💡 pwndbg biasanya sudah otomatis menampilkan hint ini di panel `disasm` context (anotasi `arg[0]`, `arg[1]` di sebelah instruksi `call`) — perhatikan panel context sebelum manual hitung offset.

---

## Langkah 7 — Trace Pemanggilan `strcmp`/`memcmp` untuk Bocorkan Validasi

```gdb
pwndbg> break strcmp
pwndbg> commands
> x86_64: print (char*)$rdi
> x86_64: print (char*)$rsi
> 32-bit: print *(char**)($esp+0x4)
> 32-bit: print *(char**)($esp+0x8)
> continue
> end
pwndbg> run
```
(Pilih baris sesuai arsitektur — hapus baris yang tidak relevan.) Command ini otomatis print kedua argumen `strcmp` setiap kali dipanggil tanpa perlu manual `continue` berkali-kali — sering langsung menampilkan password/flag literal.

⚠️ Kalau binary **statically linked**, `break strcmp` gagal (nama tidak ada). Gunakan Ghidra FID dulu (Langkah 5) untuk temukan alamat `strcmp` versi statis, lalu `break *$rebase(offset)`.

---

## Langkah 8 — Cari Offset Buffer Overflow (kalau tujuan analisis adalah exploitasi)

```gdb
pwndbg> cyclic 300
```
Copy output pattern, jalankan program dengan pattern itu sebagai input, tunggu crash:
```gdb
pwndbg> run
(masukkan pattern sebagai input, program crash)
```

### 8a. x86_64 — cek `$rip`
```gdb
pwndbg> print $rip
pwndbg> cyclic -l $rip
```

### 8b. x86 32-bit — cek `$eip`
```gdb
pwndbg> print $eip
pwndbg> cyclic -l $eip
```
Sama-sama pakai `cyclic -l`, hanya register target beda (`$eip` vs `$rip`).

⚠️ Kalau ada stack canary (`checksec` → Canary: Yes), crash akan terjadi **sebelum** overwrite `$eip`/`$rip` (di fungsi `__stack_chk_fail`) — offset canary harus dicari terpisah, biasanya lebih pendek dari offset return address.

---

## Langkah 9 — Analisa Heap (jika binary pakai `malloc`/`free`, relevan untuk kedua arsitektur)

```gdb
pwndbg> heap
pwndbg> bins
pwndbg> vis_heap_chunks
```
Struktur chunk metadata **beda ukuran** antara 32-bit dan 64-bit (`size_t` 4 byte vs 8 byte), tapi command pwndbg-nya identik — pwndbg otomatis adjust berdasarkan arsitektur terdeteksi di Langkah 2. Tidak perlu command berbeda di sini.

---

## Langkah 10 — Handle PIE dengan `$rebase()` (berlaku sama di 32-bit & 64-bit)

```gdb
pwndbg> checksec
```
Kalau **PIE: Yes**:
```gdb
pwndbg> break *$rebase(0xOFFSET)
```
`OFFSET` diambil langsung dari alamat statis Ghidra/objdump (yang berbasis `0x0` atau `0x400000`/`0x08048000`) — pwndbg otomatis hitung `base_runtime + offset`, berfungsi sama di kedua arsitektur.

---

## Langkah 11 — Automasi dengan pwntools (gabungkan semua langkah di atas ke script)

```python
from pwn import *

context.binary = elf = ELF('./binary')
context.arch = 'i386'      # atau 'amd64' — sesuaikan hasil Langkah 1

io = process('./binary')

gdbscript = '''
break *$rebase(0xOFFSET_FUNGSI_TARGET)
continue
'''

gdb.attach(io, gdbscript=gdbscript)
io.interactive()
```

### 11a. Baca argumen otomatis sesuai arsitektur di script Python
```python
if context.arch == 'amd64':
    arg1 = io.child.regs.rdi   # (ilustrasi — pakai gdb.attach + gdbscript print untuk hal ini di praktiknya)
elif context.arch == 'i386':
    pass  # baca via stack, biasanya lebih praktis lewat gdbscript langsung (Langkah 6b)
```
💡 Untuk baca argumen real-time paling praktis tetap lewat `gdbscript` string (breakpoint + `commands` block seperti Langkah 7), bukan lewat Python murni — biarkan pwndbg yang urus perbedaan kalkulasi 32-bit vs 64-bit.

---

## Langkah 12 — Checklist Ringkas (urutan eksekusi penuh)

1. `file` + `checksec` + `readelf -d` → tentukan arsitektur & dynamic/static.
2. `gdb ./binary` → `entry` → `vmmap` (catat base kalau PIE).
3. Dynamic → `break __libc_start_main` cari `main` via `$rdi` (64-bit) / `[esp+4]` (32-bit).
   Static → Ghidra FID dulu, catat offset `main`, `break *$rebase(offset)`.
4. `nearpc` di `main`, identifikasi `call` ke fungsi user (bukan PLT).
5. Breakpoint di fungsi user, baca argumen: register (64-bit) atau `x/Nwx $esp` (32-bit).
6. `break strcmp`/`memcmp` + `commands` block untuk auto-leak input vs expected value.
7. Kalau butuh overflow: `cyclic 300` → crash → `cyclic -l $eip`/`$rip`.
8. Kalau ada heap: `heap` / `bins` / `vis_heap_chunks`.
9. Bungkus semua breakpoint di atas jadi satu `gdbscript` + `gdb.attach()` pwntools untuk automasi solve akhir.

---

## Referensi Silang
- Command dasar pwndbg & konsep `$rebase()` secara umum → cheatsheet *pwndbg Stripped Binary* Bab 4–5.
- Anti-debugging & Frida hooking kalau binary juga proteksi runtime → cheatsheet *Dynamic Analysis RE x86/x86_64* Bab 4 & 6.
- Static analysis awal (Ghidra FID, xref string) sebagai prasyarat Langkah 5 di atas → cheatsheet static analysis terpisah.
