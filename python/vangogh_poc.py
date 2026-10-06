#!/usr/bin/env python3
"""fm-vangogh reference POC (Python).

The shipping tool is the Rust crate at the repo root. This single file is the
readable reference and test oracle for the EAR protocol: derive the key, decrypt,
and crack with a wordlist. Pure standard library (uses the bundled pure-Python
aes.py). Not optimised; the Rust version is the fast, GPU-capable one.

    python3 vangogh_poc.py info    <file.fmp12>
    python3 vangogh_poc.py decrypt <file.fmp12> <password> [out.fmp12]
    python3 vangogh_poc.py crack   <file.fmp12> <wordlist.txt>
"""

import os
import re
import sys
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aes  # pure-Python AES-256

SECTOR, BODY, SALT_OFF, SALT_LEN, KDF_ITER = 4096, 4064, 0xFA, 16, 18000
CHECK_SECTORS, GATE_SECTORS, GATE_BYTES, GATE_MIN_MAXBIN = 48, 2, 256, 32
_VER = re.compile(rb'(?:Pro|Server|Go|Advanced|FileMaker) ?\d{1,2}\.\d')


def is_encrypted(data):
    return data[0x0F:0x14] == b"HBAMe"


def read_hint(data):
    head, best = data[:SALT_OFF], ""
    for start in range(0x10, len(head) - 1, 2):
        run, i = bytearray(), start
        while i + 1 < len(head) and head[i + 1] == 0 and 0x20 <= head[i] < 0x7F:
            run.append(head[i]); i += 2
        if len(run) >= 3 and len(run) > len(best):
            best = run.decode("ascii", "ignore")
    return best


def derive_key(password, salt):
    return hashlib.pbkdf2_hmac("sha1", password.encode("utf-16-le"), salt, KDF_ITER, 32)


def _sector_pt(data, s, key):
    sec = data[s * SECTOR:(s + 1) * SECTOR]
    return aes.cbc_decrypt(sec[0:BODY], key, sec[BODY:BODY + 16])


def looks_right(data, key):
    # Max-bin gate: a wrong key decrypts to near-uniform bytes (max byte count ~15
    # over 256 bytes), a correct key to structured data (~100+). Confirm survivors
    # with FileMaker's version string, which de-XORs (0x5A) only under the right key.
    total = len(data) // SECTOR
    gated = False
    for s in range(1, min(GATE_SECTORS + 1, total)):
        pt = _sector_pt(data, s, key)
        if max(bytes(pt[:GATE_BYTES]).count(b) for b in set(pt[:GATE_BYTES])) >= GATE_MIN_MAXBIN:
            gated = True
            if _VER.search(bytes(b ^ 0x5A for b in pt)):
                return True
    if not gated:
        return False
    for s in range(1, min(CHECK_SECTORS + 1, total)):
        if _VER.search(bytes(b ^ 0x5A for b in _sector_pt(data, s, key))):
            return True
    return False


def check_password(data, salt, password):
    return looks_right(data, derive_key(password, salt))


def decrypt(data, key):
    out = bytearray()
    for s in range(len(data) // SECTOR):
        sec = data[s * SECTOR:(s + 1) * SECTOR]
        if s == 0:
            h = bytearray(sec)
            if h[0x0F:0x14] == b"HBAMe":
                h[0x13] = ord("7")
            out += h
        else:
            out += aes.cbc_decrypt(sec[0:BODY], key, sec[BODY:BODY + 16]) + sec[BODY:SECTOR]
    return bytes(out)


def main(argv):
    if len(argv) < 2:
        print(__doc__); return 2
    cmd, path = argv[0], argv[1]
    data = open(path, "rb").read()
    salt = data[SALT_OFF:SALT_OFF + SALT_LEN]
    if cmd == "info":
        print("encrypted:", is_encrypted(data))
        print("sectors  :", len(data) // SECTOR)
        print("salt     :", salt.hex())
        print("hint     :", read_hint(data) or "(none)")
        return 0
    if cmd == "decrypt":
        pw = argv[2]
        if not check_password(data, salt, pw):
            print("wrong password"); return 1
        out = argv[3] if len(argv) > 3 else path + "_DECRYPTED.fmp12"
        open(out, "wb").write(decrypt(data, derive_key(pw, salt)))
        print("decrypted ->", out); return 0
    if cmd == "crack":
        for line in open(argv[2], "r", encoding="utf-8", errors="ignore"):
            pw = line.strip()
            if pw and check_password(data, salt, pw):
                print("password:", pw); return 0
        print("not found"); return 1
    print("unknown command:", cmd); return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
