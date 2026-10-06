"""Pure-Python AES-256 (standard library only).

Single-block encrypt/decrypt plus CBC wrappers, enough to decrypt (and, with a
caveat, re-encrypt) FileMaker Encryption At Rest files without any third-party
dependency. This is a plain reference implementation: correct, not constant-time,
and meant for offline analysis, not for protecting live secrets.

Public API:
    encrypt_block(block16, key) -> 16 bytes
    decrypt_block(block16, key) -> 16 bytes
    cbc_encrypt(data, key, iv)  -> bytes   (len(data) must be a multiple of 16)
    cbc_decrypt(data, key, iv)  -> bytes

`key` is 16, 24 or 32 bytes (AES-128/192/256); crowbar only needs 256.
Run `python3 aes.py` for the self-test (a NIST AES-256 vector + a CBC round-trip).
"""

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _gmul(a, b):
    """Multiply in GF(2^8) with the AES reduction polynomial 0x11b."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _key_expansion(key):
    """Return the round keys as a list of 4-byte words (4*(Nr+1) of them)."""
    Nk = len(key) // 4
    Nr = {4: 10, 6: 12, 8: 14}[Nk]
    w = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]
    for i in range(Nk, 4 * (Nr + 1)):
        t = list(w[i - 1])
        if i % Nk == 0:
            t = t[1:] + t[:1]                      # RotWord
            t = [SBOX[b] for b in t]               # SubWord
            t[0] ^= RCON[i // Nk]
        elif Nk > 6 and i % Nk == 4:
            t = [SBOX[b] for b in t]               # SubWord (AES-256 only)
        w.append([w[i - Nk][j] ^ t[j] for j in range(4)])
    return w, Nr


def _add_round_key(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[r + 4 * c] ^= w[4 * rnd + c][r]


def _encrypt_block(block, w, Nr):
    s = list(block)
    _add_round_key(s, w, 0)
    for rnd in range(1, Nr):
        s = [SBOX[b] for b in s]                                   # SubBytes
        s = [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]  # ShiftRows
        s = _mix_columns(s)
        _add_round_key(s, w, rnd)
    s = [SBOX[b] for b in s]
    s = [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]
    _add_round_key(s, w, Nr)
    return bytes(s)


def _decrypt_block(block, w, Nr):
    s = list(block)
    _add_round_key(s, w, Nr)
    for rnd in range(Nr - 1, 0, -1):
        s = [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]  # InvShiftRows
        s = [INV_SBOX[b] for b in s]                                        # InvSubBytes
        _add_round_key(s, w, rnd)
        s = _inv_mix_columns(s)
    s = [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]
    s = [INV_SBOX[b] for b in s]
    _add_round_key(s, w, 0)
    return bytes(s)


def _mix_columns(s):
    o = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
        o[4 * c]     = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        o[4 * c + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        o[4 * c + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        o[4 * c + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)
    return o


def _inv_mix_columns(s):
    o = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]
        o[4 * c]     = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
        o[4 * c + 1] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
        o[4 * c + 2] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
        o[4 * c + 3] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)
    return o


def encrypt_block(block, key):
    w, Nr = _key_expansion(key)
    return _encrypt_block(block, w, Nr)


def decrypt_block(block, key):
    w, Nr = _key_expansion(key)
    return _decrypt_block(block, w, Nr)


def cbc_encrypt(data, key, iv):
    if len(data) % 16:
        raise ValueError("cbc_encrypt: data length must be a multiple of 16")
    w, Nr = _key_expansion(key)
    out = bytearray()
    prev = bytes(iv)
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = _encrypt_block(blk, w, Nr)
        out += prev
    return bytes(out)


def cbc_decrypt(data, key, iv):
    if len(data) % 16:
        raise ValueError("cbc_decrypt: data length must be a multiple of 16")
    w, Nr = _key_expansion(key)
    out = bytearray()
    prev = bytes(iv)
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        dec = _decrypt_block(blk, w, Nr)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return bytes(out)


def _selftest():
    # NIST FIPS-197 AES-256 ECB known-answer vector
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    ct = bytes.fromhex("f3eed1bdb5d2a03c064b5a7e3db181f8")
    got = encrypt_block(pt, key)
    assert got == ct, "AES-256 ECB vector failed: %s" % got.hex()
    assert decrypt_block(ct, key) == pt, "AES-256 ECB decrypt failed"
    # CBC round-trip over several blocks
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    msg = bytes(range(64))
    enc = cbc_encrypt(msg, key, iv)
    assert cbc_decrypt(enc, key, iv) == msg, "CBC round-trip failed"
    print("aes.py self-test PASS (NIST AES-256 vector + CBC round-trip)")


if __name__ == "__main__":
    _selftest()
