# FileMaker Encryption At Rest (EAR)

The scheme, reproducible offline in pure Python given only the password.

## Layout

- Magic `HBAMe` at offset 0x0F. A normal file is `HBAM7`.
- 4096-byte sectors. Sector 0 is plaintext: it holds the magic, the cleartext
  password hint (UTF-16LE), and the KDF salt.
- Salt: 16 bytes at sector 0, offset 0xFA.

## Key derivation

    key = PBKDF2-HMAC-SHA1(password.encode("utf-16-le"), salt, 18000, 32)

The password is UTF-16LE. 18000 iterations, 32-byte output = the AES-256 key.
A second key derived at 20000 iterations is believed to feed the per-sector MAC;
it is not needed for decryption.

## Per sector (s >= 1)

    ciphertext = sector[0:4064]
    iv         = sector[4064:4080]     # first 4 bytes = little-endian sector index
    trailer    = sector[4080:4096]     # 16-byte MAC, not reversed
    plaintext  = AES-256-CBC-decrypt(key, iv, ciphertext)

## Verifying a password

EAR has no up-front key check. A guess is confirmed by decrypting body sectors:

1. Entropy gate (cheap reject): a wrong key yields near-random plaintext
   (entropy ~7.95 bits/byte); a correct key yields structured fmp12 data
   (a few bits/byte). This rejects wrong guesses after one or two sectors.
2. Authority: scan the decrypted body for FileMaker's version string
   (`Pro 26.0`, `FileMaker 19.6`, etc.), which appears after XOR 0x5A only under
   the right key.

## Security note

18000 PBKDF2-HMAC-SHA1 iterations is weak by modern standards. A stolen EAR file
with a short or common password is affordably crackable offline, which is the
point of this tool for files I own.
