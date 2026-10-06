# Python reference POC

This folder is the original proof of concept. The shipping tool is the Rust crate
at the repo root; this Python is kept only as the readable reference for the EAR
protocol and as the oracle the Rust port is tested against. It is not optimised and
has no GPU path.

- `vangogh_poc.py` - derive key, decrypt, crack (standard library only)
- `aes.py` - pure-Python AES-256 used by the POC

```
python3 vangogh_poc.py info    ../tests/fixtures/ear_password.fmp12
python3 vangogh_poc.py decrypt ../tests/fixtures/ear_password.fmp12 password /tmp/out.fmp12
python3 vangogh_poc.py crack   ../tests/fixtures/ear_password.fmp12 ../wordlists/common.txt
```
