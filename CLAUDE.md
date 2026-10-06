# fm-vangogh

CLI to recover and decrypt FileMaker Encryption At Rest (EAR) files. Rust (single binary); a Python reference POC is in `python/`. Usage and layout: `README.md`.

## Authorization

I use this only on FileMaker databases I own and am authorised to administer. It
recovers access to my own encrypted files offline, given a password or by
searching for one. It never touches third-party systems.

## Hard rules

- NEVER modify a source `.fmp12`. Read-only, always: every access is `open(path, 'rb')`.
- NEVER overwrite an output. New runs get a `_v2`, `_v3` suffix (`ear._new_path`).
- NEVER commit real data. Not real `.fmp12` files, not recovered passwords, not real
  names. Committed samples are the throwaway EAR fixtures in `tests/fixtures/` (synthetic passwords).
- Keep personal/large wordlists (rockyou, etc.) out of the repo; `.gitignore` allows
  only `wordlists/common.txt`.
- No em dashes anywhere. Keep docs short. Write about me in the first person.

## Layout

- Rust is the shipping tool: `src/` (ear, crack, gpu, main, lib) and `shaders/`.
  Build with `cargo build --release`; test with `cargo test`.
- `python/` is the reference POC (vangogh_poc.py + aes.py), the oracle the Rust port
  is checked against. Kept minimal on purpose.
- Shared: `tests/fixtures/` (EAR fixtures), `wordlists/`, `docs/`, `scripts/`.
- `docs/EAR.md` is the protocol reference; `docs/GPU.md` the wgpu plan.
