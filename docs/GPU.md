# GPU acceleration (wgpu + WGSL)

Status: implemented. PBKDF2 runs on the GPU, the correctness check on the CPU.
Validated on an RTX 2080 SUPER via Vulkan; the derived keys match the CPU oracle.

CPU is the default. Each guess is one PBKDF2-HMAC-SHA1 (18000 iterations) plus a
short trial decrypt; native CPU does ~260/s per core. GPUs do PBKDF2-SHA1 orders
of magnitude faster, so the GPU path is where real throughput comes from.

## Approach

One WGSL compute shader, run through wgpu, so a single codebase targets both of
my machines:

- Apple Silicon (my Mac): Metal backend.
- NVIDIA RTX 2080 SUPER (Linux box): Vulkan backend.

No CUDA or OpenCL SDK is needed to build, and wgpu picks the backend at runtime.

## Why not stock hashcat

EAR's KDF is hashcat mode 12000 (PBKDF2-HMAC-SHA1), but EAR stores no verifier
hash: a candidate is confirmed by deriving the key, decrypting a sector, and
recognising structured plaintext. hashcat compares against a stored hash and
cannot do that decrypt-and-inspect step, and a custom hashcat module would need a
full hashcat source rebuild. wgpu keeps everything in one shippable binary.

## Shader design

The kernel (shaders/pbkdf2.wgsl) does PBKDF2-HMAC-SHA1(password UTF-16LE, salt,
18000) per candidate and returns the 32-byte AES key. The host uploads a batch of
candidates, reads the keys back, and confirms on the CPU: a cheap max-bin gate
(correct key >~100 repeated bytes over 256, wrong key <~15) then the version-string
check. Keeping AES and the check on the CPU keeps the shader to just SHA1/HMAC/PBKDF2
and reuses the proven CPU verify. Passwords up to 32 characters go to the GPU; longer
ones fall back to the CPU.

## Benchmark and where we stand

Both backends are validated: Vulkan on an RTX 2080 SUPER, Metal on an Apple M3 Max.
18000 iterations, dkLen=32 (2 blocks).

| Machine | Backend | GPU | CPU |
|---|---|---|---|
| RTX 2080 SUPER (desktop) | Vulkan | ~110,000/s | ~6,100/s (24 threads) |
| Apple M3 Max (laptop) | Metal | ~62,000/s | ~3,300/s (16 threads) |

1,000,000-candidate mask: ~9s on the 2080, ~16s on the M3 Max. Small runs show a
lower rate because GPU init and the first batch are fixed overhead; the rate climbs
to steady state on larger runs.

Kernel: the SHA1 transform is fully unrolled with register-resident word variables
(no dynamic array indexing, no per-round branches), generated into
shaders/pbkdf2.wgsl, and the HMAC ipad/opad states are precomputed once per candidate.
The unroll alone took the 2080 from ~20,800 to ~110,000/sec (~5.3x).

### Versus hashcat

hashcat `-m 12000` (PBKDF2-HMAC-SHA1) benchmarks at 1000 iterations, 1 block. Our work
is 2 blocks x 18000 = 36x that, so divide a hashcat H/s figure by 36 to compare:

- RTX 2080 SUPER: hashcat ~5,164,900 H/s -> ~143,000/s expected. At ~110,000/s we are
  ~77% of a hand-tuned kernel (naive portable kernels usually land at 5-20%). We
  precompute the HMAC ipad/opad states and fully unroll SHA1; the remaining gap is
  toolchain (naga -> SPIR-V/MSL vs hand-tuned per-vendor OpenCL, no funnel-shift
  intrinsic) and occupancy tuning.
- Apple scaled estimates: M1 Ultra ~68,000/s, M3 Pro ~33,000/s. The M3 Max sits between
  those in GPU cores, so ~62,000/s is near its realistic ceiling for this workload, not
  leaving much on the table. To check the Metal headroom directly, run `hashcat -b -m
  12000` on the Mac and divide by 36; if it lands near ~62,000/s our kernel is doing as
  well as a tuned one.

Sources: hashcat benchmark gists (epixoip, Chick3nman) and hashcat.net forum threads on
mode 12000 iteration semantics.
