# First-Principles Implementation of Core Modern Cryptographic Algorithms (AES-128, RSA, SHA-256, ECDSA)

- **Course:** `Information Security` (`012012303303`) — Institute of Information Technology and Electrical & Electronics Engineering, Ho Chi Minh City University of Transport (UTH)
- **Instructor:** Dr. Tran The Vinh
- **Student Author:** Trần Gia Thuận — Student ID (SID): `072206007183` (Last digit: `3`)
- **Runtime & Compliance:** Pure Python **3.8+** (verified on Python **3.12.10**), implemented strictly **from first principles** using only Python standard library modules (`struct`, `time`, `math`, `secrets`, `sys`, `dataclasses`, `typing`, `ast`, `os`). Zero third-party cryptographic packages (`hashlib`, `hmac`, `cryptography`, `pycryptodome`, `PyNaCl`, `ssl`, `OpenSSL`, `rsa`, `ecdsa`) are used.
- **Official Specification:** See [PROJECT_REQUIREMENTS.md](./PROJECT_REQUIREMENTS.md).

### Course Assignment & SID Mapping

| Cryptographic Component | SID Assignment Rule | Assigned Algorithm & Standard | Source Implementation | Technical Report |
| :--- | :--- | :--- | :--- | :--- |
| **Symmetric-key Cryptography** | Mandatory for all students (`key = SHA-256("Trần Gia Thuận")[:16]`) | **AES-128** (NIST FIPS 197, CBC/ECB, PKCS#7) | [algorithms/aes128.py](./algorithms/aes128.py) | [docs/bao_cao_aes128.md](./docs/bao_cao_aes128.md) |
| **Asymmetric-key Cryptography** | $\text{SID} \bmod 3 = 3 \bmod 3 = 0$ | **RSA** with **Garner's CRT** & PKCS#1 v1.5 | [algorithms/rsa.py](./algorithms/rsa.py) | [docs/bao_cao_rsa.md](./docs/bao_cao_rsa.md) |
| **Cryptographic Hash Function** | Mandatory for all students | **SHA-256** (NIST FIPS 180-4) | [algorithms/sha256.py](./algorithms/sha256.py) | [docs/bao_cao_sha256.md](./docs/bao_cao_sha256.md) |
| **Digital Signature** | $\text{SID} \bmod 4 = 3 \bmod 4 = 3$ | **ECDSA** (`secp256k1` & Toy Curve $E(\mathbb{F}_{17})$) | [algorithms/ecdsa.py](./algorithms/ecdsa.py) | [docs/bao_cao_ecdsa.md](./docs/bao_cao_ecdsa.md) |

---

## Architectural Overview & Cross-Module Cryptographic Binding

All four cryptographic primitives are implemented from scratch in `algorithms/` with direct cross-module cryptographic integration:

```text
                       Student Name (UTF-8, 18 bytes): "Trần Gia Thuận"
                                              │
                                              ▼
                       ┌──────────────────────────────────────────────┐
                       │            algorithms/sha256.py              │
                       │  bam_sha256_bytes()  /  bam_sha256_hex()     │
                       └──────────┬────────────────────────┬──────────┘
                                  │                        │
        Digest[:16] = 70c31dddb87cf9c3fd103a5669346839     │  z = int(SHA-256(M)) mod n
        Digest[16:] = aa646cb3240d200a80859c06f07ef0e0     │  (via hash_message_to_int)
                                  ▼                        ▼
              ┌─────────────────────────────┐  ┌─────────────────────────────┐
              │    algorithms/aes128.py     │  │     algorithms/ecdsa.py     │
              │  lay_khoa_va_iv_sinh_vien() │  │  sign_message() / verify()  │
              │  128-bit Key + 128-bit IV   │  │  secp256k1 & Toy Curve F_17 │
              └─────────────────────────────┘  └─────────────────────────────┘

                       ┌──────────────────────────────────────────────┐
                       │             algorithms/rsa.py                │
                       │  Independent Public-Key Cryptosystem         │
                       │  Miller–Rabin (40 rounds) + PKCS#1 v1.5      │
                       │  Garner's CRT Recombination (use_crt=True)   │
                       └──────────────────────────────────────────────┘
```

- **SHA-256 $\rightarrow$ AES-128 Key & IV Derivation:** `lay_khoa_va_iv_sinh_vien("Trần Gia Thuận")` in [algorithms/aes128.py](./algorithms/aes128.py) imports `bam_sha256_bytes` directly from [algorithms/sha256.py](./algorithms/sha256.py), computes the 32-byte digest `70c31dddb87cf9c3fd103a5669346839aa646cb3240d200a80859c06f07ef0e0`, slices the leading 16 bytes (`70c31dddb87cf9c3fd103a5669346839`) as the 128-bit AES secret key, and uses the trailing 16 bytes (`aa646cb3240d200a80859c06f07ef0e0`) as the deterministic CBC initialization vector ($IV$).
- **SHA-256 $\rightarrow$ ECDSA Message Digesting:** `hash_message_to_int` in [algorithms/ecdsa.py](./algorithms/ecdsa.py) imports `bam_sha256_bytes` from [algorithms/sha256.py](./algorithms/sha256.py) to compute the message digest integer $z$ prior to signature generation (`sign_message`) and signature verification (`verify_signature`).
- **First-Principles Guarantee:** Every mathematical primitive (prime root extraction, $GF(2^8)$ arithmetic, S-Box algebraic verification, binary modular exponentiation, Miller–Rabin primality testing, Extended Euclidean Algorithm, and short Weierstrass elliptic-curve group operations) is built purely in Python and enforced by an automated AST import audit in [tests/audit_is_project.py](./tests/audit_is_project.py).

---

## Project Directory Structure

```text
├── README.md                        # Project overview, directory guide, and execution instructions
├── PROJECT_REQUIREMENTS.md          # Official course project specification & SID algorithm mapping
├── .gitignore                       # Ignore Python bytecode (__pycache__/, *.py[cod]), temp locks, and IDE files
├── algorithms/                      # Pure-Python first-principles implementations (flat directory)
│   ├── sha256.py                    # SHA-256 hash function (Merkle–Damgård + Davies–Meyer)
│   ├── aes128.py                    # AES-128 block cipher (GF(2^8) S-Box, CBC/ECB, PKCS#7)
│   ├── rsa.py                       # RSA cryptosystem with Miller–Rabin & Garner's CRT acceleration
│   └── ecdsa.py                     # ECDSA over secp256k1 & Toy Curve E(F_17) with nonce-reuse audit
├── tests/                           # Standalone automated verification & compliance test suite
│   └── audit_is_project.py          # End-to-end AST import scan, NIST KATs, and report consistency audit
└── docs/                            # Four academic reports (8 required sections each)
    ├── bao_cao_sha256.md            # SHA-256 technical report (8 required sections + t=0,1 trace)
    ├── bao_cao_aes128.md            # AES-128 technical report (8 required sections + Round 0–1 trace)
    ├── bao_cao_rsa.md               # RSA technical report (8 required sections + small-prime CRT trace)
    └── bao_cao_ecdsa.md             # ECDSA technical report (8 required sections + F_17 worked example)
```

---

## Module-by-Module Technical & Code Summary

| Module & Stdlib Imports | Underlying Mathematical Foundation | Key / Block / Digest / Signature Size | Core Functions in Code | Verified Vectors & Worked Examples | Empirical Pure-Python Benchmark (from `docs/*.md`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **[sha256.py](./algorithms/sha256.py)**<br>`struct`, `time` | Merkle–Damgård iterative construction, 64-round Davies–Meyer feed-forward, Nothing-Up-My-Sleeve constants derived via big-int binary search | Block: `512-bit` (64 B)<br>Digest: `256-bit` (32 B)<br>Rounds: `64` | `lay_n_so_nguyen_to_dau_tien`, `trich_phan_thap_phan_32bit`, `rotr`, `shr`, `ham_ch`, `ham_maj`, `sigma_hoa_0`, `sigma_hoa_1`, `sigma_thuong_0`, `sigma_thuong_1`, `dem_thong_diep`, `chia_khoi_512bit`, `nen_mot_khoi`, `bam_sha256_bytes`, `bam_sha256_hex` | NIST FIPS 180-4 KATs (`""`, `"abc"`, 56B boundary multi-block); `"Trần Gia Thuận"` $\rightarrow$ `70c31dddb87cf9c3fd103a5669346839aa646cb3240d200a80859c06f07ef0e0`; manual $t=0,1$ trace on `"abc"` | Mean over 50 runs:<br>• `100 B`: `0.2841 ms` (`343.70 KB/s`)<br>• `1 KB`: `2.4157 ms` (`413.96 KB/s`)<br>• `10 KB`: `22.8542 ms` (`437.56 KB/s`) |
| **[aes128.py](./algorithms/aes128.py)**<br>`time` + `sha256` | Substitution-Permutation Network (SPN) over $GF(2^8)$ modulo irreducible polynomial $x^8+x^4+x^3+x+1$ (`0x11B`); S-Box verified via $a^{254}$ inverse + `0x63` affine map | Key: `128-bit` (16 B)<br>Block: `128-bit` (16 B)<br>Rounds: `10` (`11` round keys) | `xtime`, `nhan_gf256`, `nghich_dao_gf256`, `bien_doi_affine_sbox`, `kiem_chung_sbox_tu_nguyen_ly_goc`, `mo_rong_khoa_aes128`, `ma_hoa_khoi_16byte`, `giai_ma_khoi_16byte`, `dem_pkcs7`, `bo_dem_pkcs7`, `ma_hoa_aes128_cbc`, `giai_ma_aes128_cbc`, `ma_hoa_aes128_ecb`, `giai_ma_aes128_ecb`, `lay_khoa_va_iv_sinh_vien` | 256/256 S-Box & InvS-Box check; NIST FIPS 197 App. B & C.1 (`69c4e0d86a7b0430d8cdb78070b4c55a`); `"Tran Gia Thuan"` + PKCS#7 `0x02 0x02` $\rightarrow$ CT `485472a086cb866f58d5b8c321a9d5df`; 247B Vietnamese UTF-8 text | CBC mode, mean over 20 runs:<br>• `100 B`: Enc `1.8692 ms` / Dec `3.5740 ms` (`52.25 KB/s`)<br>• `1 KB`: Enc `16.8675 ms` / Dec `32.4668 ms` (`59.29 KB/s`)<br>• `10 KB`: Enc `167.4027 ms` / Dec `320.7053 ms` (`59.74 KB/s`) |
| **[rsa.py](./algorithms/rsa.py)**<br>`sys`, `math`, `time`, `secrets`, `typing` | Trapdoor permutation over $\mathbb{Z}_n^*$, Extended Euclidean Algorithm, 40-round Miller–Rabin primality test, Garner's CRT recombination (`dp`, `dq`, `qinv`) | Key: `512` / `1024` / `2048-bit`<br>Public exponent: $e=65537$<br>Padding: PKCS#1 v1.5 | `pow_mod`, `extended_gcd`, `mod_inverse`, `is_prime_miller_rabin`, `generate_prime`, `generate_keypair`, `rsa_encrypt_int`, `rsa_decrypt_int`, `pkcs1_pad`, `pkcs1_unpad`, `encrypt_text`, `decrypt_text` | Small-prime example ($p=61, q=53, e=17 \Rightarrow n=3233, d=2753, E(65)=2790$); RSA-1024 PKCS#1 v1.5 & CRT on 218B Vietnamese UTF-8 text; empty string & leading `\x00` raw chunking checks | 218-byte Vietnamese UTF-8 payload:<br>• `512-bit`: KeyGen `12.26 ms`, Std `3.01 ms`, CRT `1.29 ms` (`2.33x`)<br>• `1024-bit`: KeyGen `76.98 ms`, Std `6.93 ms`, CRT `2.47 ms` (`2.81x`)<br>• `2048-bit`: KeyGen `1010.05 ms`, Std `22.75 ms`, CRT `6.59 ms` (`3.45x`) |
| **[ecdsa.py](./algorithms/ecdsa.py)**<br>`math`, `secrets`, `sys`, `time`, `dataclasses`, `typing` + `sha256` | Short Weierstrass elliptic curves $y^2 \equiv x^3 + ax + b \pmod p$, chord-and-tangent Abelian group law, Double-and-Add scalar multiplication, SEC 1 v2 & BIP-62 Low-S | Private key $d$: `256-bit` (`secp256k1`)<br>Signature `(r, s)`: `512-bit` (64 B)<br>Cofactor: $h=1$ | `Point`, `EllipticCurve` (`is_on_curve`, `point_add`, `point_double`, `scalar_mult`), `extended_gcd`, `mod_inverse`, `generate_keypair`, `hash_message_to_int`, `sign_message`, `verify_signature`, `attack_nonce_reuse` | `TOY_CURVE_F17` ($y^2 = x^3 + 2x + 2 \bmod 17$, $G=(5,1), n=19, d=7 \to Q=(0,6), z=10, k=13 \to (16,5)$); `secp256k1` signing/tamper tests; `attack_nonce_reuse`; cofactor $h>1$ & Low-S checks | `secp256k1`, mean over 30 runs:<br>• KeyGen: `12.21 ms` (`81.9 ops/s`)<br>• Sign: `12.78 ms` (`78.3 ops/s`)<br>• Verify: `24.24 ms` (`41.3 ops/s`) |

---

## Prerequisites & Environment Setup

- **Python Version:** Python **3.8+** (uses `@dataclass` and `math.isqrt`; tested across Python 3.10+ and verified on **Python 3.12.10** on Windows, Linux, and macOS).
- **Dependencies:** **Zero external packages** — no virtual environment or `pip install` step is required.

> [!IMPORTANT]
> **Critical Execution Rules:**
> 1. **Always run commands from the repository root directory:** Cross-module imports (`from sha256 import bam_sha256_bytes` inside `algorithms/aes128.py` and `algorithms/ecdsa.py`) and path resolution in `tests/audit_is_project.py` expect execution from the repository root. Running `tests/` or `algorithms/` from an unrelated directory without `algorithms/` on `PYTHONPATH` will raise `ModuleNotFoundError`.
> 2. **Always pass `-X utf8` (or set `PYTHONUTF8=1`) on Windows:** On Windows consoles using legacy code pages (e.g., `cp1252`), running without UTF-8 mode can trigger `UnicodeEncodeError` when printing Vietnamese test strings (`"Trần Gia Thuận"`) and Unicode verification markers (`✓`).

---

## Quick Start: One-Command Automated Verification Suite

Clone the repository and execute the unified verification suite from the project root:

```powershell
git clone <repository-url>
cd <repository-folder>
python -X utf8 tests/audit_is_project.py
```

The standalone auditor ([tests/audit_is_project.py](./tests/audit_is_project.py)) performs **30 automated checks** across **6 verification groups**:

1. **`[1]` AST Import Compliance Scan (4 checks):** Parses the Abstract Syntax Tree (`ast`) of all four files in `algorithms/` to guarantee zero imports from prohibited cryptographic libraries (`hashlib`, `Crypto`, `cryptography`, `hmac`, `ssl`, `OpenSSL`, `pycryptodome`).
2. **`[2]` SHA-256 Verification (4 checks):** Validates NIST FIPS 180-4 test vectors (empty string `""`, single-block `"abc"`, 448-bit 56B multi-block boundary + 32-bit `rotr` boundary), and verifies the `"Trần Gia Thuận"` UTF-8 digest.
3. **`[3]` AES-128 Verification (9 checks):** Validates 128-bit key extraction from `sha256.py`, 256/256 algebraic S-Box/InvS-Box equivalence over $GF(2^8)$, NIST FIPS 197 Appendix B & C.1 vector, `"Tran Gia Thuan"` + PKCS#7 `0x02 0x02` worked example, 4 CBC/ECB + PKCS#7 round-trips (18B accented name, `0B`, `16B`, 150B UTF-8 text), and security boundary enforcement (rejecting non-16B blocks and malformed PKCS#7 padding).
4. **`[4]` RSA + Garner's CRT Verification (3 checks):** Validates the small-prime hand calculation ($p=61, q=53, e=17 \rightarrow d=2753, E(65)=2790$), RSA-1024 key generation (40-round Miller–Rabin) + PKCS#1 v1.5 + standard vs. CRT decryption on Vietnamese text, and edge-case defenses (empty string `""`, raw chunking preserving leading `\x00` bytes, rejecting even `e=2`).
5. **`[5]` ECDSA `secp256k1` Verification (4 checks):** Validates the `TOY_CURVE_F17` worked example, `secp256k1` signing/verification integrated with `sha256.py` plus tamper rejection, full private-key recovery via `attack_nonce_reuse`, and SEC 1 v2 / BIP-62 security checks (cofactor subgroup check for $h > 1$, rejecting non-canonical $Q.x \notin [0, p-1]$, and Low-S canonicalization).
6. **`[6]` Cross-Report Consistency Audit (6 checks):** Confirms absence of the erroneous string `"Tran Gia Thuan 3"` in both `algorithms/aes128.py` and `docs/bao_cao_aes128.md`, matches Round 0/Round 1 intermediate states and ciphertext against `docs/bao_cao_aes128.md`, and verifies that all four reports in `docs/` contain `## Section 1.` through `## Section 8.`.

Expected summary line:

```text
TỔNG KẾT KIỂM ĐỊNH 4 THUẬT TOÁN: ĐẠT 30/30 HẠNG MỤC (100%)
```

---

## Running Individual Algorithm Modules

Each module can also be executed standalone from the repository root to inspect step-by-step derivations, interactive CLI demos, and local runtime benchmarks:

```powershell
python -X utf8 algorithms/sha256.py
python -X utf8 algorithms/aes128.py
python -X utf8 algorithms/rsa.py
python -X utf8 algorithms/ecdsa.py
```

- **`algorithms/sha256.py`:** Prints NIST FIPS 180-4 KAT verdicts, the 256-bit digest of `"Trần Gia Thuận"` and derived 128-bit AES key, round `t=0` and `t=1` compression traces for `"abc"`, and the 50-run benchmark table (`100 B`, `1 KB`, `10 KB`).
- **`algorithms/aes128.py`:** Prints the 256-element algebraic S-Box check, NIST FIPS 197 Appendix C.1 verification, derived student key & IV, all 11 expanded round keys, the complete Round 0 & Round 1 state trace for `"Tran Gia Thuan"`, CBC/ECB Vietnamese text round-trips, and the 20-run AES-128-CBC benchmark table.
- **`algorithms/rsa.py`:** Prints the $p=61, q=53$ hand-calculation verification, a live RSA-1024 keygen + PKCS#1 v1.5 + Garner's CRT demo on Vietnamese text, and the 512/1024/2048-bit keygen/encryption/standard-vs-CRT benchmark table.
- **`algorithms/ecdsa.py`:** Prints the `TOY_CURVE_F17` verification, a live `secp256k1` signing and tamper-detection demo, 5 adversarial security test cases (including the nonce-reuse private-key recovery attack), and the 30-iteration `secp256k1` KeyGen/Sign/Verify benchmark table.

---

## Troubleshooting Common Issues

| Symptom | Root Cause | Resolution |
| :--- | :--- | :--- |
| `UnicodeEncodeError: 'charmap' codec can't encode character ...` | Windows console defaults to a non-UTF-8 code page (e.g., `cp1252` on Python `< 3.15`) while scripts print Vietnamese strings and `✓`. | Always invoke Python with `-X utf8` (e.g., `python -X utf8 tests/audit_is_project.py`) or set `$env:PYTHONUTF8 = "1"` in PowerShell before running. |
| `ModuleNotFoundError: No module named 'sha256'` or `FileNotFoundError` | Script was invoked from outside the repository root, or `aes128.py`/`ecdsa.py` was imported as a package module without `algorithms/` on `sys.path`. | `cd` into the repository root directory and run `python -X utf8 algorithms/<module>.py` or `python -X utf8 tests/audit_is_project.py`. |

---

## Documentation & Reports Index

| Document | Description |
| :--- | :--- |
| [PROJECT_REQUIREMENTS.md](./PROJECT_REQUIREMENTS.md) | Official project requirements, 8 mandatory report objectives, and SID-based algorithm assignment rules (`SID mod 3 = 0`, `SID mod 4 = 3`). |
| [docs/bao_cao_sha256.md](./docs/bao_cao_sha256.md) | Full 8-section SHA-256 report covering Merkle–Damgård padding, Davies–Meyer compression, $t=0, 1$ worked calculation on `"abc"`, and benchmarks. |
| [docs/bao_cao_aes128.md](./docs/bao_cao_aes128.md) | Full 8-section AES-128 report covering $GF(2^8)$ arithmetic, S-Box algebra, KeyExpansion, Round 0–1 worked trace on `"Tran Gia Thuan"`, and CBC benchmarks. |
| [docs/bao_cao_rsa.md](./docs/bao_cao_rsa.md) | Full 8-section RSA report covering Miller–Rabin primality testing, Garner's CRT recombination, PKCS#1 v1.5 padding, small-prime worked trace, and benchmarks. |
| [docs/bao_cao_ecdsa.md](./docs/bao_cao_ecdsa.md) | Full 8-section ECDSA report covering short Weierstrass curves, chord-and-tangent group law, $E(\mathbb{F}_{17})$ worked example, nonce-reuse exploit, and `secp256k1` benchmarks. |
| [tests/audit_is_project.py](./tests/audit_is_project.py) | Standalone verification script validating AST import rules, standard vectors, security boundaries, and report consistency across all four modules. |
