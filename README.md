# QuantumVault
### A Unified Lattice-Based Framework for Post-Quantum Confidential Cloud Computation

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![Rust](https://img.shields.io/badge/Rust-Production%20Library-orange?logo=rust)](src/rust/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![NIST PQC](https://img.shields.io/badge/NIST-FIPS%20203%2F204%2F205-green)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Security](https://img.shields.io/badge/Security-128--bit%20Post--Quantum-purple)](docs/security.md)
[![PhD Research](https://img.shields.io/badge/PhD%20Research-4%20Year%20Programme-darkred)](docs/proposal/)
[![Funding](https://img.shields.io/badge/Funding-EU%20Horizon%20%2F%20National%20Grant-blue)](docs/funding.md)

> **QuantumVault: A Unified Lattice-Based Framework for Post-Quantum Confidential Cloud Computation**
>
> PhD Research Programme — Department of Computer Science & Cryptography Engineering
> Duration: 4 Years | Targets: CRYPTO, EuroCrypt, CCS, IEEE S&P, USENIX Security

---

## The Problem in One Paragraph

NIST's 2024 PQC standards (FIPS 203/204/205) address key exchange and signatures at the
primitive level. The higher-order constructs that actually secure cloud systems remain
classical and quantum-vulnerable:

| Cloud Security Layer | Current State | QuantumVault Solution |
|---------------------|--------------|----------------------|
| **Identity & access control** | RSA-IBE, ECC, X.509 PKI | Hierarchical IBE from MLWE (L1) |
| **Multi-party authorisation** | ECDSA, FROST threshold | Threshold Dilithium with identifiable abort (L2) |
| **Confidential computation** | Paillier HE, plaintext FL | NTT-optimised CKKS FHE for federated learning (L3) |
| **Access-pattern privacy** | AES-ORAM, DDH-PIR | FHE-ciphertext ORAM + LWE-PIR (L4) |

QuantumVault co-designs all four layers for cross-layer composability, with a single
unified Module-LWE security reduction.

---

## Four-Layer Architecture

```
+------------------------------------------------------------+
|  L1 -- HIBE                                                |
|  Hierarchical Identity-Based Encryption                    |
|  GPV trapdoor delegation: Root KGC -> Dept -> User         |
|  NEW: Ciphertext format in R_q^{k+1} -- natively          |
|  evaluable under CKKS/FHE, no format conversion needed     |
|  Security: IND-ID-CPA under MLWE                           |
+------------------------------------------------------------+
|  L2 -- ThSig                                               |
|  t-of-n Threshold Lattice Signatures                       |
|  Two-round protocol; identifiable abort via ZK proofs      |
|  Output: standard Dilithium signature (FIPS 204 compat.)   |
|  Security: EUF-CMA under Module-LWE                        |
+------------------------------------------------------------+
|  L3 -- FHE                                                 |
|  Leveled Homomorphic Encryption (CKKS)                     |
|  NTT-domain SIMD batching: n/2 gradients per ciphertext    |
|  2-4x FL aggregation throughput vs standard CKKS           |
|  Params: n=2^15, log(q)=438 bits, ~128-bit PQ security     |
+------------------------------------------------------------+
|  L4 -- ORAM + LWE-PIR                                      |
|  FHE-Ciphertext Oblivious RAM                              |
|  RAM cells hold FHE blocks, not plaintexts                 |
|  Re-randomisation: add fresh Enc(0) on each eviction       |
|  Bandwidth: O(log^2 n) amortised; ~8x over plaintext ORAM  |
|  Security: Access-pattern indistinguishability under LWE   |
+------------------------------------------------------------+
              |
              v
    Unified MLWE security reduction (C5)
    e_MLWE >= e / (L + 7),  L = HIBE depth
```

---

## Root Hardness Assumption

**All five contributions reduce to one problem:**

```
Module Learning With Errors  (MLWE_{k, n, q, chi})

Given:  A in R_q^{k x k},  b = A*s + e in R_q^k
Decide: (A, b)  vs  (A, uniform)

Ring:     R_q = Z_q[x] / (x^n + 1),  n = 256
Modulus:  q = 3329  (NTT-friendly: q = 1 mod 512)
Rank:     k = 3  (Kyber-768 / FIPS 203 equivalent)
Error:    chi = discrete Gaussian, sigma = 3.2
Security: >= 128-bit post-quantum (Albrecht et al. 2024)
NTT:      O(n log n) polynomial multiplication
```

No RSA. No ECC. No DDH. Anywhere.

---

## Five Research Contributions

| ID | Contribution | Novel Claim | Target Venue |
|----|-------------|------------|-------------|
| **C1** | FHE-compatible HIBE from lattices | First HIBE ciphertexts natively evaluable under CKKS — no format conversion | CRYPTO / EuroCrypt 2026 |
| **C2** | Threshold Dilithium with identifiable abort | First to achieve: MLWE hardness + identifiable abort + O(n log n) comm + FIPS 204 output | IEEE S&P / CCS 2026 |
| **C3** | NTT-optimised FHE for federated learning | NTT-domain SIMD gradient batching — no direct precedent; 2-4x CKKS throughput | ACM CCS 2026 |
| **C4** | FHE-aware hierarchical ORAM + LWE-PIR | First ORAM operating on FHE ciphertext blocks with ciphertext re-randomisation on eviction | USENIX Security 2027 |
| **C5** | Unified Module-LWE security reduction | Single MLWE instance covers all 4 layers via cross-layer hybrid proof | CRYPTO 2027 / J. Cryptology |

---

## Layer Design Details

### L1 — FHE-Compatible HIBE (Contribution C1)

The key innovation is a new HIBE ciphertext format in **R_q^{k+1}** — matching the CKKS
ring ciphertext structure — enabling the FHE layer (L3) to evaluate over HIBE-encrypted
data without any re-encoding step. All prior HIBE constructions produce incompatible formats.

```
Root KGC:         (msk, mpk) <- MLWE.KeyGen
Delegation:       sk_child  = HIBE.KeyDel(sk_parent, id_child)
                             via SampleLeft / SampleRight trapdoor algorithms
Encryption:       ct in R_q^{k+1}  (CKKS-compatible format)
Decryption:       uses level-specific trapdoor basis
```

**Security:** IND-ID-CPA under MLWE (GPV reduction).

### L2 — Threshold Dilithium with Identifiable Abort (Contribution C2)

Any t of n parties jointly produce a standard Dilithium signature. A malicious or
unavailable party is publicly identified without halting honest signers.

```
Protocol: 2-round interactive
  Round 1 (Commit):   each party commits to masking polynomial w_i
  Round 2 (Respond):  contributions z_i combined linearly
  Abort:              ZK proof of correct opening; faulty party identified

Output:   (z, c, h)  -- passes standard Dilithium (FIPS 204) verification unchanged
```

**Properties achieved simultaneously (no prior scheme has all three):**
- Identifiable abort via lattice Sigma protocols
- O(n log n) communication via NTT-domain commitment aggregation
- FIPS 204 output compatibility

### L3 — NTT-FHE for Federated Learning (Contribution C3)

```
Encryption:    CKKS, n=2^15, log(q)=438 bits, scale=2^40
SIMD packing:  up to n/2 = 16,384 gradient values per ciphertext
Aggregation:   sum of ciphertexts in NTT domain (vectorised polynomial add)
Throughput:    2-4x vs standard CKKS element-wise aggregation

Circuit depth: L levels for standard NN layer operations
Bootstrapping: selective, triggered by noise budget exhaustion
```

### L4 — FHE-Aware ORAM + LWE-PIR (Contribution C4)

The critical extension over PathORAM: RAM cells contain **FHE ciphertext blocks**, not
plaintexts. The ORAM must shuffle and re-randomise ciphertexts without ever decrypting them.

```
Re-randomisation:  ct_new = ct_old + FHE.Enc(pk, 0)
                   Preserves embedded plaintext; erases ciphertext bit-pattern identity
PIR access:        LWE-based query -- quantum-safe retrieval primitive
Storage:           Hierarchical bucket tree; each bucket holds FHE-encrypted blocks
Bandwidth:         O(log^2 n) amortised; ~8x constant factor over plaintext ORAM
```

**Security:** Access-pattern indistinguishability under LWE (single-server computational PIR).

---

## Unified Security Reduction (C5)

```
Theorem (QuantumVault Unified Security):
Let A be any PPT adversary breaking QuantumVault-IND-CPA with advantage e.
Then there exists PPT B solving MLWE_{k=3, n=256, q=3329} with:

  e_MLWE  >=  e / (L + 7)

  where  L = max HIBE hierarchy depth
         7 = 1 (ThSig) + 5 (modulus-switching kappa) + 1 (ORAM-PIR)

Proved via 5-game hybrid (one game per contribution):
  H0: Real QuantumVault system         advantage = e
  H1: HIBE simulated (L queries)       gap = L * e_MLWE   [MLWE -> GPV trapdoor]
  H2: ThSig simulated                  gap = 1 * e_MLWE   [MLWE -> EUF-CMA]
  H3: FHE simulated + mod-switch       gap = 5 * e_MLWE   [RLWE -> MLWE via BV12]
  H4: ORAM access-pattern hidden       gap = 1 * e_MLWE   [LWE-PIR privacy]
  H5: Ideal (zero leakage)             advantage = 0
```

**Open problem:** eliminate the kappa=5 modulus-switching factor by finding a prime q*
satisfying NTT-compatibility, 128-bit MLWE security, and sufficient FHE noise budget.
Candidates: q* = 2^30 + 3 (1,073,741,827), q* = 2^31 - 483 (2,013,265,921).

---

## Repository Structure

```
quantumvault/
|
+-- README.md
+-- LICENSE                         # MIT
+-- requirements.txt
|
+-- quantumvault/
|   +-- __init__.py
|   +-- hibe.py                     # L1: HIBE -- GPV trapdoor, R_q^{k+1} ciphertext
|   +-- threshold_sig.py            # L2: Threshold Dilithium, identifiable abort
|   +-- fhe.py                      # L3: CKKS NTT-batching, FL gradient aggregation
|   +-- oram.py                     # L4: FHE-ciphertext ORAM + LWE-PIR
|   +-- keygen.py                   # Cross-layer key coordination
|   +-- ntt.py                      # O(n log n) NTT over Z_q (R_q arithmetic)
|   +-- mlwe.py                     # Core MLWE sampling and reduction
|   └-- params.py                   # MLWE parameter sets: n, k, q, chi, security level
|
+-- src/
|   +-- rust/                       # Production implementation
|   |   +-- src/
|   |   |   +-- lib.rs
|   |   |   +-- ntt.rs              # AVX-512 + ARM Neon SIMD NTT
|   |   |   +-- hibe.rs
|   |   |   +-- threshold.rs
|   |   |   +-- fhe.rs
|   |   |   └-- oram.rs
|   |   └-- Cargo.toml
|   └-- lean4/                      # Formal verification (C1, C2, C5)
|       +-- HIBECorrectness.lean
|       +-- ThresholdEUFCMA.lean
|       └-- UnifiedReduction.lean
|
+-- proofs/
|   +-- c1_ind_id_cpa.md            # HIBE IND-ID-CPA under MLWE
|   +-- c2_euf_cma_abort.md         # ThSig EUF-CMA with identifiable abort
|   +-- c3_circuit_privacy.md       # FHE circuit privacy + NTT batching
|   +-- c4_access_indist.md         # ORAM access-pattern indistinguishability
|   └-- c5_unified_reduction.md     # 5-game hybrid H0->H5 (full proof)
|
+-- test/
|   +-- test_hibe.py                # KeyGen, delegation, encrypt, decrypt
|   +-- test_threshold.py           # t-of-n signing, identifiable abort
|   +-- test_fhe.py                 # CKKS SIMD batching correctness
|   +-- test_oram.py                # ORAM re-randomisation + access-pattern
|   └-- test_cross_layer.py         # HIBE key authenticating FHE session
|
+-- benchmarks/
|   +-- bench_hibe.py               # KeyGen / delegation / enc latency
|   +-- bench_threshold.py          # Per-party contribution + aggregation time
|   +-- bench_fhe.py                # FL gradient aggregation throughput vs CKKS
|   └-- bench_oram.py               # Bandwidth overhead vs n (2^10 to 2^20)
|
+-- experiments/
|   +-- mimic3/                     # Federated analytics on MIMIC-III
|   |   +-- run_federated.py        # Multi-hospital FHE training
|   |   +-- eval_privacy.py         # Access-pattern privacy analysis
|   |   └-- README.md               # IRB + PhysioNet credential requirements
|   └-- enterprise_pki/             # Enterprise PKI migration prototype
|       +-- active_directory_map.py # AD hierarchy -> HIBE delegation tree
|       └-- hsm_threshold_demo.py   # HSM + threshold signing integration
|
+-- docs/
|   +-- security.md                 # Full security boundary and assumptions
|   +-- threat_model.md             # Quantum adversary model
|   +-- parameter_selection.md      # APS lattice estimator outputs
|   +-- pki_migration_guide.md      # NIST SP 1800-38D aligned migration guide
|   +-- compliance.md               # FIPS 203/204/205 alignment
|   +-- proposal/                   # Full PhD research proposal
|   └-- notation.md                 # Symbol glossary (Appendix A)
|
└-- examples/
    +-- sovereign_cloud.py          # Ministry-level HIBE + FHE analytics
    +-- federated_healthcare.py     # Hospital trust -> dept -> clinician -> device
    └-- enterprise_pki.py           # Root CA -> intermediate CA -> leaf cert
```

---

## Installation

```bash
git clone https://github.com/your-org/quantumvault.git
cd quantumvault

python -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows

pip install -r requirements.txt
```

**Requirements** (`requirements.txt`):
```
numpy>=1.24.0
scipy>=1.11.0
pytest>=7.4.0
# Rust library: cargo build --release
# Lean 4: elan install leanprover/lean4:stable
```

---

## Quick Start

### Full Stack — Federated Healthcare Analytics

```python
from quantumvault import QuantumVault

# Initialise all four layers (Kyber-768 equivalent parameters)
qv = QuantumVault(n=256, k=3, q=3329)

# L1: Offline HIBE key delegation (Hospital -> Dept -> Clinician)
root_sk, mpk = qv.hibe.keygen()
dept_sk      = qv.hibe.delegate(root_sk, id='Hospital/Cardiology')
clin_sk      = qv.hibe.delegate(dept_sk, id='Hospital/Cardiology/Dr-Smith')

# L2: Multi-hospital threshold authorisation (3-of-5 hospitals approve update)
shares    = [qv.threshold.sign_share(hospital_sk, model_hash, i)
             for i, hospital_sk in enumerate(hospital_keys)]
signature = qv.threshold.aggregate(shares[:3])   # any t=3 of n=5

# L3: FHE gradient aggregation (10 hospitals, each sends encrypted gradients)
ct_grads    = [qv.fhe.encrypt(grad) for grad in local_gradients]
ct_combined = qv.fhe.ntt_aggregate(ct_grads)     # NTT-domain SIMD batching

# L4: Oblivious write to audit log (access pattern hidden from server)
qv.oram.access('write', address=42, data=ct_combined)
```

### Layer 1 Only — Enterprise PKI Migration

```python
from quantumvault.hibe import HIBEScheme

hibe = HIBEScheme(n=256, k=3, q=3329)

# Map existing CA hierarchy to HIBE delegation tree
root_sk, mpk = hibe.keygen()                                 # Root KGC (replaces root CA)
inter_sk     = hibe.delegate(root_sk, 'Corp/Engineering')    # Intermediate KGC
leaf_sk      = hibe.delegate(inter_sk, 'Corp/Engineering/TeamA')

# Encrypt to identity (no certificate needed)
ct = hibe.encrypt(mpk, 'Corp/Engineering/TeamA', plaintext=session_key)
recovered = hibe.decrypt(leaf_sk, ct)
assert recovered == session_key
```

### Layer 2 Only — Threshold Signing

```python
from quantumvault.threshold_sig import ThresholdDilithium

thresh = ThresholdDilithium(t=3, n=5, n_ring=256, k=3, q=3329)
keys   = thresh.distributed_keygen()

# Two-round threshold signing
r1_msgs  = [thresh.round1(keys[i]) for i in range(5)]
r2_msgs  = [thresh.round2(keys[i], r1_msgs, message) for i in range(5)]
sig      = thresh.aggregate(r2_msgs[:3])           # any 3-of-5

# Verify with standard Dilithium (FIPS 204) -- no modification needed
assert thresh.verify(keys[0].pk, message, sig)
```

### Layer 3 Only — FHE Gradient Aggregation

```python
from quantumvault.fhe import CKKSAggregator

agg = CKKSAggregator(n=2**15, log_q=438, scale=2**40)
pk, sk = agg.keygen()

# Each hospital encrypts its gradient vector (SIMD-packed into one ciphertext)
ct_list = [agg.encrypt(pk, hospital_gradient) for hospital_gradient in gradients]

# NTT-domain aggregation -- no decryption at server
ct_sum  = agg.ntt_aggregate(ct_list)          # 2-4x faster than element-wise

# Authorised party decrypts the aggregate
global_gradient = agg.decrypt(sk, ct_sum)
```

---

## Performance Targets

| Operation | Target | Hardware |
|-----------|--------|----------|
| HIBE KeyGen (depth-3 hierarchy) | < 10ms | Commodity server |
| HIBE Delegation (one level) | < 5ms | Commodity server |
| Threshold Sign (3-of-5, total round-trip) | < 500ms | Network included |
| FHE gradient aggregation (SIMD) | 2x vs standard CKKS | Commodity server |
| ORAM access overhead (N = 2^20) | < 10x vs plaintext ORAM | Cloud VM |
| End-to-end QuantumVault overhead | < 3x vs non-PQ baseline | Cloud VM |
| Concrete PQ security (all layers) | >= 128-bit | — |

---

## Research Roadmap

```
Year 1 (Months 1-12): Foundations
  ├── C1: FHE-compatible HIBE -- IND-ID-CPA proof under MLWE
  ├── C2: Threshold Dilithium -- EUF-CMA proof with identifiable abort
  ├── C3: NTT-FHE scheme -- circuit privacy proof
  ├── C4: FHE-aware ORAM -- access-pattern indistinguishability proof
  ├── Begin unified reduction H0->H2 (C5)
  └── C1 draft submitted to EuroCrypt 2026

Year 2 (Months 13-24): Implementation
  ├── Python reference (~2,000 LOC): all four layers
  ├── Rust production: AVX-512 NTT + ARM Neon SIMD
  ├── Benchmark suite: throughput / latency / bandwidth / memory
  ├── Cross-layer integration tests
  ├── C2 -> IEEE S&P 2026
  └── C3 -> ACM CCS 2026

Year 3 (Months 25-36): Integration & Proof Completion
  ├── Full prototype: AWS deployment + MIMIC-III evaluation (46K ICU records)
  ├── Enterprise PKI migration prototype (Active Directory -> HIBE)
  ├── Complete C5 unified reduction (H0->H5)
  ├── C4 -> USENIX Security 2027
  └── C5 -> CRYPTO 2027

Year 4 (Months 37-48): Thesis & Dissemination
  ├── PhD thesis + examination
  ├── Journal paper: J. Cryptology or IEEE Trans. IT
  ├── QuantumVault v1.0 MIT licence public release
  ├── Lean 4 / Coq formal proofs (C1, C2, C5)
  ├── NIST PQC migration working group engagement
  └── Enterprise PKI migration guide (NIST SP 1800-38D aligned)
```

---

## Target Applications

### Sovereign AI and Cloud
National governments require quantum-resistant security against nation-state quantum
adversaries. QuantumVault provides: HIBE for ministry-level identity, threshold signing
for inter-agency authorisation, FHE for analytics on classified datasets, ORAM for
audit-log access-pattern privacy. Target deployments: Gulf Cooperation Council cloud
sovereignty initiatives, EU GAIA-X.

### Federated Healthcare Analytics
Multiple hospitals collaboratively train ML models on the MIMIC-III ICU dataset (46,000
records) without exposing patient data — even to a quantum eavesdropper. HIBE maps to
Hospital/Department/Clinician hierarchies; threshold signing enforces multi-hospital
consent; FHE enables joint model training; ORAM hides which cohorts are analysed.

### Post-Quantum Enterprise PKI Migration
QuantumVault's HIBE layer is a direct drop-in for hierarchical PKI:
- Root CA → Root KGC
- Intermediate CA → Department KGC
- Leaf certificate → Identity-specific HIBE key

Existing Active Directory hierarchies map directly to the HIBE delegation tree.
Threshold layer is FIPS 204 compatible — existing HSM infrastructure works unchanged.

---

## Research Gaps Addressed

| Gap | Prior Work Limitation | QuantumVault Contribution |
|-----|----------------------|--------------------------|
| HIBE + FHE composition | All prior HIBE ciphertexts incompatible with CKKS — costly re-encoding required | C1: R_q^{k+1} format natively CKKS-evaluable |
| Threshold PQ signatures | Damgard et al. (2021): no identifiable abort; Boneh et al. (2023): O(n^2) comm | C2: all three properties simultaneously — first |
| FHE for federated learning | Kim et al. (2020): CKKS aggregation but no NTT batching | C3: NTT SIMD slot packing, 2-4x throughput |
| PQ ORAM | Ishai et al. (2021): LWE-PIR for plaintext only | C4: FHE ciphertext blocks + re-randomisation — first |
| Unified security proof | Each layer proved independently, incompatible assumptions | C5: single MLWE instance, 5-game hybrid reduction |

---

## Notation Reference

| Symbol | Definition |
|--------|-----------|
| R_q | Polynomial ring Z_q[x]/(x^n + 1), n=256 or 512 |
| MLWE_{k,n,q,chi} | Module-LWE: distinguish (A, As+e) from uniform |
| chi | Discrete Gaussian, sigma = 3.2 |
| NTT | Number Theoretic Transform, O(n log n) polynomial multiply |
| KGC | Key Generation Centre -- root of HIBE delegation hierarchy |
| FHE.Enc(pk, m) | FHE encryption of m under pk |
| ORAM.Access(op,a,d) | Oblivious RAM: op in {read,write}, address a, data d |
| PIR.Query(i,n) | LWE-PIR query for index i among n elements |
| ThreshSig.Sign(sk_i, msg) | Party i's contribution to threshold signature |
| HIBE.KeyDel(sk_id, id') | Delegate HIBE key from id to child identity id' |

---

## Expected Outputs

| Output | Timeline |
|--------|----------|
| 5 peer-reviewed publications (CRYPTO, EuroCrypt, CCS, IEEE S&P, USENIX) | Years 1-4 |
| 1 journal paper (J. Cryptology or IEEE Trans. IT) | Year 4 |
| QuantumVault open-source library (Python + Rust), MIT licence | Year 3 |
| Formal proofs in Lean 4 / Coq (C1, C2, C5) | Year 3-4 |
| Enterprise PKI migration guide (NIST SP 1800-38D aligned) | Year 4 |
| MIMIC-III federated analytics prototype (IRB-approved) | Year 3 |

---



---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>QuantumVault · Unified Post-Quantum Cloud Security · PhD Research Programme</sub><br/>
  <sub>Department of Computer Science & Cryptography Engineering</sub>
</p>
