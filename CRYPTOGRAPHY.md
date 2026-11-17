# Cryptographic Architecture & Implementation Specification

**Project:** Hybrid Post-Quantum Key Encapsulation in TLS 1.3 and WireGuard VPNs  
**Phase:** Phase 1 — Cryptographic Foundation Remediation  
**Status:** Remediated & Independently Verified  
**Primary Standards:**
- NIST FIPS 203 (*Module-Lattice-Based Key-Encapsulation Mechanism Standard*)
- RFC 7748 (*Elliptic Curves for Security — Curve25519 / X25519*)
- RFC 5869 (*HMAC-based Extract-and-Expand Key Derivation Function — HKDF*)
- NIST SP 800-56C Rev 2 (*Recommendation for Key-Derivation Methods in Key-Establishment Schemes*)

---

## 1. Cryptographic Modules & Libraries Overview

In Phase 1, all simulated, placeholder, and insecure implementations (including random-byte key generation and toy polynomial convolution) were completely replaced with verified, constant-time cryptographic implementations.

| Component | Implementation Provider | Library Version | Underlying Engine | Security Properties Verified |
| :--- | :--- | :--- | :--- | :--- |
| **X25519 (ECDH)** | `pyca/cryptography` | `48.0.0` | OpenSSL 4.0.0 (C/Assembly) | RFC 7748 compliant, constant-time curve scalar multiplication |
| **ML-KEM-512** | `mlkem` | `0.2.0` | Compiled Native Rust / Assembly | FIPS 203 compliant, constant-time NTT, IND-CCA2 FO implicit rejection |
| **ML-KEM-768** | `mlkem` / `cryptography` | `0.2.0` / `48.0.0` | Rust & OpenSSL 4.0.0 Dual Engines | FIPS 203 compliant, cross-library verified, KAT reproducible |
| **ML-KEM-1024** | `mlkem` / `cryptography` | `0.2.0` / `48.0.0` | Rust & OpenSSL 4.0.0 Dual Engines | FIPS 203 compliant, cross-library verified, KAT reproducible |
| **Hybrid Combiner** | `crypto/dual_hkdf.py` | Native / `cryptography` | HMAC-SHA-256 (OpenSSL 4.0.0) | Domain-separated IKM & OKM, context-bound, input-validated |

---

## 2. Algorithm Parameters & Wire Specifications

All post-quantum parameter sets adhere strictly to NIST FIPS 203 Section 8 (Table 2):

| Algorithm | NIST Security Level | Classic Equivalent | Public Key ($ek$) | Ciphertext ($c$) | Shared Secret ($K$) | Matrix Rank ($k$) | Sub-Vector Parameters ($\eta_1, \eta_2, d_u, d_v$) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-KEM-512** | Category 1 | AES-128 | 800 Bytes | 768 Bytes | 32 Bytes | $k = 2$ | $(\eta_1=3, \eta_2=2, d_u=10, d_v=4)$ |
| **ML-KEM-768** | Category 3 | AES-192 | 1,184 Bytes | 1,088 Bytes | 32 Bytes | $k = 3$ | $(\eta_1=2, \eta_2=2, d_u=10, d_v=4)$ |
| **ML-KEM-1024**| Category 5 | AES-256 | 1,568 Bytes | 1,568 Bytes | 32 Bytes | $k = 4$ | $(\eta_1=2, \eta_2=2, d_u=11, d_v=5)$ |
| **X25519** | Classical 128 | Curve25519 | 32 Bytes | 32 Bytes | 32 Bytes | N/A | Montgomery Curve $y^2 = x^3 + 486662x^2 + x$ |

### Composite Wire Formats

1. **Composite Public Key (`initiator_pk`):**
   $$\text{CompositePK} = \text{PK}_{X25519} \mathbin{\Vert} \text{PK}_{ML-KEM}$$
   - `X25519 + ML-KEM-512`: $32 + 800 = 832$ Bytes
   - `X25519 + ML-KEM-768`: $32 + 1,184 = 1,216$ Bytes
   - `X25519 + ML-KEM-1024`: $32 + 1,568 = 1,600$ Bytes

2. **Responder Payload (`response_payload`):**
   $$\text{ResponsePayload} = \text{PK}_{server\_X25519} \mathbin{\Vert} \text{Ciphertext}_{ML-KEM}$$
   - `X25519 + ML-KEM-512`: $32 + 768 = 800$ Bytes
   - `X25519 + ML-KEM-768`: $32 + 1,088 = 1,120$ Bytes
   - `X25519 + ML-KEM-1024`: $32 + 1,568 = 1,600$ Bytes

---

## 3. Mathematical Operations & Hardening

### 3.1 Module Learning With Errors (M-LWE)
The security of ML-KEM rests on the hardness of M-LWE over the cyclotomic polynomial ring:
$$R_q = \mathbb{Z}_q[X]/(X^{256} + 1) \quad \text{where } q = 3329$$

- **Number Theoretic Transform (NTT):**
  Polynomial multiplication in $R_q$ is evaluated in the NTT domain using primitive 256th roots of unity ($\zeta = 17 \pmod{3329}$). The implemented NTT operations run in strictly constant time.
- **Rejection Sampling:**
  Uniform matrix generation $A \in R_q^{k \times k}$ uses SHAKE-128 stream rejection sampling (`SampleNTT`), rejecting candidate 12-bit integers $\ge 3329$ to guarantee zero modulo bias.
- **Centered Binomial Distribution (CBD):**
  Error vectors and secret vectors are sampled using Little-Endian bit extraction over $\eta_1$ and $\eta_2$.

### 3.2 Fujisaki-Okamoto (FO) Transform & Implicit Rejection
To achieve IND-CCA2 security against chosen-ciphertext adversaries, decapsulation executes the Fujisaki-Okamoto transform:
1. Re-encrypt the decoded message $\hat{m}$ to compute candidate ciphertext $\hat{c}$.
2. If $c == \hat{c}$, output $K = \text{KDF}(\hat{m}, c)$.
3. If $c \ne \hat{c}$, output pseudorandom rejected secret $K = \text{KDF}(z, c)$ derived deterministically from secret seed $z$.
4. Both branches evaluate in constant time, preventing timing leakages (mitigating KyberSlash 1 and 2 attacks).

---

## 4. Hybrid Secret Combination (`DualHKDF`)

The hybrid combiner merges classical and post-quantum secrets via HKDF-SHA-256 (RFC 5869) with unambiguous domain separation:

### 4.1 Extraction (IKM Serialization)
$$\text{IKM} = \text{b"Hybrid-PQC-KEM-v1:IKM:"} \mathbin{\Vert} \text{len}(\text{suite}) \mathbin{\Vert} \text{suite} \mathbin{\Vert} \text{len}(ss_{ec}) \mathbin{\Vert} ss_{ec} \mathbin{\Vert} \text{len}(ss_{pqc}) \mathbin{\Vert} ss_{pqc}$$
$$\text{PRK} = \text{HMAC-SHA256}(\text{Salt}, \text{IKM})$$

- If no salt is supplied, $\text{Salt} = 0^{32}$.
- Input length validation rejects any secret component whose length is neither 0 nor 32 bytes.
- At least one component secret must be non-empty.

### 4.2 Expansion (Context Binding)
$$\text{Info} = \text{b"Hybrid-PQC-KEM-v1:EXPAND:"} \mathbin{\Vert} \text{len}(\text{suite}) \mathbin{\Vert} \text{suite} \mathbin{\Vert} \text{len}(\text{context}) \mathbin{\Vert} \text{context} \mathbin{\Vert} \text{label}$$
$$\text{OKM} = \text{HKDF-Expand}(\text{PRK}, \text{Info}, \text{length})$$

- Independent sessions using distinct salts or contexts derive mathematically independent keys.
- Cross-suite key collision is prevented by embedding the negotiated suite name in both IKM and Info.

---

## 5. Known Limitations & Scope Boundaries

1. **FIPS 140-3 Validation Status:**
   While the implementations strictly adhere to the mathematical and wire specifications of NIST FIPS 203 (August 2024), neither the Python wrappers nor the user environment hold a formal NIST Cryptographic Module Validation Program (CMVP) FIPS 140-3 validation certificate. Do not claim formal FIPS certification in regulatory or compliance disclosures.
2. **Protocol Key Schedule Separation:**
   `crypto/dual_hkdf.py` is a generic cryptographic combiner. It is deliberately distinct from the TLS 1.3 Key Schedule (RFC 8446 Section 7.1) and WireGuard Noise chaining key state machines, which are transport-layer concerns scheduled for Phase 2.
3. **No RFC 9180 HPKE Claim:**
   The hybrid combiner does not implement the RFC 9180 HPKE (Hybrid Public Key Encryption) protocol specification; it is an authenticated dual HKDF combiner.
4. **Memory Zeroization in Python Runtime:**
   CPython manages memory via reference counting and internal pools with immutable `bytes` objects. Best-effort zeroization methods release references and reassign zero buffers, but cannot execute native `memset` on immutable memory. True constant-time memory erasure requires native C/Rust secure memory allocators.
5. **Backend Algorithm Coverage Asymmetry:**
   The Rust `mlkem` package provides full coverage across Category 1 (512), Category 3 (768), and Category 5 (1024). In contrast, OpenSSL 4.0.0 via `pyca/cryptography` natively provides Category 3 (768) and Category 5 (1024), intentionally omitting Category 1 (512) per NSA CNSA 2.0 and IETF TLS 1.3 standards. Cross-library interoperability is verified for 768 and 1024.
