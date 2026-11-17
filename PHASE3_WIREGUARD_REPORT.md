# Phase 3: Experimental Hybrid Post-Quantum WireGuard-Based Protocol Report

**Project:** Hybrid Post-Quantum Key Encapsulation in TLS 1.3 and WireGuard VPNs  
**Phase:** Phase 3 — Experimental Hybrid Post-Quantum Key Exchange for WireGuard (Noise_IK + ML-KEM-768)  
**Date:** November 17, 2026  
**Classification:** **EXPERIMENTAL RESEARCH PROTOTYPE**  
**Status:** **VERIFIED (51/51 Repository Tests Passing)**

---

## 1. Executive Summary & Protocol Classification

Phase 3 implements an **Experimental Hybrid Post-Quantum WireGuard-Based Protocol Research Prototype** combining classical **Curve25519 (X25519)** with **NIST FIPS 203 ML-KEM-768** (NIST Security Category 3).

### Strict Boundary Declarations
1. **Experimental Classification:** This work is strictly an *experimental cryptographic research prototype*. It is **NOT** standard WireGuard, and it does **NOT** claim wire interoperability with official, unmodified WireGuard peers (such as Linux kernel `wireguard.ko`, `wireguard-go`, or `wireguard-nt`).
2. **Wire Incompatibility with Standard WireGuard:** Official WireGuard peers enforce strict message size parsing (148 bytes for Message 1; 92 bytes for Message 2). Because our hybrid handshake embeds an ML-KEM-768 public key (1,184 bytes) and ciphertext (1,088 bytes), resulting in 1,332-byte and 1,180-byte packets, **unmodified official WireGuard peers will immediately discard these messages with `invalid message length`**.
3. **Userspace UDP Prototype vs. Complete IP VPN Tunnel:** This implementation executes cryptographic handshakes and authenticated data transfer over **real UDP sockets**. It does **NOT** provision virtual network adapter drivers (`tun`/`tap`), manipulate kernel IP routing tables, intercept global OS network packets, or perform DNS redirection. It provides the cryptographic state machine and packet encryption layer for a WireGuard-like tunnel, not a complete turn-key operating system VPN.

---

## 2. Review of the Custom Noise Handshake & Hybrid KDF Integration

### 2.1 Preserved Standard Noise Operations
The implementation faithfully preserves the mathematical core of the WireGuard protocol's `Noise_IKpsk2` pattern:
- **Hash and MAC Functions:** Standard 32-byte BLAKE2s digest (`blake2s_hash`), 16-byte keyed BLAKE2s MAC (`blake2s_mac`), and 32-byte HMAC-BLAKE2s (`blake2s_hmac`) per RFC 7693.
- **Key Derivation Functions:** KDF1, KDF2, and KDF3 are implemented using the exact HMAC-BLAKE2s chaining structure defined in Section 5.1 of the WireGuard specification:
  $$\tau_0 = \text{HMAC-BLAKE2s}(key, input)$$
  $$\tau_1 = \text{HMAC-BLAKE2s}(\tau_0, \text{0x01})$$
  $$\tau_2 = \text{HMAC-BLAKE2s}(\tau_0, \tau_1 \parallel \text{0x02})$$
  $$\tau_3 = \text{HMAC-BLAKE2s}(\tau_0, \tau_2 \parallel \text{0x03})$$
- **Classical Diffie-Hellman Tokens:** All four Curve25519 operations from Noise_IK are executed in sequence:
  - $SS_1 = \text{DH}(e_i, S_r)$ (Ephemeral-Static)
  - $SS_2 = \text{DH}(s_i, S_r)$ (Static-Static)
  - $SS_3 = \text{DH}(e_r, E_i)$ (Ephemeral-Ephemeral)
  - $SS_4 = \text{DH}(e_r, S_i)$ (Ephemeral-Static)
- **Symmetric AEAD Record Encryption:** ChaCha20-Poly1305 (RFC 8439) with 96-bit (12-byte) nonces consisting of 4 zero bytes followed by the 8-byte little-endian message counter.
- **Peer Authentication & Transcript Hashing:** Static public key encrypted in Message 1 and verified against the peer database; transcript hash $H$ continuously mixed with each transmitted token via `MixHash`.
- **Anti-Amplification & Denial of Service Defense:** Keyed BLAKE2s MAC1 calculated over message headers up to MAC fields using responder static public key hash; cookie MAC2 slot preserved.

### 2.2 Modified / Extended Operations
To introduce post-quantum key encapsulation without redesigning the state machine from scratch, the following modifications were introduced:
1. **Extended Construction Identifier:**
   - Classical: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`
   - Experimental Hybrid: `Noise_IKpsk2_X25519_MLKEM768_ChaChaPoly_BLAKE2s`
2. **Ephemeral Key Share Expansion (Message 1):**
   - In standard WireGuard, the unencrypted ephemeral key is 32 bytes ($E_i$).
   - In our hybrid construction, the unencrypted ephemeral field is composite: $E_i \parallel PK_{\text{pqc}}$ (32 bytes X25519 + 1,184 bytes ML-KEM-768 = **1,216 bytes**).
   - $H$ mixes the entire 1,216-byte composite payload: $H_2 = \text{BLAKE2s}(H_1 \parallel E_i \parallel PK_{\text{pqc}})$.
3. **Ephemeral Response Expansion (Message 2):**
   - In standard WireGuard, the unencrypted ephemeral field is 32 bytes ($E_r$).
   - In our hybrid construction, the unencrypted ephemeral field is composite: $E_r \parallel CT_{\text{pqc}}$ (32 bytes X25519 + 1,088 bytes ML-KEM-768 ciphertext = **1,120 bytes**).
   - $H$ mixes the entire 1,120-byte composite payload: $H_5 = \text{BLAKE2s}(H_4 \parallel E_r \parallel CT_{\text{pqc}})$.
4. **Dynamic Hybrid Injection into the PSK Slot:**
   - Standard WireGuard utilizes a pre-configured, out-of-band 32-byte pre-shared key ($PSK$) in the final handshake step:
     $$(C_5, \tau, \kappa_3) = \text{KDF3}(C_4, PSK)$$
   - Our experimental protocol dynamically injects the ML-KEM-768 shared secret ($SS_{\text{pqc}}$) into the PSK slot via domain-separated HMAC-BLAKE2s:
     $$PSK_{\text{hybrid}} = \text{HMAC-BLAKE2s}(C_4, \text{"WireGuard-PQC-Hybrid-MLKEM768-v1:"} \parallel SS_{\text{pqc}} \parallel PSK_{\text{peer}})$$
     $$(C_5, \tau, \kappa_3) = \text{KDF3}(C_4, PSK_{\text{hybrid}})$$
   - This ensures both classical Diffie-Hellman secrets and the post-quantum lattice secret mathematically condition the final transport keys $T_{\text{send}}$ and $T_{\text{recv}}$.

---

## 3. Protocol Variants & Handshake Message Formats

The codebase explicitly separates three protocol variants to maintain research clarity and test harness compatibility:

```
                               ┌────────────────────────────────────────────────────────┐
                               │                 Protocol Implementations               │
                               └───────────────────────────┬────────────────────────────┘
                                                           │
               ┌───────────────────────────────────────────┼───────────────────────────────────────────┐
               ▼                                           ▼                                           ▼
┌─────────────────────────────┐             ┌─────────────────────────────┐             ┌─────────────────────────────┐
│  Classical WireGuard        │             │  Experimental Hybrid        │             │  Remediated Legacy Proxy    │
│  Baseline (Noise_IKpsk2)    │             │  WireGuard Engine           │             │  Compatibility Harness      │
├─────────────────────────────┤             ├─────────────────────────────┤             ├─────────────────────────────┤
│ • File: wireguard_pqc.py    │             │ • File: wireguard_pqc.py    │             │ • File:                     │
│ • Mode: CLASSICAL           │             │ • Mode: HYBRID_MLKEM768     │             │   wireguard_pqc_proxy.py    │
│ • Msg 1: 148 bytes          │             │ • Msg 1: 1,332 bytes        │             │ • Msg 1: 1,301 bytes        │
│ • Msg 2: 92 bytes           │             │ • Msg 2: 1,180 bytes        │             │ • Msg 2: 1,161 bytes        │
│ • Header: 4-byte uint32     │             │ • Header: 4-byte uint32     │             │ • Header: 1-byte opcode     │
│ • Standard WireGuard Wire   │             │ • Custom Hybrid Wire Format │             │ • Real BLAKE2s MAC1/MAC2    │
│   Specification Reference   │             │ • Full TAI64N Timestamps    │             │ • Dissertation Suite Tests  │
└─────────────────────────────┘             └─────────────────────────────┘             └─────────────────────────────┘
```

### Detailed Field Comparison Table

| Field | Classical WireGuard Baseline | Experimental Hybrid (`standard_4b`) | Remediated Proxy (`legacy_1b`) | Purpose / Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Header Type** | 4B (`0x01000000`) | 4B (`0x01000000`) | 1B (`0x01`) | Message type opcode |
| **Sender Index** | 4B (uint32 LE) | 4B (uint32 LE) | 4B (uint32 LE) | Ephemeral session ID |
| **Ephemeral KeyShare** | 32B ($E_i$) | 1,216B ($E_i \parallel PK_{\text{pqc}}$) | 1,216B ($E_i \parallel PK_{\text{pqc}}$) | Ephemeral public key material |
| **Encrypted Static Key** | 48B | 48B | 48B | ChaCha20-Poly1305 encrypted static identity |
| **Encrypted Timestamp** | 28B (TAI64N) | 28B (TAI64N) | Omitted (0B) | Handshake replay protection |
| **MAC1** | 16B (BLAKE2s) | 16B (BLAKE2s) | 16B (BLAKE2s) | Keyed responder authentication |
| **MAC2** | 16B (Cookie/Zero) | 16B (Cookie/Zero) | 16B (Cookie/Zero) | DoS mitigation |
| **Total Message 1 Length** | **148 bytes** | **1,332 bytes** | **1,301 bytes** | Ethernet MTU fit (< 1,500 bytes) |
| **Total Message 2 Length** | **92 bytes** | **1,180 bytes** | **1,161 bytes** | Ethernet MTU fit (< 1,500 bytes) |

---

## 4. Replay Protection & Anti-Denial-of-Service Defense

### 4.1 Handshake Replay Rejection (TAI64N)
- Message 1 contains a 12-byte TAI64N timestamp encrypted under $\kappa_2$.
- Responders record the `greatest_timestamp` seen from each authorized peer static public key.
- Any incoming initiation containing a timestamp $\le \text{greatest\_timestamp}$ is **strictly rejected**. Intercepted initiation messages cannot be replayed.

### 4.2 Transport Replay Rejection (64-Bit Sliding Window)
- Data packets (Type 4) carry an 8-byte sequential counter.
- The `ReplayFilter` class implements a standard 64-bit sliding window bitmap:
  - Counters $> \text{max\_counter}$: Window shifts right; packet accepted.
  - Counters $\le \text{max\_counter}$ within 64 packets: Checked against bitmap. Duplicate counters are **rejected immediately**; unseen out-of-order counters are accepted.
  - Counters $< \text{max\_counter} - 64$: Dropped as ancient.

---

## 5. Security & Cryptographic Assumptions

1. **Dual Security Property:**
   - If Curve25519 is broken by a quantum computer running Shor's algorithm, the confidentiality of session keys is preserved by ML-KEM-768 (based on the hardness of Module-LWE).
   - If an algorithmic breakthrough weakens ML-KEM-768, classical Curve25519 Diffie-Hellman operations preserve confidentiality against classical adversaries.
2. **Pre-Shared Static Keys (Out-of-Band Trust):**
   - Like standard WireGuard, this protocol assumes static public keys are exchanged out-of-band and pre-configured in peer authorization tables. It does not implement a Public Key Infrastructure (PKI) or certificate verification.
3. **Identity Hiding:**
   - The initiator static public key is encrypted with $\kappa_1$ (derived from $DH(e_i, S_r)$) before transmission, protecting the initiator identity against passive network eavesdroppers.
   - An active attacker spoofing the responder can decrypt the initiator static key, matching standard WireGuard Noise_IK privacy properties.

---

## 6. Compatibility & Operational Limitations

1. **Incompatible with Standard WireGuard Peers:**
   - **Do not deploy this prototype against official WireGuard peers.** Unmodified peers running `wireguard.ko` or standard `wireguard-go` will drop hybrid handshakes due to packet length mismatch.
   - Interoperability requires both peers to run this experimental codebase or a custom patched fork of `wireguard-go`.
2. **Userspace UDP Datagram Communication vs. Virtual Network Tunnel:**
   - The prototype demonstrates real, authenticated point-to-point UDP communication.
   - Creating an actual OS-level VPN network adapter (`wg0` interface) requires platform-specific TUN/TAP drivers (`Wintun` on Windows, `/dev/net/tun` on Linux) and administrative permissions.
3. **Fragmentation on Constrained MTU Paths:**
   - Handshake Message 1 (1,332 bytes) and Message 2 (1,180 bytes) fit inside standard 1,500-byte Ethernet MTUs without IP fragmentation.
   - On links with Path MTUs smaller than 1,332 bytes (such as IPv6 minimum MTU of 1,280 bytes, or double-encapsulated tunnels), handshake packets will experience IP fragmentation unless packet slicing (`crypto/packet_framing.py`) is engaged.

---

## 7. Automated Testing & Verification Evidence

An independent automated test suite was executed in [`tests/test_wireguard_pqc_real.py`](file:///C:/Users/91990/.gemini/antigravity/scratch/MTech_PQC_Project3/tests/test_wireguard_pqc_real.py), validating all 12 core protocol aspects:

```powershell
python -m unittest tests/test_wireguard_pqc_real.py -v
```

```text
test_01_classical_wireguard_handshake_baseline ... ok
test_02_hybrid_wireguard_handshake_x25519_mlkem768 ... ok
test_03_matching_session_secrets_and_session_separation ... ok
test_04_invalid_peer_authentication_rejection ... ok
test_05_modified_handshake_messages_rejection ... ok
test_06_handshake_replay_protection_tai64n ... ok
test_07_encrypted_transport_data_bidirectional ... ok
test_08_transport_replay_protection_sliding_window ... ok
test_09_session_key_rotation_and_rekeying ... ok
test_10_real_udp_socket_peer_communication ... ok
test_11_classical_vs_hybrid_handshake_benchmark ... ok
test_12_proxy_backward_compatibility_with_real_macs ... ok

----------------------------------------------------------------------
Ran 12 tests in 0.055s

OK
```

### Empirical Microsecond Latency Measurements

Benchmarked over 10 independent trials on identical hardware (Intel Core i5-1035G1 @ 1.00GHz, Windows 11):

| Handshake Protocol Variant | Message 1 Size | Message 2 Size | Mean Handshake Latency | Overhead vs Classical |
| :--- | :--- | :--- | :--- | :--- |
| **Classical WireGuard Baseline (`X25519`)** | 148 bytes | 92 bytes | **448.4 $\mu\text{s}$ (0.45 ms)** | Reference Baseline |
| **Experimental Hybrid (`X25519 + ML-KEM-768`)** | **1,332 bytes** | **1,180 bytes** | **618.4 $\mu\text{s}$ (0.62 ms)** | **+170.1 $\mu\text{s}$ (+0.17 ms)** |

---

## 8. Full Repository Test Suite Status

1. **Full Repository Discovery Suite:** **51 / 51 tests passing** (`python -m unittest discover -s tests -v`):
   - FIPS 203 ML-KEM Algorithm Tests (Phase 1 / 1.1): 12 tests
   - Cross-Library KAT Tests: 5 tests
   - Dual HKDF & Pipeline Tests: 3 tests
   - Adaptive Negotiation Engine Tests: 3 tests
   - Real RFC 8446 TLS 1.3 Post-Quantum Engine (Phase 2): 14 tests
   - Experimental Userspace WireGuard Engine (Phase 3): 12 tests
   - Protocol Framing & Proxy Integration: 2 tests
2. **Master Dissertation Compliance Suite:** **28 / 28 tests passing (100.0% Success Rate)** (`python tests/comprehensive_test_suite.py`).

---

## 9. Conclusion

Phase 3 establishes a working, verifiable research implementation of a hybrid post-quantum key exchange inspired by WireGuard's Noise_IK architecture. It eliminates simulated MACs and fake nonces, integrates authentic FIPS 203 ML-KEM-768 key encapsulation, validates anti-replay defenses, and operates over real UDP sockets, with its experimental boundaries and standard peer incompatibilities explicitly documented.
