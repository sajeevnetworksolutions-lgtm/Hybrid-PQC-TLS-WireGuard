# FINAL ARCHITECTURE DOCUMENTATION: HYBRID POST-QUANTUM PROTOCOL FRAMEWORK

**Project**: M.Tech Cybersecurity Project 3 — Master Dissertation  
**Document**: System Architecture, Cryptographic State Machines & Protocol Specification  
**Version**: 2.0 (Final Integration)  
**Date**: November 2026  

---

## 1. System Architecture Overview

The Hybrid Post-Quantum Key Encapsulation Framework is architectured into four distinct, modular, and loosely-coupled subsystems. This modularity ensures independent testability, clean cryptographic boundaries, and robust separation between control planes, protocol transports, and empirical telemetry collection.

```
+-----------------------------------------------------------------------------------+
|                        APPLICATION & INTERACTION LAYER                            |
|  +-------------------------------------+   +------------------------------------+  |
|  |     Master CLI Controller           |   |      Live Dashboard Server         |  |
|  |     (main.py)                       |   |      (dashboard_server.py:8080)   |  |
|  |     - --mode classical|hybrid       |   |      - Web Dashboard UI (HTML5/JS) |  |
|  |     - --protocol tls|wireguard|both |   |      - REST API: /api/status       |  |
|  |     - --benchmark / --adaptive      |   |      - REST API: /api/handshake    |  |
|  +------------------+------------------+   +-----------------+------------------+  |
+---------------------|----------------------------------------|--------------------+
                      |                                        |
                      v                                        v
+-----------------------------------------------------------------------------------+
|                           CONTROL & ADAPTIVE LAYER                                |
|  +-----------------------------------------------------------------------------+  |
|  |                    Unified Protocol Manager (protocols/unified_controller.py)|  |
|  +------------------------------------+----------------------------------------+  |
|                                       |                                           |
|  +------------------------------------+----------------------------------------+  |
|  |                    Dynamic Adaptive Negotiation Engine                      |  |
|  |  +-----------------------------+       +---------------------------------+  |  |
|  |  | NetworkMonitor              | ----> | AdaptiveNegotiator              |  |  |
|  |  | (RFC 6298 EWMA RTT/Loss/MTU)|       | (Calibrated Heuristic Modeler)  |  |  |
|  |  +-----------------------------+       | - Strict Downgrade Prevention   |  |  |
|  |                                        | - Auditable Decision Log        |  |  |
|  |                                        +---------------------------------+  |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
                      |                                        |
                      v                                        v
+-----------------------------------------------------------------------------------+
|                         TRANSPORT PROTOCOL ENGINES                                |
|  +------------------------------------+   +------------------------------------+  |
|  | Real TLS 1.3 Engine (RFC 8446)     |   | Experimental WireGuard Prototype   |  |
|  | (protocols/tls13_pqc.py)           |   | (protocols/wireguard_pqc.py)       |  |
|  | - OpenSSL 4.0.0 Native C-Bindings  |   | - Noise_IKpsk2 State Machine       |  |
|  | - X25519MLKEM768 (0x11ec) Hybrid   |   | - ML-KEM-768 in PSK MixKeySlot     |  |
|  | - ECDSA X.509 PKI Validation       |   | - BLAKE2s MAC1 / MAC2 Cookies      |  |
|  | - Keylog Traffic Secret Extraction |   | - TAI64N & 64-bit Sliding Window   |  |
|  | - Memory BIO & TCP Socket Layers   |   | - Userspace UDP Socket Layer       |  |
|  +------------------------------------+   +------------------------------------+  |
+-----------------------------------------------------------------------------------+
                      |                                        |
                      v                                        v
+-----------------------------------------------------------------------------------+
|                      CRYPTOGRAPHIC FOUNDATION LAYER (`crypto/`)                   |
|  +-----------------------------------------------------------------------------+  |
|  | NIST FIPS 203 Module-Lattice-Based KEM (`mlkem 0.2.0` / OpenSSL 4.0.0)      |  |
|  | - ML-KEM-512 (Category 1) | ML-KEM-768 (Category 3) | ML-KEM-1024 (Category 5)  |  |
|  | - Authentic Decapsulation with Fujisaki-Okamoto Implicit Rejection          |  |
|  +-----------------------------------------------------------------------------+  |
|  | RFC 7748 Classical Primitive: Curve25519 / X25519 ECDH (32-byte Keys)        |  |
|  +-----------------------------------------------------------------------------+  |
|  | RFC 5869 Dual HKDF Pipeline (`crypto/dual_hkdf.py`): Extract-and-Expand     |  |
|  | PRK = HKDF-Extract(Salt, SS_ec || SS_pqc) -> Dual IND-CCA2 Security Margin  |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 2. Cryptographic Architecture

### 2.1 NIST FIPS 203 ML-KEM Specification
ML-KEM is a Module-Lattice-Based Key Encapsulation Mechanism derived from the CRYSTALS-Kyber submission. Security relies on the hardness of the Module Learning With Errors ($\text{M-LWE}$) problem over the polynomial quotient ring:
$$R_q = \mathbb{Z}_q[X] / (X^{256} + 1) \quad \text{where } q = 3329$$

Key parameters across supported parameter sets:

| Parameter Set | Security Category | Matrix Dimension ($k$) | Noise Parameters ($\eta_1, \eta_2$) | Compression ($d_u, d_v$) | Public Key ($pk$) | Ciphertext ($c$) | Shared Secret ($ss$) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-KEM-512** | NIST Cat 1 (AES-128) | $k = 2$ | $\eta_1 = 3, \eta_2 = 2$ | $d_u = 10, d_v = 4$ | 800 Bytes | 768 Bytes | 32 Bytes |
| **ML-KEM-768** | NIST Cat 3 (AES-192) | $k = 3$ | $\eta_1 = 2, \eta_2 = 2$ | $d_u = 10, d_v = 4$ | 1,184 Bytes | 1,088 Bytes | 32 Bytes |
| **ML-KEM-1024** | NIST Cat 5 (AES-256) | $k = 4$ | $\eta_1 = 2, \eta_2 = 2$ | $d_u = 11, d_v = 5$ | 1,568 Bytes | 1,568 Bytes | 32 Bytes |

**Fujisaki-Okamoto (FO) Transform**:
To achieve IND-CCA2 security against chosen-ciphertext adversaries, decapsulation re-encrypts the decrypted candidate message $m'$ using deterministically derived randomness $r' = \text{SHAKE-256}(m' \mathbin{\Vert} H(pk))$. If the re-encrypted ciphertext $c'$ matches the received ciphertext $c$, the true shared secret $K = \text{SHAKE-256}(m' \mathbin{\Vert} H(c))$ is returned. If $c' \neq c$, implicit rejection returns a pseudorandom shared secret $K = \text{SHAKE-256}(z \mathbin{\Vert} c)$, preventing active timing side-channel oracle attacks.

### 2.2 Dual HKDF Key Derivation Pipeline (`crypto/dual_hkdf.py`)
To prevent security regressions, session keys are derived using an RFC 5869 Dual HKDF construction combining the classical ECDH shared secret ($ss_{ec} \in \{0,1\}^{256}$) and post-quantum KEM shared secret ($ss_{pqc} \in \{0,1\}^{256}$):

```
       Salt (Session Transcript / Static Salt)
         |
         v
+------------------+
|   HKDF-Extract   | <--- IKM = (ss_ec || ss_pqc)  [64 Bytes]
+------------------+
         |
         v
   PRK (Pseudo-Random Key - 32 Bytes)
         |
         v
+------------------+
|    HKDF-Expand   | <--- Info = "PQC_DUAL_KDF_SESSION_EXPANSION_V1"
+------------------+
         |
         v
   OKM (Output Keying Material - 32 Bytes Master Session Key)
         |
         +---> Client AEAD Write Key (32B) + Nonce/IV (12B)
         +---> Server AEAD Write Key (32B) + Nonce/IV (12B)
```

**Dual Security Theorem**:
Let $\mathcal{A}$ be a polynomial-time adversary against the derived master key $K$. The advantage of $\mathcal{A}$ in distinguishing $K$ from random is bounded by:
$$\mathbf{Adv}^{\text{IND-CCA2}}_{\text{Dual}}(\mathcal{A}) \le \min\left(\mathbf{Adv}^{\text{CDH}}_{\text{X25519}}(\mathcal{A}_{\text{classical}}), \mathbf{Adv}^{\text{IND-CCA2}}_{\text{ML-KEM}}(\mathcal{A}_{\text{quantum}})\right) + \epsilon_{\text{HKDF}}$$
If quantum computers break X25519, ML-KEM ensures security. If an unexpected algorithmic breakthrough compromises module lattices, classical X25519 ensures security.

---

## 3. TLS 1.3 Post-Quantum State Machine (`protocols/tls13_pqc.py`)

The TLS 1.3 implementation operates on real OpenSSL 4.0.0 C-bindings according to RFC 8446 and `draft-ietf-tls-hybrid-design`.

### 3.1 Handshake Sequence Diagram

```
 CLIENT                                                               SERVER
   |                                                                    |
   | 1. ClientHello                                                     |
   |    - SupportedVersions: [TLSv1.3]                                  |
   |    - SupportedGroups: [X25519MLKEM768 (0x11ec)]                    |
   |    - KeyShare: pk_client_composite (32B X25519 || 1184B ML-KEM-768)|
   | -----------------------------------------------------------------> |
   |                                                                    |
   |                                2. ServerHello                      |
   |                                   - SelectedVersion: TLSv1.3       |
   |                                   - KeyShare: resp_composite       |
   |                                     (32B X25519 || 1088B ML-KEM CT)|
   |                                {EncryptedExtensions}               |
   |                                {Certificate (ECDSA P-256)}         |
   |                                {CertificateVerify}                 |
   |                                {Finished}                          |
   | <----------------------------------------------------------------- |
   |                                                                    |
   | [Client verifies Server Certificate against Root CA]               |
   | [Client derives traffic secrets: CLIENT/SERVER_TRAFFIC_SECRET_0]   |
   |                                                                    |
   | 3. {Finished}                                                      |
   | -----------------------------------------------------------------> |
   |                                                                    |
   | === Handshake Completed (1-RTT) ===                                |
   |                                                                    |
   | 4. Application Data Record [AES-256-GCM / ChaCha20-Poly1305]       |
   | <================================================================> |
```

### 3.2 Wire KeyShare Framing
In compliance with `draft-ietf-tls-hybrid-design`:
- Named Group Code: `0x11ec` (`X25519MLKEM768`).
- Client KeyShare Payload: exactly $32 + 1184 = 1216\text{ bytes}$.
- Server KeyShare Payload: exactly $32 + 1088 = 1120\text{ bytes}$.
- Certificate Authentication: authentic ECDSA P-256 X.509 chain validated using `SSL_get_verify_result()`.

---

## 4. Experimental WireGuard-Based Protocol (`protocols/wireguard_pqc.py`)

The experimental WireGuard-based protocol extends the standard WireGuard `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` construction by injecting ML-KEM-768 into the pre-shared key (PSK) key derivation step.

### 4.1 Message Wire Formats

#### Message 1: Handshake Initiation (1,332 Bytes)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type (0x01) |                   Reserved (0x000000)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Sender Index (4 Bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Unencrypted Ephemeral X25519 Public Key (32B)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|            ML-KEM-768 Public Key KeyShare (1,184 Bytes)       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Encrypted Static Identity Key (ChaCha20Poly1305 - 48B)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Encrypted TAI64N Timestamp (ChaCha20Poly1305 - 28B)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  MAC1 (BLAKE2s - 16 Bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  MAC2 (BLAKE2s - 16 Bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Total Length: 4 + 4 + 32 + 1184 + 48 + 28 + 16 + 16 = 1,332 Bytes
```

#### Message 2: Handshake Response (1,180 Bytes)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type (0x02) |                   Reserved (0x000000)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Sender Index (4 Bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Receiver Index (4 Bytes)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Unencrypted Ephemeral X25519 Public Key (32B)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|            ML-KEM-768 Ciphertext KeyShare (1,088 Bytes)       |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Encrypted Empty Authentication Tag (16 Bytes)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  MAC1 (BLAKE2s - 16 Bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  MAC2 (BLAKE2s - 16 Bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Total Length: 4 + 4 + 4 + 32 + 1088 + 16 + 16 + 16 = 1,180 Bytes
```

### 4.2 Noise State Machine Transitions & PQC Injection
The Noise Protocol Framework maintains a chaining key $ck \in \{0,1\}^{256}$ and hash transcript $h \in \{0,1\}^{256}$:
1. **Initialization**:
   - $ck \leftarrow \text{BLAKE2s}(\text{"Noise\_IKpsk2\_X25519\_MLKEM768\_ChaChaPoly\_BLAKE2s"})$
   - $h \leftarrow \text{BLAKE2s}(ck \mathbin{\Vert} \text{"WireGuard v1 zx2c4 Jason@zx2c4.com"})$
   - $h \leftarrow \text{BLAKE2s}(h \mathbin{\Vert} pk_{s})$
2. **Initiation Processing**:
   - Client generates ephemeral keypair $(e_c, pk_{e\_c})$ and ML-KEM-768 keypair $(dk_{pqc}, pk_{pqc})$.
   - $h \leftarrow \text{BLAKE2s}(h \mathbin{\Vert} pk_{e\_c})$
   - $ck, \kappa \leftarrow \text{KDF}_2(ck, \text{ECDH}(e_c, pk_s))$
   - $h \leftarrow \text{BLAKE2s}(h \mathbin{\Vert} pk_{pqc})$
   - Encrypt static identity $pk_{s\_c}$ with $\kappa$; $h \leftarrow \text{BLAKE2s}(h \mathbin{\Vert} c_{\text{static}})$.
   - $ck, \kappa \leftarrow \text{KDF}_2(ck, \text{ECDH}(s_c, pk_s))$
   - Encrypt TAI64N timestamp; $h \leftarrow \text{BLAKE2s}(h \mathbin{\Vert} c_{\text{timestamp}})$.
3. **Response Processing & PQC MixKey**:
   - Server encapsulates: $(ss_{pqc}, ct_{pqc}) = \text{ML-KEM.Encaps}(pk_{pqc})$.
   - $h \leftarrow \text{BLAKE2s}(h \mathbin{\Vert} pk_{e\_s})$
   - $ck, \kappa \leftarrow \text{KDF}_2(ck, \text{ECDH}(e_s, pk_{e\_c}))$
   - $ck, \kappa \leftarrow \text{KDF}_2(ck, \text{ECDH}(e_s, pk_{s\_c}))$
   - $h \leftarrow \text{BLAKE2s}(h \mathbin{\Vert} ct_{pqc})$
   - **PQC Injection**: $ck, \tau, \kappa \leftarrow \text{KDF}_3(ck, ss_{pqc})$ (Injected into Noise PSK slot).
   - $h \leftarrow \text{BLAKE2s}(h \mathbin{\Vert} \tau)$
   - Encrypt empty payload with $\kappa$; $h \leftarrow \text{BLAKE2s}(h \mathbin{\Vert} c_{\text{empty}})$.
4. **Final Session Key Derivation**:
   - $K_{\text{send}}, K_{\text{recv}} \leftarrow \text{KDF}_2(ck, \epsilon)$ (Directionally swapped on initiator and responder).

### 4.3 Anti-Replay & Anti-DoS Security Architecture
- **TAI64N Timestamps**: Nanosecond-precision timestamps (12 bytes: 8B seconds + 4B nanoseconds) encrypted inside Initiation messages. Responders strictly require $t > t_{\text{greatest}}$ for that peer, preventing replay of initiation datagrams.
- **RFC 6479 64-bit Sliding Window Bitmap**: Transport packets carry 64-bit monotonically increasing sequence numbers. A sliding window bitmap tracking 64 packets rejects duplicate or out-of-window transport packets in $O(1)$ constant time.
- **BLAKE2s MAC1 & MAC2 Cookies**:
  - `MAC1`: $\text{BLAKE2s-128}(pk_{s\_responder} \mathbin{\Vert} \text{Msg}[0..-32])$. Every packet must have a valid MAC1.
  - `MAC2`: Under CPU exhaustion (>100 handshakes/sec), responders issue cookie reply datagrams containing an encrypted cookie. Subsequent initiations must include `MAC2 = BLAKE2s-128(Cookie || Msg[0..-16])`, ensuring proof-of-work/reachability.

---

## 5. Adaptive Cryptographic Engine (`adaptive_engine/`)

The adaptive engine optimizes post-quantum parameters dynamically to avoid multi-packet fragmentation over constrained networks without human intervention.

```
+-----------------------------------------------------------------------------+
|                            LINK TELEMETRY INPUTS                            |
|       - RTT Samples (TCP / Protocol Timing)                                 |
|       - Packet Loss Events (Success / Retransmission)                       |
|       - Path MTU (PMTU Detection: 1500B Ethernet / 1280B IPv6/Cellular)     |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
|                     RFC 6298 EWMA NETWORK QUALITY MONITOR                   |
|       SRTT   = (1 - 0.125) * SRTT + 0.125 * RTT_sample                      |
|       RTTVAR = (1 - 0.250) * RTTVAR + 0.250 * |SRTT - RTT_sample|           |
|       RTO    = max(50 ms, SRTT + 4 * RTTVAR)                                |
|       P_loss = (1 - 0.100) * P_loss + 0.100 * Drop_Sample                   |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
|                       EMPIRICAL HOST CALIBRATOR                             |
|       Measures Host System KeyGen + Encaps + Decaps execution times         |
|       (X25519: ~140us, ML-KEM-512: ~165us, ML-KEM-768: ~280us, 1024: ~360us)  |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
|                    DYNAMIC ADAPTIVE DECISION MATRIX                         |
|                                                                             |
|  [MTU >= 1500, Loss < 1.0%, High Security Req] ---> HYBRID_X25519_MLKEM1024|
|                                                     (NIST Level 5)          |
|                                                                             |
|  [Standard Channel: Loss < 1.5%, MTU >= 1350] ----> HYBRID_X25519_MLKEM768 |
|                                                     (Standard Default)      |
|                                                                             |
|  [Degraded Channel: Loss >= 1.5% OR MTU < 1350] --> HYBRID_X25519_MLKEM512 |
|                                                     (Fragmentation Guard)   |
|                                                                             |
|  [Catastrophic Loss > 20% AND Explicit Flag] -----> CLASSIC_X25519         |
|                                                     (CRITICAL WARNING LOG)  |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
|                         AUDITABLE LOG GENERATION                            |
|       Chronological Audit Trail: Decision ID, Justification,                |
|       Fragment Count, Predicted Latency Overhead %, Security Guarantee      |
+-----------------------------------------------------------------------------+
```

---

## 6. Live Dashboard Server Architecture (`dashboard_server.py`)

A zero-external-dependency HTTP and REST API server implemented on Python's built-in `http.server`:
- **Static Assets**: Serves `index.html` / `web_dashboard.html`, IEEE figures (`fig1` through `fig4`), and client scripts.
- **`/api/status` (GET)**: Delivers live health of cryptographic engines, calibrated host metrics, active TLS named groups, WireGuard status, and test pass counts.
- **`/api/handshake` (GET/POST)**: Triggers authentic in-memory handshakes on demand and returns exact execution timestamps, hex key shares, and secrets-match verification.
- **`/api/adaptive` (GET/POST)**: Ingests real-time RTT/Loss/MTU parameters and queries `AdaptiveNegotiator`, returning decision logs, fragment counts, and latency penalties.
- **`/api/benchmark` (GET)**: Streams raw empirical results from `benchmark/final_benchmark_results.json`.
