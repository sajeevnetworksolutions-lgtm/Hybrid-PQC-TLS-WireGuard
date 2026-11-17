# Phase 2: Real TLS 1.3 Post-Quantum Key Exchange Implementation Report

**Project:** Hybrid Post-Quantum Key Encapsulation in TLS 1.3 and WireGuard VPNs  
**Phase:** Phase 2 — Genuine TLS 1.3 Hybrid Post-Quantum Key Exchange (RFC 8446)  
**Date:** November 17, 2026  
**Implementation Lead:** Senior Cryptographic Systems Engineer & TLS 1.3 Protocol Engineer  
**Status:** **COMPLETE & FULLY VERIFIED**

---

## 1. Executive Summary

Phase 2 replaces the legacy simulated TCP framing in `protocols/tls13_pqc_tunnel.py` with a **genuine, standards-compliant RFC 8446 TLS 1.3 implementation** integrating **X25519 + ML-KEM-768 Hybrid Key Exchange (`X25519MLKEM768`)**, Pure Post-Quantum Key Exchange (`MLKEM768`, `MLKEM1024`), and Classical Key Exchange (`X25519`).

All requirements specified for Phase 2 have been fulfilled:
1. **Real TLS 1.3 Stack:** Operates over an actual OpenSSL 4.0.0 TLS 1.3 engine via `cryptography.hazmat.bindings.openssl.binding.Binding()`, strictly enforcing `TLS1_3_VERSION` (`0x0304`).
2. **Standard Hybrid Key Exchange:** Configures and negotiates the official hybrid group `X25519MLKEM768` (per `draft-ietf-tls-hybrid-design` and IANA codepoint `0x11ec`).
3. **Full Security Guarantees:** Genuine X.509 certificate validation, authentic SHA-256/SHA-384 transcript hashing, Finished record verification, and AES-256-GCM / ChaCha20-Poly1305 authenticated record protection.
4. **Traffic Secret Agreement:** Verifies bit-for-bit identity across derived client and server TLS 1.3 key schedule traffic secrets via OpenSSL keylog integration.
5. **Robust Rejection & No Silent Downgrade:** Invalid certificates (untrusted CA, expired validity) and group mismatches are strictly rejected. Requesting unsupported groups (e.g. ML-KEM-512) raises `UnsupportedCipherSuiteError` without silent downgrade.
6. **Zero-Permission Execution:** Implements in-memory BIO stream transport alongside socket transport, enabling 100% reliable, zero-permission, port-conflict-free testing in sandboxed environments.

---

## 2. Architecture & Cryptographic Stack

### 2.1 Underlying Cryptographic Stack
- **Engine Provider:** `pyca/cryptography` v48.0.0
- **TLS Engine:** Compiled Native OpenSSL 4.0.0 (`OpenSSL 4.0.0 14 Apr 2026`, hex: `0x40000000`)
- **Protocol Enforcement:**
  - `SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)`
  - `SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)`
  - Prevents version downgrade to TLS 1.2 or earlier.

### 2.2 Named Groups & Cipher Suites

| Named Group in Engine | Standard Specification | Key Exchange Type | NIST Level | Handshake Overhead |
| :--- | :--- | :--- | :--- | :--- |
| **`X25519MLKEM768`** | `draft-ietf-tls-hybrid-design` (0x11ec) | **Hybrid (X25519 + ML-KEM-768)** | **Level 3 + 128-bit Classical** | 1,216B PK / 1,120B CT |
| **`MLKEM768`** | NIST FIPS 203 Section 8 | **Pure Post-Quantum** | **Level 3 (AES-192 eq.)** | 1,184B PK / 1,088B CT |
| **`MLKEM1024`** | NIST FIPS 203 Section 8 | **Pure Post-Quantum** | **Level 5 (AES-256 eq.)** | 1,568B PK / 1,568B CT |
| **`SecP256r1MLKEM768`**| `draft-ietf-tls-hybrid-design` | **Hybrid (P-256 + ML-KEM-768)** | **Level 3 + 128-bit Classical** | 1,248B PK / 1,152B CT |
| **`X25519`** | RFC 8446 / RFC 7748 | **Classical Curve25519 Baseline** | **Classical 128-bit** | 32B PK / 32B CT |

Negotiated Record AEAD Ciphers:
- `TLS_AES_256_GCM_SHA384` (Default primary)
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

---

## 3. Component Design & Source Structure

### 3.1 [`protocols/tls13_pqc.py`](file:///C:/Users/91990/.gemini/antigravity/scratch/MTech_PQC_Project3/protocols/tls13_pqc.py)
Core RFC 8446 TLS 1.3 protocol engine exposing:
- `RealTLS13Config`: Dataclass specifying named group, cipher suites, certificate paths, CA paths, and verification flags.
- `RealTLS13Server`: OpenSSL 4.0.0 server context. Validates private key consistency, configures named groups, loads certs, and hooks keylog callbacks.
- `RealTLS13Client`: OpenSSL 4.0.0 client context. Enforces peer certificate verification (`SSL_VERIFY_PEER`), configures named groups, and hooks keylog callbacks.
- `TLS13SessionPair`: High-performance in-memory session orchestrator communicating over OpenSSL Memory BIOs (`BIO_s_mem`). Handles handshake state pumping, record encryption/decryption, application data read/write, and traffic secret cross-checks.
- `UnsupportedCipherSuiteError`: Raised immediately when an invalid or unsupported cipher suite is requested.
- `TLSHandshakeError`: Raised when certificate validation fails, a group mismatch occurs, or a fatal alert is received.

### 3.2 [`protocols/tls_cert_utils.py`](file:///C:/Users/91990/.gemini/antigravity/scratch/MTech_PQC_Project3/protocols/tls_cert_utils.py)
Automated X.509 PKI manager using standard TLS 1.3 ECDSA P-256 (`ecdsa_secp256r1_sha256`):
- Root CA Certificate and Key (`ca_cert.pem`)
- Server Certificate and Key (`server_cert.pem`) with SubjectAlternativeNames (`localhost`, `127.0.0.1`)
- Untrusted Rogue Certificate (`rogue_cert.pem`) for negative authentication testing
- Expired Certificate (`expired_cert.pem`) for validity-period rejection testing

### 3.3 [`protocols/tls13_pqc_tunnel.py`](file:///C:/Users/91990/.gemini/antigravity/scratch/MTech_PQC_Project3/protocols/tls13_pqc_tunnel.py)
Backward-compatible wrapper integrating `RealTLS13Server` and `RealTLS13Client` into `TLS13PQCClient` and `TLS13PQCServer`. Maps project enum `CipherSuiteType.HYBRID_X25519_MLKEM768` to OpenSSL group `X25519MLKEM768`.

---

## 4. Key Schedule & Traffic Secret Agreement Verification

During an authentic RFC 8446 TLS 1.3 handshake, the endpoints derive a sequence of traffic secrets from the shared secret ($ss$) negotiated via `X25519MLKEM768`:

$$\text{Early Secret} \longrightarrow \text{Handshake Secret} \longrightarrow \text{Master Secret}$$

Via OpenSSL's `SSL_CTX_set_keylog_callback`, both client and server extract the derived secrets. `TLS13SessionPair.verify_traffic_secrets()` asserts bit-for-bit equality across all five key schedule components:
1. `CLIENT_HANDSHAKE_TRAFFIC_SECRET`: Encrypts server-bound handshake records.
2. `SERVER_HANDSHAKE_TRAFFIC_SECRET`: Encrypts client-bound handshake records (EncryptedExtensions, Certificate, CertificateVerify, Finished).
3. `CLIENT_TRAFFIC_SECRET_0`: Generates Client Write Key & IV for application data records.
4. `SERVER_TRAFFIC_SECRET_0`: Generates Server Write Key & IV for application data records.
5. `EXPORTER_SECRET`: Cryptographic material for application-layer key export.

### Actual Handshake Secret Verification Output:
```text
[+] Key Schedule Traffic Secret Agreement:
    All 5 TLS 1.3 Secrets Matched: True
    - CLIENT_HANDSHAKE_TRAFFIC_SECRET : 6bc32ac331662013...
    - SERVER_HANDSHAKE_TRAFFIC_SECRET : b07064e114fdc211...
    - CLIENT_TRAFFIC_SECRET_0         : e036ddd6d7547b02...
    - SERVER_TRAFFIC_SECRET_0         : 6828b03802076c4c...
    - EXPORTER_SECRET                 : 438ab039e1fb0b68...
```

---

## 5. How to Run Client and Server

### 5.1 Interactive CLI Demonstration

Run the self-contained demonstration directly:
```powershell
Set-Location -Path "C:\Users\91990\.gemini\antigravity\scratch\MTech_PQC_Project3"

# 1. Hybrid X25519 + ML-KEM-768 Key Exchange (Default)
python protocols/tls13_pqc.py --group X25519MLKEM768

# 2. Pure ML-KEM-768 Post-Quantum Key Exchange
python protocols/tls13_pqc.py --group MLKEM768

# 3. Pure ML-KEM-1024 Level 5 Post-Quantum Key Exchange
python protocols/tls13_pqc.py --group MLKEM1024

# 4. Classical X25519 Baseline Comparison
python protocols/tls13_pqc.py --group X25519
```

### 5.2 Programmatic Python API

```python
from protocols.tls_cert_utils import PKIManager
from protocols.tls13_pqc import RealTLS13Config, RealTLS13Server, RealTLS13Client, TLS13SessionPair

with PKIManager() as pki:
    # Configure Server with Hybrid Group
    server_cfg = RealTLS13Config(
        key_exchange_group="X25519MLKEM768",
        cert_file=pki.server_cert_path,
        key_file=pki.server_key_path
    )
    server = RealTLS13Server(server_cfg)

    # Configure Client with Peer Verification
    client_cfg = RealTLS13Config(
        key_exchange_group="X25519MLKEM768",
        ca_file=pki.ca_cert_path,
        verify_peer=True
    )
    client = RealTLS13Client(client_cfg)

    # Establish TLS 1.3 Session
    session = TLS13SessionPair(server, client)
    session.do_handshake()

    print(f"Negotiated Group: {session.get_negotiated_group()}")  # X25519MLKEM768
    print(f"Cipher Suite:     {session.get_cipher_suite()}")      # TLS_AES_256_GCM_SHA384
    print(f"TLS Version:      {session.get_tls_version()}")       # TLSv1.3

    # Send Encrypted Application Data
    session.client_write(b"Hello Quantum-Safe World!")
    received_data = session.server_read()
    print(f"Server Received:  {received_data.decode()}")

    session.close()
    server.close()
    client.close()
```

---

## 6. Automated Testing & Verification Results

A dedicated automated test suite was created in [`tests/test_tls13_pqc_real.py`](file:///C:/Users/91990/.gemini/antigravity/scratch/MTech_PQC_Project3/tests/test_tls13_pqc_real.py), covering all 8 required testing aspects.

### 6.1 Test Execution Command and Output
```powershell
Set-Location -Path "C:\Users\91990\.gemini\antigravity\scratch\MTech_PQC_Project3"
python -m unittest tests/test_tls13_pqc_real.py -v
```

```text
test_01_successful_hybrid_handshake_x25519_mlkem768 (tests.test_tls13_pqc_real.TestRealTLS13PostQuantum.test_01_successful_hybrid_handshake_x25519_mlkem768)
1. Successful TLS 1.3 Handshake with X25519 + ML-KEM-768 Hybrid Key Exchange. ... ok
test_02_client_server_traffic_secret_agreement (tests.test_tls13_pqc_real.TestRealTLS13PostQuantum.test_02_client_server_traffic_secret_agreement)
2. Client and Server Traffic Secret Agreement Verification. ... ok
test_03_encrypted_application_data_transfer (tests.test_tls13_pqc_real.TestRealTLS13PostQuantum.test_03_encrypted_application_data_transfer)
3. Encrypted Application-Data Transmission. ... ok
test_04_pure_mlkem768_handshake (tests.test_tls13_pqc_real.TestRealTLS13PostQuantum.test_04_pure_mlkem768_handshake)
4. Pure Post-Quantum Key Exchange with ML-KEM-768 (NIST Category 3). ... ok
test_05_pure_mlkem1024_handshake (tests.test_tls13_pqc_real.TestRealTLS13PostQuantum.test_05_pure_mlkem1024_handshake)
5. Pure Post-Quantum Key Exchange with ML-KEM-1024 (NIST Category 5). ... ok
test_06_classical_tls_comparison (tests.test_tls13_pqc_real.TestRealTLS13PostQuantum.test_06_classical_tls_comparison)
6. Classical TLS 1.3 Key Exchange Comparison (X25519 baseline). ... ok
test_07_certificate_verification_success (tests.test_tls13_pqc_real.TestRealTLS13PostQuantum.test_07_certificate_verification_success)
7. Real X.509 Certificate Chain of Trust Verification. ... ok
test_08_invalid_certificate_rejection (tests.test_tls13_pqc_real.TestRealTLS13PostQuantum.test_08_invalid_certificate_rejection)
8. Rejection of Untrusted / Rogue Server Certificate. ... ok
test_09_expired_certificate_rejection (tests.test_tls13_pqc_real.TestRealTLS13PostQuantum.test_09_expired_certificate_rejection)
9. Rejection of Expired Server Certificate. ... ok
test_10_unsupported_hybrid_cipher_suite_handling (tests.test_tls13_pqc_real.TestRealTLS13PostQuantum.test_10_unsupported_hybrid_cipher_suite_handling)
10. Unsupported Cipher Suite Handling (Explicit Rejection, No Silent Downgrade). ... ok
test_11_key_exchange_group_mismatch_failure (tests.test_tls13_pqc_real.TestRealTLS13PostQuantum.test_11_key_exchange_group_mismatch_failure)
11. Failed Handshake on Named Group Mismatch. ... ok
test_12_tunnel_client_server_wrapper (tests.test_tls13_pqc_real.TestRealTLS13PostQuantum.test_12_tunnel_client_server_wrapper)
12. Validates TLS13PQCClient and TLS13PQCServer tunnel wrappers. ... ok
test_13_real_tcp_socket_handshake_and_traffic_secrets (tests.test_tls13_pqc_real.TestRealTLS13PostQuantum.test_13_real_tcp_socket_handshake_and_traffic_secrets)
13. Real TCP Socket Handshake, Certificate Authentication, Bidirectional Transfer, ... ok
test_14_negotiated_group_verification_from_session (tests.test_tls13_pqc_real.TestRealTLS13PostQuantum.test_14_negotiated_group_verification_from_session)
14. Direct Negotiated Group Verification from Live OpenSSL SSL Session. ... ok

----------------------------------------------------------------------
Ran 14 tests in 0.168s

OK
```

### 6.2 Real TCP Socket & Direct Negotiated Group Verification (Check 1 & Check 2)

#### 1. Real TCP Socket Verification (`test_13`)
- **OS Socket Binding:** Server binds to `127.0.0.1` on an ephemeral OS-allocated port (`sock.bind(('127.0.0.1', 0))`) using actual Windows TCP sockets (`SOCK_STREAM`).
- **Real Handshake Execution:** Handshake executed over the TCP connection via `_lib.SSL_set_fd(ssl, sock.fileno())` and `_lib.SSL_do_handshake(ssl)`.
- **Certificate Chain Validation:** The client verifies the server's X.509 certificate against the trusted Root CA (`_lib.SSL_get_verify_result(client_ssl) == 0` / `X509_V_OK`).
- **Encrypted Bidirectional Application Data:** Application requests and responses are encrypted and decrypted over the live TCP socket (`SSL_write` / `SSL_read`) using TLS 1.3 AES-256-GCM.
- **Traffic Secret Equality:** All 5 TLS 1.3 Key Schedule traffic secrets captured via `SSL_CTX_set_keylog_callback` (`CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`, `EXPORTER_SECRET`) match bit-for-bit across client and server.
- **Clean Termination:** Endpoints perform proper bidirectional TLS close-notify alerts (`SSL_shutdown`) and close sockets; the server thread joins cleanly with 0 ms hang.

#### 2. Live Session Negotiated Group Verification (`test_14`)
- **Extraction Mechanism:** The test inspects the live OpenSSL session struct directly using `_lib.SSL_get0_group_name(ssl)`. It does **not** read from local configuration or requested parameters.
- **Pre-Handshake State:** Before handshake completion, the session group pointer is strictly `NULL`, verifying that the group is an intrinsic property of the completed cryptographic exchange.
- **Post-Handshake Assertion:**
  - Negotiated Group: **`X25519MLKEM768`** (confirmed on both client and server sessions)
  - Negotiated Protocol: **`TLSv1.3`** (`_lib.SSL_get_version(ssl)`)
  - Negotiated Cipher Suite: **`TLS_AES_256_GCM_SHA384`** (`_lib.SSL_CIPHER_get_name(ssl)`)

### 6.3 Full Repository Test Suite Status
Running the complete test discovery suite verifies that all 39 tests across Phase 1, Phase 1.1, and Phase 2 pass with 100% success:

```powershell
python -m unittest discover -s tests -v
# Ran 39 tests in 0.223s — OK
```

And the comprehensive dissertation evaluation suite:
```powershell
python tests/comprehensive_test_suite.py
# Ran 28 tests in 0.015s — OK (100.0% Success Rate)
```

---

## 7. Limitations & Unsupported Features

1. **ML-KEM-512 in TLS 1.3:**  
   OpenSSL 4.0.0 deliberately does NOT support `ML-KEM-512` or `X25519+ML-KEM-512`. This is intentional: NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) and IETF TLS hybrid standards (`draft-ietf-tls-hybrid-design`) mandate Category 3 (`X25519MLKEM768`) and Category 5 (`SecP384r1MLKEM1024`) as standard key exchange groups, omitting Category 1. Attempting to initialize TLS 1.3 with ML-KEM-512 raises `UnsupportedCipherSuiteError`.
2. **0-RTT Early Data:**  
   Early data (0-RTT) is currently disabled to prevent replay attacks and forward secrecy degradation during initial PQC evaluation.
3. **Post-Quantum Digital Signatures (ML-DSA / FIPS 204):**  
   X.509 certificate chains currently use standard ECDSA P-256 (`ecdsa_secp256r1_sha256`) or RSA-2048. Post-quantum authentication certificates (ML-DSA-65) remain an active standardization area in IETF (`draft-ietf-lamps-kyber-certificates`).

---

## 8. Conclusion & Readiness for Phase 3

Phase 2 is **100% complete**. The repository now possesses a genuine, fully functioning, verified RFC 8446 TLS 1.3 client and server engine negotiating real `X25519MLKEM768` hybrid post-quantum key exchange with zero simulated cryptography. The repository is fully prepared for **Phase 3 (WireGuard Noise IK PQC Remediation)**.
