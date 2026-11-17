# M.Tech Cyber Security Project 3: Hybrid Post-Quantum Key Encapsulation

**Title:** Performance Benchmarking and Adaptive Optimization of Hybrid Post-Quantum Key Encapsulation in High-Throughput TLS 1.3 and WireGuard VPNs  
**Specialization:** Cyber Security & Applied Cryptography  
**Standards:** NIST FIPS 203 (ML-KEM) | RFC 7748 (X25519) | RFC 8446 (TLS 1.3) | draft-ietf-tls-hybrid-design | RFC 5869 (HKDF) | Noise IK Protocol Framework  
**Remediation Status:** Phase 1, Phase 1.1, Phase 2 & Phase 3 Complete (Real TLS 1.3 Post-Quantum Key Exchange & Experimental Hybrid WireGuard-Based Protocol Implemented & Verified)

---

## 🏛️ Architecture Overview

```
Hybrid-PQC-TLS-WireGuard/
├── main.py                          # Unified CLI controller & protocol orchestrator
├── dashboard_server.py              # Live REST API & Web Dashboard Server
├── index.html                       # Live interactive web dashboard application
├── web_dashboard.html               # Web dashboard source template
├── README.md                        # Complete documentation & usage guide
├── FINAL_PROJECT_REPORT.md          # Master executive dissertation report
├── FINAL_ARCHITECTURE.md            # System architecture & cryptographic state machines
├── FINAL_BENCHMARK_REPORT.md        # Comprehensive empirical benchmark analysis
├── FINAL_TEST_REPORT.md             # Quality assurance & security boundary test report
├── FINAL_LIMITATIONS_AND_FUTURE_WORK.md # Technical limitations & future research agenda
├── AUDIT_REPORT.md                  # Comprehensive 32-issue independent audit report
├── CRYPTOGRAPHY.md                  # Cryptographic architecture & FIPS 203 specifications
├── PHASE1_VERIFICATION_REPORT.md    # Phase 1 verification evidence & benchmark report
├── PHASE1_1_INDEPENDENT_VERIFICATION.md # Phase 1.1 independent verification & official NIST KAT report
├── PHASE2_TLS_REPORT.md             # Phase 2 Real TLS 1.3 Post-Quantum Key Exchange report
├── PHASE3_WIREGUARD_REPORT.md       # Phase 3 Experimental Hybrid WireGuard Protocol report
├── PHASE3_FINAL_STATUS.md           # Executive classification & status of Phase 3
├── requirements.txt                 # Verified Python dependencies (cryptography, mlkem)
├── .gitignore                       # Git ignore rules for clean environment
├── crypto/                          # Cryptographic Engine (Remediated in Phase 1)
│   ├── hybrid_kem.py                # X25519 + NIST FIPS 203 ML-KEM-512/768/1024
│   ├── dual_hkdf.py                 # Domain-separated HKDF-SHA-256 hybrid secret combiner
│   ├── kyber512_reference.py        # FIPS 203 ML-KEM-512 constant-time provider
│   └── packet_framing.py            # Wire framing, MTU slicing & reassembly
├── adaptive_engine/                 # Dynamic Adaptation & Host-Calibrated Heuristics
│   ├── network_monitor.py           # Real-time RFC 6298 RTT/RTO, Loss tracking & live ingestion
│   ├── heuristics.py                # Latency model (Eq. 3) & host empirical calibration
│   └── adaptive_negotiator.py       # Strict downgrade-preventing dynamic cipher selector
├── protocols/                       # Transport Protocol Implementations (Phase 2 & 3 Remediated)
│   ├── unified_controller.py        # Unified Protocol Manager for TLS 1.3 & WireGuard
│   ├── tls13_pqc.py                 # Genuine RFC 8446 TLS 1.3 Engine (X25519MLKEM768)
│   ├── tls_cert_utils.py            # Automated X.509 PKI & ECDSA Certificate Manager
│   ├── tls13_pqc_tunnel.py          # High-throughput TLS 1.3 tunnel client & server
│   ├── wireguard_pqc.py             # Experimental Hybrid WireGuard Protocol Engine (X25519 + ML-KEM-768)
│   └── wireguard_pqc_proxy.py       # Remediated WireGuard Noise IK PQC proxy (real BLAKE2s MACs)
├── benchmark/                       # Experimental Benchmarking Suite
│   ├── final_benchmark.py           # Reproducible final empirical benchmarking harness
│   ├── final_benchmark_results.json # Comprehensive empirical dataset (1,000 runs)
│   ├── final_benchmark_summary.csv  # Consolidated summary table for publication
│   ├── latency_bench.py             # Microsecond crypto & TTFB loss curves
│   ├── throughput_bench.py          # Multi-threaded handshake throughput
│   ├── memory_cpu_profile.py        # Session memory & x86 vs ARM hardware energy
│   └── network_impairment.py        # Virtual WAN impairment & loss simulator
├── visualization/                   # Publication Visualizations
│   ├── plot_results.py              # IEEE-format figure generator
│   ├── fig1_latency_vs_loss.png     # Handshake Latency vs. Packet Loss (0%-5%)
│   ├── fig2_throughput_scaling.png  # Handshake Throughput Scaling (conns/s)
│   ├── fig3_key_sizes.png           # Public Key & Ciphertext vs. Ethernet MTU
│   └── fig4_energy_dissipation.png  # Hardware Energy Dissipation (x86 vs. ARM)
├── tests/                           # Automated Verification & Test Suites (100% Pass)
│   ├── test_final_integration.py    # End-to-end integration & downgrade prevention tests (8 tests)
│   ├── test_wireguard_pqc_real.py   # Experimental WireGuard Post-Quantum test suite (12 tests)
│   ├── test_tls13_pqc_real.py       # Real RFC 8446 TLS 1.3 automated test suite (14 tests)
│   ├── test_fips203_phase1.py       # Independent 12-aspect Phase 1 verification suite
│   ├── test_cross_library.py        # OpenSSL 4.0.0 <-> Rust mlkem cross-library verification (5 tests)
│   ├── comprehensive_test_suite.py  # Master 28-test multi-aspect verification suite
│   ├── test_fastapi_dashboard.py    # FastAPI web dashboard REST API test suite (10 tests)
│   ├── test_crypto.py               # Cryptographic primitives & HKDF tests (3 tests)
│   ├── test_adaptive.py             # Adaptive negotiation & heuristics tests (3 tests)
│   └── test_protocols.py            # WireGuard & TLS 1.3 state machine tests (2 tests)
├── app.py                           # Unified FastAPI Web Backend Application (Port 8000)
├── start.bat                        # One-Click Windows Startup Script (Batch)
├── start.ps1                        # One-Click Windows Startup Script (PowerShell)
└── dissertation_docs/               # Complete Dissertation Proposal & Report
    └── DISSERTATION_FINAL_REPORT.md # Comprehensive 7-chapter dissertation document
```

---

## ⚡ Quick Start & One-Click Launch

### 1. One-Click Launch on Windows (Recommended)
Launch the complete application with automated virtual environment check, dependency validation, and browser opening:
```cmd
start.bat
```
Or via PowerShell:
```powershell
.\start.ps1
```
The script automatically starts the FastAPI server and opens your default browser at:
**`http://127.0.0.1:8000`** (Rendered in clean, high-contrast **Light Mode**).

---

### 2. Manual Installation & Startup
```bash
# 1. Install dependencies (FastAPI, uvicorn, cryptography, mlkem, etc.)
pip install -r requirements.txt

# 2. Launch the FastAPI application directly
python app.py 8000
# Or via uvicorn:
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser.

---

### 3. REST API Endpoints Overview
The FastAPI backend provides live endpoints for all cryptographic operations:
| Endpoint | Method | Functionality |
| :--- | :---: | :--- |
| `GET /` | `HTML` | Serves the interactive Light Mode Web Dashboard |
| `GET /api/health` | `JSON` | Health-check endpoint reporting engine & library versions |
| `GET /api/status` | `JSON` | Live cryptographic, TLS 1.3, WireGuard, and test status |
| `POST /api/handshake/tls` | `JSON` | Real RFC 8446 TLS 1.3 hybrid handshake (`X25519MLKEM768`) |
| `POST /api/handshake/wireguard` | `JSON` | Experimental Noise_IKpsk2 WireGuard handshake |
| `POST /api/crypto/keygen` | `JSON` | Generates real NIST FIPS 203 ML-KEM ephemeral keypairs |
| `POST /api/crypto/encapsulate` | `JSON` | Encapsulates shared secret against public key |
| `POST /api/crypto/decapsulate` | `JSON` | Decapsulates ciphertext and verifies secret agreement |
| `POST /api/crypto/encrypt` | `JSON` | Real AEAD authenticated encryption (AES-256-GCM / ChaCha20-Poly1305) |
| `POST /api/crypto/decrypt` | `JSON` | Authenticated decryption + bit-flip tamper rejection testing |
| `POST /api/adaptive/evaluate` | `JSON` | Evaluates RTT, loss, and MTU via Equation 3 heuristic |
| `GET /api/benchmark/summary` | `JSON` | Serves verified 1,000-iteration empirical benchmark results |
| `POST /api/benchmark/run-quick`| `JSON` | Triggers a live micro-benchmark and returns measured latencies |

---

### 4. Run Phase 1 Cryptographic Verification Suite
Execute the independent 12-aspect verification suite validating FIPS 203 ML-KEM (512, 768, 1024), X25519, input validation, and cross-library interoperability:
```bash
python -m unittest tests/test_fips203_phase1.py -v
```

### 5. Run Real TLS 1.3 Post-Quantum Handshake (Phase 2)
Run the live RFC 8446 TLS 1.3 demonstration negotiating `X25519MLKEM768`:
```bash
# 1. Run live TLS 1.3 Post-Quantum Handshake demonstration
python protocols/tls13_pqc.py --group X25519MLKEM768

# 2. Run the automated Real TLS 1.3 test suite (14 tests)
python -m unittest tests/test_tls13_pqc_real.py -v
```

### 6. Run Experimental Hybrid WireGuard-Based Protocol Test Suite (Phase 3)
Run the automated test suite for Classical Baseline & Experimental Hybrid WireGuard (`X25519 + ML-KEM-768`):
```bash
python -m unittest tests/test_wireguard_pqc_real.py -v
```

### 7. Unified Controller & Interactive Demonstrations
```bash
# Run unified execution across TLS 1.3 & WireGuard in hybrid mode
python main.py

# Run specific protocols and modes:
python main.py --protocol tls --mode hybrid          # Real OpenSSL 4.0.0 TLS 1.3 (X25519MLKEM768)
python main.py --protocol wireguard --mode hybrid    # Experimental WireGuard Noise_IKpsk2 (ML-KEM-768)
python main.py --protocol both --mode classical      # Classical baselines (X25519 ECDH)
python main.py --demo-handshake                      # Pure Hybrid KEM & Dual HKDF pipeline
python main.py --demo-adaptive                       # Host-calibrated Adaptive Negotiation engine
python main.py --serve-dashboard 8000                # Live FastAPI Dashboard Server
```

### 6. Launch Live Interactive Web Dashboard Server
### 8. Run Reproducible Empirical Benchmark Suite
```bash
# Execute 1,000 primitive iterations & 100 protocol handshakes with statistical analysis
python benchmark/final_benchmark.py

# Or run quick validation benchmark:
python benchmark/final_benchmark.py --quick
```

### 9. Run Full Regression & Integration Test Suite
```bash
# Run all 69 discovery unit & integration tests (including 10 FastAPI tests)
python -m unittest discover -s tests -v

# Run the master dissertation compliance suite (28 Tests - 100% Passing)
python tests/comprehensive_test_suite.py
```

---

## 📄 Project Governance & Technical Documentation

### Final Dissertation Reports (Final Integration Phase)
* **[PROJECT_FREEZE.md](PROJECT_FREEZE.md):** 🔒 Definitive freeze record — exact dependency versions, test execution results (87 run / 85 passed / 2 skipped), benchmark environment, and known limitations.
* **[FINAL_PROJECT_REPORT.md](FINAL_PROJECT_REPORT.md):** Comprehensive executive dissertation report summarizing all phases, objectives, empirical findings, and academic contributions.
* **[FINAL_VALIDATION_REPORT.md](FINAL_VALIDATION_REPORT.md):** Independent technical validation report verifying adaptive security, downgrade prevention, benchmark decoupling, dashboard contracts, and dissertation readiness.
* **[FINAL_ARCHITECTURE.md](FINAL_ARCHITECTURE.md):** Complete system architecture, FIPS 203 parameters, TLS 1.3 state machine, Noise_IKpsk2 framing, and adaptive engine specification.
* **[FINAL_BENCHMARK_REPORT.md](FINAL_BENCHMARK_REPORT.md):** Detailed statistical analysis across 1,000 iterations (latency, throughput, wire sizes, fragmentation, hardware energy).
* **[FINAL_TEST_REPORT.md](FINAL_TEST_REPORT.md):** Verification & validation report covering all 87 test executions (85 passed, 2 skipped in Windows sandbox / both pass unsandboxed), negative security boundary testing, and KAT results.
* **[FINAL_LIMITATIONS_AND_FUTURE_WORK.md](FINAL_LIMITATIONS_AND_FUTURE_WORK.md):** Rigorous analysis of technical constraints (userspace prototype, classical authentication gap, PMTU discovery) and future research roadmap.

### Prior Phase Verification Reports
* **[AUDIT_REPORT.md](AUDIT_REPORT.md):** Comprehensive 32-issue independent technical audit identifying legacy simulated primitives.
* **[CRYPTOGRAPHY.md](CRYPTOGRAPHY.md):** Mathematical specification of FIPS 203 ML-KEM and RFC 5869 Dual HKDF algorithms.
* **[PHASE1_VERIFICATION_REPORT.md](PHASE1_VERIFICATION_REPORT.md):** Phase 1 cryptographic foundation remediation evidence and verification benchmarks.
* **[PHASE1_1_INDEPENDENT_VERIFICATION.md](PHASE1_1_INDEPENDENT_VERIFICATION.md):** Official NIST ACVP Known-Answer Test (KAT) vectors and cross-library interoperability report.
* **[PHASE2_TLS_REPORT.md](PHASE2_TLS_REPORT.md):** Real RFC 8446 TLS 1.3 hybrid key exchange, traffic secret validation, and TCP socket testing report.
* **[PHASE3_WIREGUARD_REPORT.md](PHASE3_WIREGUARD_REPORT.md):** Experimental Hybrid Post-Quantum WireGuard-Based Protocol (Noise_IKpsk2), anti-replay defense, and empirical benchmarking.
* **[PHASE3_FINAL_STATUS.md](PHASE3_FINAL_STATUS.md):** Classification boundaries and operational capabilities of the Phase 3 implementation.
* **[DISSERTATION_FINAL_REPORT.md](dissertation_docs/DISSERTATION_FINAL_REPORT.md):** Full 7-chapter dissertation proposal and research findings report.
