# M.Tech Cyber Security Project 3: Hybrid Post-Quantum Key Encapsulation

**Title:** Performance Benchmarking and Adaptive Optimization of Hybrid Post-Quantum Key Encapsulation in High-Throughput TLS 1.3 and WireGuard VPNs  
**Specialization:** Cyber Security & Applied Cryptography  
**Standards:** NIST FIPS 203 (ML-KEM / Kyber) | RFC 8446 (TLS 1.3) | RFC 5869 (HKDF) | Noise IK Protocol

---

## 🏛️ Architecture Overview

```
Hybrid-PQC-TLS-WireGuard/
├── main.py                          # Master interactive CLI & runner
├── index.html                       # Local interactive web dashboard application
├── web_dashboard.html               # Web dashboard source template
├── README.md                        # Complete documentation & usage guide
├── .gitignore                       # Git ignore rules for clean environment
├── crypto/                          # Cryptographic Engine
│   ├── hybrid_kem.py                # X25519 + NIST FIPS 203 ML-KEM-512/768/1024
│   ├── dual_hkdf.py                 # RFC 5869 Dual HKDF secret derivation (Eq. 2)
│   ├── kyber512_reference.py        # Module-LWE reference implementation
│   └── packet_framing.py            # Wire framing, MTU slicing & reassembly
├── adaptive_engine/                 # Dynamic Adaptation & Heuristics
│   ├── network_monitor.py           # Real-time RFC 6298 RTT/RTO and Loss tracking
│   ├── heuristics.py                # Mathematical latency model (Eq. 3)
│   └── adaptive_negotiator.py       # Loss- and MTU-aware dynamic cipher selector
├── protocols/                       # Transport Protocol Implementations
│   ├── tls13_pqc_tunnel.py          # Asynchronous high-throughput TLS 1.3 tunnel
│   └── wireguard_pqc_proxy.py       # WireGuard Zero-Trust Noise IK PQC proxy
├── benchmark/                       # Experimental Benchmarking Suite
│   ├── latency_bench.py             # Microsecond crypto & TTFB loss curves
│   ├── throughput_bench.py          # Multi-threaded handshake throughput
│   ├── memory_cpu_profile.py        # Session memory & x86 vs ARM hardware energy
│   ├── network_impairment.py        # Virtual WAN impairment & loss simulator
│   ├── run_all_benchmarks.py        # Orchestrator & CSV/JSON exporter
│   ├── benchmark_results.json       # Complete raw empirical dataset
│   └── benchmark_summary.csv        # Consolidated summary table for LaTeX
├── visualization/                   # Publication Visualizations
│   ├── plot_results.py              # IEEE-format figure generator
│   ├── fig1_latency_vs_loss.png     # Handshake Latency vs. Packet Loss (0%-5%)
│   ├── fig2_throughput_scaling.png  # Handshake Throughput Scaling (conns/s)
│   ├── fig3_key_sizes.png           # Public Key & Ciphertext vs. Ethernet MTU
│   └── fig4_energy_dissipation.png  # Hardware Energy Dissipation (x86 vs. ARM)
├── tests/                           # Automated Verification & Test Suites (100% Pass)
│   ├── comprehensive_test_suite.py  # Master 28-test multi-aspect verification suite
│   ├── test_crypto.py               # Cryptographic primitives & HKDF tests
│   ├── test_adaptive.py             # Adaptive negotiation & heuristics tests
│   └── test_protocols.py            # WireGuard & TLS 1.3 state machine tests
└── dissertation_docs/               # Complete Dissertation Proposal & Report
    └── DISSERTATION_FINAL_REPORT.md # Comprehensive 7-chapter dissertation document
```

---

## ⚡ Quick Start & Usage

### 1. Run Interactive Demonstrations
```bash
# Run the complete interactive demonstration suite
python main.py

# Or run individual demonstration modules:
python main.py --demo-handshake   # Pure Hybrid KEM & Dual HKDF
python main.py --demo-adaptive    # Adaptive Cipher Negotiation under network degradation
python main.py --demo-wireguard   # WireGuard Post-Quantum Noise IK exchange
```

### 2. Run Comprehensive 28-Test Multi-Aspect Suite
```bash
# Run the master multi-aspect verification suite (28/28 tests passing)
python tests/comprehensive_test_suite.py

# Or run standard unittest discovery
python -m unittest discover -s tests -v
```

### 3. Launch Local Interactive Web Dashboard
```bash
# Serve the interactive dashboard locally
python -m http.server 8080

# Open in your browser:
# http://localhost:8080
```

### 4. Run Experimental Benchmark Harness
```bash
# Re-run full experimental profiling (crypto, loss curves, throughput, hardware energy)
python -m benchmark.run_all_benchmarks
```

### 5. Generate IEEE Publication Figures
```bash
# Re-generate high-resolution publication plots in visualization/
python -m visualization.plot_results
```

---

## 📊 Key Experimental Results Summary

1. **Provable Dual Quantum Security:** Combines classical $X25519$ and NIST FIPS 203 $ML-KEM$ via RFC 5869 Dual HKDF:
   $$K_{hybrid} = \text{HKDF-Extract}\left(\text{Salt}, \text{ECDH}(sk_{ec}, pk_{ec}) \mathbin{\Vert} \text{ML-KEM.Decaps}(sk_{pqc}, c_{pqc})\right)$$
2. **Low Latency Overhead:** Restricts handshake latency overhead to $<12\%$ under WAN packet loss ($2\%$).
3. **High Handshake Throughput:** Achieves over $1,770$ conns/sec for Hybrid $X25519 + ML-KEM-768$ and $4,760$ conns/sec for baseline $X25519$.
4. **Adaptive MTU Protection:** Automatically switches to ML-KEM-512 when path MTU drops to $\le 1280\text{B}$ or packet loss exceeds $1.5\%$, preventing catastrophic multi-packet drops and TCP timeout spikes.
5. **Ultra-Low Memory & Energy:** Limits session state to $\le 4.86\text{ KB}$ (well within the $\le 8.6\text{ KB}$ SLA) with an edge energy footprint of $\approx 10.4\ \mu\text{J}$ on ARM Cortex-A53 devices.

---

## 📄 Documentation & Academic Artifacts
* **[DISSERTATION_FINAL_REPORT.md](dissertation_docs/DISSERTATION_FINAL_REPORT.md):** Full 7-chapter dissertation proposal and research findings report.
* **[benchmark_summary.csv](benchmark_summary.csv):** Formatted comparative performance data table.
* **[benchmark_results.json](benchmark_results.json):** Raw microsecond latency percentiles, concurrency throughput distributions, and hardware energy dissipation models.
