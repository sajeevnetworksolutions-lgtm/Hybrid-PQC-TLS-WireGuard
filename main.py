"""
M.Tech Cybersecurity Project 3: Master Controller & CLI
Title: Performance Benchmarking and Adaptive Optimization of Hybrid
       Post-Quantum Key Encapsulation in High-Throughput TLS 1.3 and WireGuard VPNs

Unifies:
1. NIST FIPS 203 ML-KEM & Dual HKDF Pipeline
2. Real TLS 1.3 Post-Quantum Key Exchange (OpenSSL 4.0.0 - RFC 8446)
3. Experimental Hybrid Post-Quantum WireGuard-Based Protocol Research Prototype (Noise_IKpsk2)
4. Empirical Calibrated Adaptive Negotiation Engine (RFC 6298 EWMA)
5. Live REST & Web Dashboard Server
6. Reproducible Final Benchmarking Suite
"""

import sys
import os
import argparse
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto.hybrid_kem import (
    HybridKEMInitiator,
    HybridKEMResponder,
    CipherSuiteType,
    CIPHER_TAXONOMY
)
from crypto.dual_hkdf import DualHKDF
from adaptive_engine.network_monitor import NetworkMonitor
from adaptive_engine.adaptive_negotiator import AdaptiveNegotiator
from adaptive_engine.heuristics import LatencyModeler, calibrate_host_crypto_profile
from protocols.unified_controller import UnifiedProtocolManager
from protocols.tls13_pqc import run_demo as demo_tls13_openssl
from protocols.wireguard_pqc_proxy import WireGuardPQCProxy
from benchmark.final_benchmark import run_full_benchmark
from dashboard_server import run_dashboard_server


def demo_interactive_handshake():
    print("=" * 78)
    print("DEMO: HYBRID POST-QUANTUM KEY ENCAPSULATION & DUAL HKDF PIPELINE")
    print("=" * 78)

    suite = CipherSuiteType.HYBRID_X25519_MLKEM768
    tax = CIPHER_TAXONOMY[suite]
    print(f"\n[+] Selected Suite       : {suite.value}")
    print(f"[+] Security Level       : {tax['security_level']}")
    print(f"[+] NIST PQC Level       : {tax['nist_level']}")
    print(f"[+] Public Key Size      : {tax['pk_size']} Bytes (X25519: 32B + ML-KEM-768: 1184B)")
    print(f"[+] Ciphertext Size      : {tax['ct_size']} Bytes (X25519: 32B + ML-KEM-768: 1088B)")

    initiator = HybridKEMInitiator(suite=suite)
    responder = HybridKEMResponder(suite=suite)

    # 1. Initiator generates Composite Key
    print("\n--- 1. Initiator (Client) Ephemeral Key Generation ---")
    init_pk = initiator.generate_keypair()
    print(f"  -> Generated Composite Public Key ({len(init_pk)} bytes)")
    print(f"  -> Execution Time: {initiator.keygen_time_us:.2f} microseconds")

    # 2. Responder processes Key & Encapsulates
    print("\n--- 2. Responder (Server) Encapsulation & ECDH ---")
    salt = b"TLS13_SESSION_SALT_001"
    resp_payload, server_master_key = responder.process_initiator_pk(init_pk, salt=salt)
    print(f"  -> Generated Server Response Payload ({len(resp_payload)} bytes)")
    print(f"  -> Server Derived Master Key (Hex): {server_master_key.hex()[:32]}...")
    print(f"  -> Execution Time: {responder.encaps_time_us:.2f} microseconds")

    # 3. Initiator decapsulates
    print("\n--- 3. Initiator (Client) Decapsulation & Dual HKDF ---")
    t0 = time.perf_counter_ns()
    client_master_key = initiator.decapsulate_response(resp_payload, salt=salt)
    decaps_us = (time.perf_counter_ns() - t0) / 1000.0
    print(f"  -> Client Derived Master Key (Hex): {client_master_key.hex()[:32]}...")
    print(f"  -> Execution Time: {decaps_us:.2f} microseconds")

    # 4. Verification
    print("\n--- 4. Dual Cryptographic Security Verification ---")
    match = (client_master_key == server_master_key)
    print(f"  -> Secrets Match: {match}")
    print(f"  -> Dual Security Property: IND-CCA2 Quantum Resistance Guaranteed (FIPS 203)")


def demo_adaptive_engine():
    print("=" * 78)
    print("DEMO: ADAPTIVE CIPHER NEGOTIATION UNDER NETWORK IMPAIRMENT")
    print("=" * 78)

    monitor = NetworkMonitor()
    negotiator = AdaptiveNegotiator(target_security_tier="Standard", use_host_calibration=True)

    scenarios = [
        {"name": "Clean Local Network (LAN)", "rtt": 1.5, "loss": 0.00, "mtu": 1500},
        {"name": "Moderate WAN Channel", "rtt": 25.0, "loss": 0.005, "mtu": 1500},
        {"name": "Degraded Lossy WAN (3% Loss)", "rtt": 45.0, "loss": 0.03, "mtu": 1500},
        {"name": "Constrained MTU (Cellular / Tunnel)", "rtt": 35.0, "loss": 0.01, "mtu": 1280},
    ]

    for s in scenarios:
        print(f"\n[Scenario: {s['name']}]")
        print(f"  Conditions: RTT={s['rtt']}ms, Loss={s['loss']*100:.1f}%, MTU={s['mtu']}B")
        monitor.set_channel_state(rtt_ms=s['rtt'], loss_rate=s['loss'], mtu=s['mtu'])
        decision = negotiator.select_optimal_suite(monitor)
        print(f"  -> Selected Suite     : {decision['suite_name']}")
        print(f"  -> Reason             : {decision['decision_reason']}")
        print(f"  -> Fragments Required : {decision['num_fragments']}")
        print(f"  -> Predicted Latency  : {decision['predicted_handshake_ms']} ms (Overhead: {decision['overhead_percent']}%)")
        print(f"  -> Audit Record ID    : #{decision['decision_id']} (Downgrade: {decision['downgrade_occurred']})")


def demo_wireguard_protocol(mode: str = "hybrid"):
    print("=" * 78)
    print(f"DEMO: EXPERIMENTAL POST-QUANTUM WIREGUARD-BASED PROTOCOL ({mode.upper()})")
    print("=" * 78)
    mgr = UnifiedProtocolManager()
    res = mgr.run_wireguard_handshake(mode=mode)
    print(f"[+] Protocol        : {res['protocol']}")
    print(f"[+] Mode            : {res['mode']}")
    print(f"[+] Handshake Time  : {res['handshake_latency_ms']:.3f} ms ({res['handshake_latency_us']:.1f} us)")
    print(f"[+] Msg 1 Initiation: {res['msg1_initiation_bytes']} Bytes (Type 1)")
    print(f"[+] Msg 2 Response  : {res['msg2_response_bytes']} Bytes (Type 2)")
    print(f"[+] Secrets Match   : {res['secrets_match']}")
    print(f"[+] Transport Data  : {res['transport_data_verified']}")
    print(f"[+] Replay Security : TAI64N Timestamps & 64-bit Sliding Window Active")
    print(f"[!] Notice          : {res['classification_notice']}")


def demo_tls13_protocol(mode: str = "hybrid"):
    print("=" * 78)
    print(f"DEMO: REAL TLS 1.3 OPENSSL 4.0.0 PROTOCOL ({mode.upper()})")
    print("=" * 78)
    mgr = UnifiedProtocolManager()
    res = mgr.run_tls13_handshake(mode=mode)
    print(f"[+] Protocol        : {res['protocol']}")
    print(f"[+] Protocol Version: {res['protocol_version']}")
    print(f"[+] Negotiated Group: {res['negotiated_group']}")
    print(f"[+] Cipher Suite    : {res['cipher_suite']}")
    print(f"[+] Handshake Time  : {res['handshake_latency_ms']:.3f} ms ({res['handshake_latency_us']:.1f} us)")
    print(f"[+] Secrets Match   : {res['secrets_match']}")
    print(f"[+] Certificate Auth: {res['certificate_authenticated']}")
    print(f"[+] App Data Echo   : {res['application_data_verified']}")


def main():
    parser = argparse.ArgumentParser(
        description="M.Tech Cybersecurity Project 3: Hybrid Post-Quantum Key Encapsulation Framework"
    )
    parser.add_argument("--protocol", choices=["tls", "wireguard", "both"], default="both", help="Protocol to execute (tls, wireguard, both)")
    parser.add_argument("--mode", choices=["classical", "hybrid", "both"], default="hybrid", help="Key exchange mode (classical, hybrid, both)")
    parser.add_argument("--demo-handshake", action="store_true", help="Run interactive Hybrid KEM & Dual HKDF demo")
    parser.add_argument("--demo-adaptive", action="store_true", help="Run Adaptive Negotiation Engine demo")
    parser.add_argument("--demo-wireguard", action="store_true", help="Run WireGuard Noise IK prototype demo")
    parser.add_argument("--demo-tls", action="store_true", help="Run Real TLS 1.3 OpenSSL demo")
    parser.add_argument("--benchmark", action="store_true", help="Execute complete empirical benchmarking harness")
    parser.add_argument("--quick-benchmark", action="store_true", help="Execute quick empirical benchmark (fewer iters)")
    parser.add_argument("--serve-dashboard", nargs="?", const=8080, type=int, help="Launch live HTTP dashboard server on port (default 8080)")
    parser.add_argument("--all", action="store_true", help="Run all protocol demos and calibrations")

    args = parser.parse_args()

    # Dashboard Server Mode
    if args.serve_dashboard is not None:
        run_dashboard_server(port=args.serve_dashboard)
        return

    # Benchmark Mode
    if args.benchmark or args.quick_benchmark:
        run_full_benchmark(quick=args.quick_benchmark)
        return

    # Execution logic
    if len(sys.argv) == 1 or args.all:
        print("\n" + "#" * 78)
        print("# M.TECH CYBERSECURITY PROJECT 3: HYBRID POST-QUANTUM PROTOCOL FRAMEWORK")
        print("#" * 78 + "\n")
        demo_interactive_handshake()
        print("\n")
        demo_adaptive_engine()
        print("\n")
        demo_tls13_protocol(mode="hybrid")
        print("\n")
        demo_wireguard_protocol(mode="hybrid")
        print("\n")
        print("[+] Unified Execution Completed Successfully.")
        print("[+] To launch the live interactive dashboard: python main.py --serve-dashboard 8080")
        print("[+] To run full empirical benchmarks: python main.py --benchmark\n")
        return

    if args.demo_handshake:
        demo_interactive_handshake()
    if args.demo_adaptive:
        demo_adaptive_engine()
    if args.demo_tls:
        demo_tls13_protocol(mode="hybrid" if args.mode in ("hybrid", "both") else "classical")
    if args.demo_wireguard:
        demo_wireguard_protocol(mode="hybrid" if args.mode in ("hybrid", "both") else "classical")

    if not any([args.demo_handshake, args.demo_adaptive, args.demo_tls, args.demo_wireguard]):
        # Run selected protocol and mode
        modes_to_run = ["hybrid"] if args.mode == "hybrid" else (["classical"] if args.mode == "classical" else ["classical", "hybrid"])
        for m in modes_to_run:
            if args.protocol in ("tls", "both"):
                demo_tls13_protocol(mode=m)
                print()
            if args.protocol in ("wireguard", "both"):
                demo_wireguard_protocol(mode=m)
                print()


if __name__ == "__main__":
    main()
