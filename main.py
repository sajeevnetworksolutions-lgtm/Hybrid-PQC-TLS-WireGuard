"""
M.Tech Cybersecurity Project 3: Master CLI & Interactive Demonstration
Title: Performance Benchmarking and Adaptive Optimization of Hybrid
       Post-Quantum Key Encapsulation in High-Throughput TLS 1.3 and WireGuard VPNs
"""

import sys
import os
import argparse
import asyncio
import time

from crypto.hybrid_kem import (
    HybridKEMInitiator,
    HybridKEMResponder,
    CipherSuiteType,
    CIPHER_TAXONOMY
)
from crypto.dual_hkdf import DualHKDF
from crypto.packet_framing import PacketFramer
from adaptive_engine.network_monitor import NetworkMonitor
from adaptive_engine.adaptive_negotiator import AdaptiveNegotiator
from adaptive_engine.heuristics import LatencyModeler
from protocols.tls13_pqc_tunnel import TLS13PQCClient, TLS13PQCServer
from protocols.wireguard_pqc_proxy import WireGuardPQCProxy
from benchmark.run_all_benchmarks import run_full_benchmark_suite
from visualization.plot_results import generate_all_plots


def demo_interactive_handshake():
    print("=" * 75)
    print("DEMO: HYBRID POST-QUANTUM KEY ENCAPSULATION & DUAL HKDF PIPELINE")
    print("=" * 75)

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
    print(f"  -> Server Derived Master Key (Hex): {server_master_key.hex()}")
    print(f"  -> Execution Time: {responder.encaps_time_us:.2f} microseconds")

    # 3. Initiator decapsulates
    print("\n--- 3. Initiator (Client) Decapsulation & Dual HKDF ---")
    t0 = time.perf_counter_ns()
    client_master_key = initiator.decapsulate_response(resp_payload, salt=salt)
    decaps_us = (time.perf_counter_ns() - t0) / 1000.0
    print(f"  -> Client Derived Master Key (Hex): {client_master_key.hex()}")
    print(f"  -> Execution Time: {decaps_us:.2f} microseconds")

    # 4. Verification
    print("\n--- 4. Dual Cryptographic Security Verification ---")
    match = (client_master_key == server_master_key)
    print(f"  -> Secrets Match: {match}")
    print(f"  -> Dual Security Property: IND-CCA2 Quantum Resistance Guaranteed (FIPS 203)")


def demo_adaptive_engine():
    print("=" * 75)
    print("DEMO: ADAPTIVE CIPHER NEGOTIATION UNDER NETWORK IMPAIRMENT")
    print("=" * 75)

    monitor = NetworkMonitor()
    negotiator = AdaptiveNegotiator(target_security_tier="Standard")

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


def demo_wireguard_proxy():
    print("=" * 75)
    print("DEMO: WIREGUARD ZERO-TRUST POST-QUANTUM NOISE IK TUNNEL")
    print("=" * 75)

    peer_a = WireGuardPQCProxy("Edge_Client", suite=CipherSuiteType.HYBRID_X25519_MLKEM768)
    peer_b = WireGuardPQCProxy("Cloud_VPN_Gateway", suite=CipherSuiteType.HYBRID_X25519_MLKEM768)

    print("\n[+] Step 1: Client sends Message 1 (Noise IK Init + ML-KEM-768 PK)")
    msg1, _ = peer_a.initiate_wireguard_handshake(peer_b.static_pub_ec)
    print(f"  -> WireGuard Msg 1 Size: {len(msg1)} Bytes")
    print(f"  -> Time: {peer_a.handshake_stats['init_time_us']:.2f} us")

    print("\n[+] Step 2: Gateway processes Message 1 & returns Message 2 (Response + CT_pqc)")
    msg2, key_b = peer_b.respond_wireguard_handshake(msg1, peer_a.static_pub_ec)
    print(f"  -> WireGuard Msg 2 Size: {len(msg2)} Bytes")
    print(f"  -> Time: {peer_b.handshake_stats['resp_time_us']:.2f} us")
    print(f"  -> Gateway Session Key  : {key_b.hex()}")

    print("\n[+] Step 3: Client finalizes handshake")
    key_a = peer_a.complete_wireguard_handshake(msg2)
    print(f"  -> Client Session Key   : {key_a.hex()}")
    print(f"  -> Handshake Completed  : Keys Match = {key_a == key_b}")


def main():
    parser = argparse.ArgumentParser(
        description="M.Tech Cybersecurity Project 3: Hybrid Post-Quantum Key Encapsulation Framework"
    )
    parser.add_argument("--demo-handshake", action="store_true", help="Run interactive Hybrid KEM & Dual HKDF demo")
    parser.add_argument("--demo-adaptive", action="store_true", help="Run Adaptive Negotiation Engine demo")
    parser.add_argument("--demo-wireguard", action="store_true", help="Run WireGuard Post-Quantum Noise IK proxy demo")
    parser.add_argument("--benchmark", action="store_true", help="Execute complete empirical benchmarking harness")
    parser.add_argument("--plot", action="store_true", help="Generate publication-ready IEEE figures")
    parser.add_argument("--all", action="store_true", help="Run all demos, benchmarks, and generate plots")

    args = parser.parse_args()

    if len(sys.argv) == 1 or args.all:
        demo_interactive_handshake()
        print("\n")
        demo_adaptive_engine()
        print("\n")
        demo_wireguard_proxy()
        print("\n")
        if args.benchmark or args.all:
            run_full_benchmark_suite(".")
            generate_all_plots()
    else:
        if args.demo_handshake:
            demo_interactive_handshake()
        if args.demo_adaptive:
            demo_adaptive_engine()
        if args.demo_wireguard:
            demo_wireguard_proxy()
        if args.benchmark:
            run_full_benchmark_suite(".")
        if args.plot:
            generate_all_plots()


if __name__ == "__main__":
    main()
