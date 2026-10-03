"""
Handshake Latency & TTFB Benchmarking Module
Measures cryptographic execution, network transmission, percentile latency distributions,
and adaptive fragmentation guards.
"""

import time
import os
import numpy as np
from typing import Dict, Any, List
from crypto.hybrid_kem import (
    HybridKEMInitiator,
    HybridKEMResponder,
    CipherSuiteType,
    CIPHER_TAXONOMY
)
from benchmark.network_impairment import VirtualNetworkChannel
from adaptive_engine.network_monitor import NetworkMonitor
from adaptive_engine.adaptive_negotiator import AdaptiveNegotiator


def benchmark_crypto_primitives(iterations: int = 300) -> Dict[str, Any]:
    """
    Microsecond-resolution benchmark of pure cryptographic operations for each cipher suite.
    """
    results = {}
    for suite in CipherSuiteType:
        keygen_times = []
        encaps_times = []
        decaps_times = []
        total_crypto_times = []

        for _ in range(iterations):
            initiator = HybridKEMInitiator(suite=suite)
            responder = HybridKEMResponder(suite=suite)

            # 1. KeyGen
            t0 = time.perf_counter_ns()
            init_pk = initiator.generate_keypair()
            t1 = time.perf_counter_ns()
            keygen_us = (t1 - t0) / 1000.0

            # 2. Encapsulation / Server processing
            t2 = time.perf_counter_ns()
            resp_payload, server_key = responder.process_initiator_pk(init_pk)
            t3 = time.perf_counter_ns()
            encaps_us = (t3 - t2) / 1000.0

            # 3. Decapsulation / Client processing
            t4 = time.perf_counter_ns()
            client_key = initiator.decapsulate_response(resp_payload)
            t5 = time.perf_counter_ns()
            decaps_us = (t5 - t4) / 1000.0

            total_us = keygen_us + encaps_us + decaps_us

            keygen_times.append(keygen_us)
            encaps_times.append(encaps_us)
            decaps_times.append(decaps_us)
            total_crypto_times.append(total_us)

        results[suite.value] = {
            "keygen_mean_us": round(float(np.mean(keygen_times)), 2),
            "keygen_std_us": round(float(np.std(keygen_times)), 2),
            "encaps_mean_us": round(float(np.mean(encaps_times)), 2),
            "encaps_std_us": round(float(np.std(encaps_times)), 2),
            "decaps_mean_us": round(float(np.mean(decaps_times)), 2),
            "decaps_std_us": round(float(np.std(decaps_times)), 2),
            "total_crypto_mean_us": round(float(np.mean(total_crypto_times)), 2),
            "total_crypto_p95_us": round(float(np.percentile(total_crypto_times, 95)), 2),
            "total_crypto_p99_us": round(float(np.percentile(total_crypto_times, 99)), 2),
            "pk_size_bytes": CIPHER_TAXONOMY[suite]["pk_size"],
            "ct_size_bytes": CIPHER_TAXONOMY[suite]["ct_size"],
            "is_quantum_safe": CIPHER_TAXONOMY[suite]["is_quantum_safe"]
        }

    return results


def benchmark_network_latency_curve(
    loss_rates: List[float] = [0.0, 0.005, 0.01, 0.02, 0.03, 0.05],
    base_rtt_ms: float = 20.0,
    mtu: int = 1500,
    iterations_per_point: int = 100,
    cert_size: int = 1200
) -> Dict[str, Any]:
    """
    Evaluates end-to-end handshake latency across network packet loss rates.
    Simulates real certificate + key exchange flight over fragmented MTU channels.
    """
    dummy_cert = b"\xaa" * cert_size

    suites_to_test = [
        CipherSuiteType.CLASSIC_X25519,
        CipherSuiteType.HYBRID_X25519_MLKEM512,
        CipherSuiteType.HYBRID_X25519_MLKEM768,
        CipherSuiteType.HYBRID_X25519_MLKEM1024
    ]

    results = {
        "loss_rates_percent": [round(l * 100, 2) for l in loss_rates]
    }
    for s in suites_to_test:
        results[s.value] = []
    results["Adaptive_Optimization"] = []

    for loss in loss_rates:
        channel = VirtualNetworkChannel(
            base_rtt_ms=base_rtt_ms,
            loss_rate=loss,
            mtu=mtu,
            jitter_ms=1.5,
            rto_base_ms=150.0
        )

        # Benchmark standard suites
        for s in suites_to_test:
            latencies = []
            for _ in range(iterations_per_point):
                init = HybridKEMInitiator(s)
                resp = HybridKEMResponder(s)

                t0 = time.perf_counter_ns()
                pk = init.generate_keypair()
                # Flight 1: ClientHello + KeyShare + Cert
                tx1 = channel.simulate_transmission(dummy_cert + pk)

                # Server response
                r_payload, s_key = resp.process_initiator_pk(pk)
                # Flight 2: ServerHello + Cert + Encapsulated Key
                tx2 = channel.simulate_transmission(dummy_cert + r_payload)

                c_key = init.decapsulate_response(r_payload)
                t1 = time.perf_counter_ns()

                crypto_ms = (t1 - t0) / 1_000_000.0
                total_ms = crypto_ms + tx1["elapsed_ms"] + tx2["elapsed_ms"]
                latencies.append(total_ms)

            results[s.value].append(round(float(np.mean(latencies)), 2))

        # Benchmark Proposed Adaptive Optimization
        adapt_latencies = []
        monitor = NetworkMonitor(initial_rtt_ms=base_rtt_ms, initial_mtu=mtu, initial_loss_rate=loss)
        negotiator = AdaptiveNegotiator(target_security_tier="Standard")

        for _ in range(iterations_per_point):
            decision = negotiator.select_optimal_suite(monitor, cert_size=cert_size)
            chosen_suite = decision["selected_suite"]

            init = HybridKEMInitiator(chosen_suite)
            resp = HybridKEMResponder(chosen_suite)

            t0 = time.perf_counter_ns()
            pk = init.generate_keypair()
            tx1 = channel.simulate_transmission(dummy_cert + pk)
            r_payload, s_key = resp.process_initiator_pk(pk)
            tx2 = channel.simulate_transmission(dummy_cert + r_payload)
            c_key = init.decapsulate_response(r_payload)
            t1 = time.perf_counter_ns()

            crypto_ms = (t1 - t0) / 1_000_000.0
            total_ms = crypto_ms + tx1["elapsed_ms"] + tx2["elapsed_ms"]
            adapt_latencies.append(total_ms)

        results["Adaptive_Optimization"].append(round(float(np.mean(adapt_latencies)), 2))

    return results
