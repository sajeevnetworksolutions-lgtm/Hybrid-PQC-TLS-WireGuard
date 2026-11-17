"""
Phase 1.1 Cryptographic Performance Validation Benchmark
Complies with Task 6 requirements:
- At least 1,000 iterations per primitive
- 100 warm-up iterations
- 5 independent trials per primitive
- Statistical metrics: Median, Mean, Standard Deviation, P95, P99
- Consistent hardware and software configuration recording
- Clearly defined measurement boundaries for standalone primitives and hybrid suites
- Saves raw data and summary statistics to JSON
"""

import os
import sys
import time
import json
import platform
import statistics
import psutil
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import mlkem as pyca_mlkem
from cryptography.hazmat.backends.openssl import backend as openssl_backend
import mlkem as rust_mlkem

from crypto.dual_hkdf import DualHKDF
from crypto.kyber512_reference import MLKEM512PrivateKey, MLKEM512PublicKey
from crypto.hybrid_kem import (
    HybridKEMInitiator,
    HybridKEMResponder,
    CipherSuiteType,
    CIPHER_TAXONOMY
)


def get_system_environment() -> Dict[str, Any]:
    """Capture detailed hardware and software execution environment."""
    return {
        "os": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count_physical": psutil.cpu_count(logical=False),
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "total_ram_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "python_version": sys.version,
        "cryptography_version": "48.0.0",
        "openssl_version": openssl_backend.openssl_version_text(),
        "mlkem_version": "0.2.0"
    }


def benchmark_standalone_primitives(
    warmup_iters: int = 100,
    trial_iters: int = 1000,
    trials_count: int = 5
) -> Dict[str, Any]:
    """
    Measures isolated standalone cryptographic operations:
    - X25519 (KeyGen, Diffie-Hellman Exchange)
    - ML-KEM-512 (KeyGen, Encaps, Decaps via Rust mlkem)
    - ML-KEM-768 (KeyGen, Encaps, Decaps via OpenSSL and Rust mlkem)
    - ML-KEM-1024 (KeyGen, Encaps, Decaps via OpenSSL and Rust mlkem)
    - DualHKDF (Extract + Expand)
    """
    print("=" * 70)
    print("BENCHMARKING STANDALONE CRYPTOGRAPHIC PRIMITIVES")
    print(f"Config: {warmup_iters} warm-up, {trial_iters} iters/trial, {trials_count} trials")
    print("=" * 70)

    results = {}

    # 1. X25519 (RFC 7748)
    print("\n[1/5] Benchmarking X25519 (Classical Baseline)...")
    # Warmup
    for _ in range(warmup_iters):
        priv_a = x25519.X25519PrivateKey.generate()
        priv_b = x25519.X25519PrivateKey.generate()
        pub_b = priv_b.public_key()
        ss = priv_a.exchange(pub_b)

    keygen_trials = []
    exchange_trials = []
    for t in range(trials_count):
        kg_times = []
        ex_times = []
        for _ in range(trial_iters):
            t0 = time.perf_counter_ns()
            priv_a = x25519.X25519PrivateKey.generate()
            t1 = time.perf_counter_ns()
            priv_b = x25519.X25519PrivateKey.generate()
            pub_b = priv_b.public_key()
            t2 = time.perf_counter_ns()
            ss = priv_a.exchange(pub_b)
            t3 = time.perf_counter_ns()
            kg_times.append((t1 - t0) / 1000.0)
            ex_times.append((t3 - t2) / 1000.0)
        keygen_trials.extend(kg_times)
        exchange_trials.extend(ex_times)

    results["X25519"] = {
        "KeyGen_us": {
            "mean": statistics.mean(keygen_trials),
            "median": statistics.median(keygen_trials),
            "std": statistics.stdev(keygen_trials),
            "p95": sorted(keygen_trials)[int(0.95 * len(keygen_trials))],
            "p99": sorted(keygen_trials)[int(0.99 * len(keygen_trials))]
        },
        "Exchange_us": {
            "mean": statistics.mean(exchange_trials),
            "median": statistics.median(exchange_trials),
            "std": statistics.stdev(exchange_trials),
            "p95": sorted(exchange_trials)[int(0.95 * len(exchange_trials))],
            "p99": sorted(exchange_trials)[int(0.99 * len(exchange_trials))]
        }
    }

    # 2. ML-KEM-512 (Rust mlkem)
    print("[2/5] Benchmarking ML-KEM-512 (FIPS 203 Category 1)...")
    kem512 = rust_mlkem.ML_KEM(rust_mlkem.ParameterSet.ML_KEM_512)
    for _ in range(warmup_iters):
        ek, dk = kem512.key_gen()
        ss, ct = kem512.encaps(ek)
        ss2 = kem512.decaps(dk, ct)

    kg_trials, enc_trials, dec_trials = [], [], []
    for t in range(trials_count):
        for _ in range(trial_iters):
            t0 = time.perf_counter_ns()
            ek, dk = kem512.key_gen()
            t1 = time.perf_counter_ns()
            ss, ct = kem512.encaps(ek)
            t2 = time.perf_counter_ns()
            ss2 = kem512.decaps(dk, ct)
            t3 = time.perf_counter_ns()
            kg_trials.append((t1 - t0) / 1000.0)
            enc_trials.append((t2 - t1) / 1000.0)
            dec_trials.append((t3 - t2) / 1000.0)

    results["ML-KEM-512"] = {
        "KeyGen_us": {
            "mean": statistics.mean(kg_trials),
            "median": statistics.median(kg_trials),
            "std": statistics.stdev(kg_trials),
            "p95": sorted(kg_trials)[int(0.95 * len(kg_trials))],
            "p99": sorted(kg_trials)[int(0.99 * len(kg_trials))]
        },
        "Encaps_us": {
            "mean": statistics.mean(enc_trials),
            "median": statistics.median(enc_trials),
            "std": statistics.stdev(enc_trials),
            "p95": sorted(enc_trials)[int(0.95 * len(enc_trials))],
            "p99": sorted(enc_trials)[int(0.99 * len(enc_trials))]
        },
        "Decaps_us": {
            "mean": statistics.mean(dec_trials),
            "median": statistics.median(dec_trials),
            "std": statistics.stdev(dec_trials),
            "p95": sorted(dec_trials)[int(0.95 * len(dec_trials))],
            "p99": sorted(dec_trials)[int(0.99 * len(dec_trials))]
        }
    }

    # 3. ML-KEM-768 (OpenSSL / cryptography)
    print("[3/5] Benchmarking ML-KEM-768 (FIPS 203 Category 3 / OpenSSL Backend)...")
    for _ in range(warmup_iters):
        sk = pyca_mlkem.MLKEM768PrivateKey.generate()
        pk = sk.public_key()
        ss, ct = pk.encapsulate()
        ss2 = sk.decapsulate(ct)

    kg_trials, enc_trials, dec_trials = [], [], []
    for t in range(trials_count):
        for _ in range(trial_iters):
            t0 = time.perf_counter_ns()
            sk = pyca_mlkem.MLKEM768PrivateKey.generate()
            t1 = time.perf_counter_ns()
            pk = sk.public_key()
            ss, ct = pk.encapsulate()
            t2 = time.perf_counter_ns()
            ss2 = sk.decapsulate(ct)
            t3 = time.perf_counter_ns()
            kg_trials.append((t1 - t0) / 1000.0)
            enc_trials.append((t2 - t1) / 1000.0)
            dec_trials.append((t3 - t2) / 1000.0)

    results["ML-KEM-768"] = {
        "KeyGen_us": {
            "mean": statistics.mean(kg_trials),
            "median": statistics.median(kg_trials),
            "std": statistics.stdev(kg_trials),
            "p95": sorted(kg_trials)[int(0.95 * len(kg_trials))],
            "p99": sorted(kg_trials)[int(0.99 * len(kg_trials))]
        },
        "Encaps_us": {
            "mean": statistics.mean(enc_trials),
            "median": statistics.median(enc_trials),
            "std": statistics.stdev(enc_trials),
            "p95": sorted(enc_trials)[int(0.95 * len(enc_trials))],
            "p99": sorted(enc_trials)[int(0.99 * len(enc_trials))]
        },
        "Decaps_us": {
            "mean": statistics.mean(dec_trials),
            "median": statistics.median(dec_trials),
            "std": statistics.stdev(dec_trials),
            "p95": sorted(dec_trials)[int(0.95 * len(dec_trials))],
            "p99": sorted(dec_trials)[int(0.99 * len(dec_trials))]
        }
    }

    # 4. ML-KEM-1024 (OpenSSL / cryptography)
    print("[4/5] Benchmarking ML-KEM-1024 (FIPS 203 Category 5 / OpenSSL Backend)...")
    for _ in range(warmup_iters):
        sk = pyca_mlkem.MLKEM1024PrivateKey.generate()
        pk = sk.public_key()
        ss, ct = pk.encapsulate()
        ss2 = sk.decapsulate(ct)

    kg_trials, enc_trials, dec_trials = [], [], []
    for t in range(trials_count):
        for _ in range(trial_iters):
            t0 = time.perf_counter_ns()
            sk = pyca_mlkem.MLKEM1024PrivateKey.generate()
            t1 = time.perf_counter_ns()
            pk = sk.public_key()
            ss, ct = pk.encapsulate()
            t2 = time.perf_counter_ns()
            ss2 = sk.decapsulate(ct)
            t3 = time.perf_counter_ns()
            kg_trials.append((t1 - t0) / 1000.0)
            enc_trials.append((t2 - t1) / 1000.0)
            dec_trials.append((t3 - t2) / 1000.0)

    results["ML-KEM-1024"] = {
        "KeyGen_us": {
            "mean": statistics.mean(kg_trials),
            "median": statistics.median(kg_trials),
            "std": statistics.stdev(kg_trials),
            "p95": sorted(kg_trials)[int(0.95 * len(kg_trials))],
            "p99": sorted(kg_trials)[int(0.99 * len(kg_trials))]
        },
        "Encaps_us": {
            "mean": statistics.mean(enc_trials),
            "median": statistics.median(enc_trials),
            "std": statistics.stdev(enc_trials),
            "p95": sorted(enc_trials)[int(0.95 * len(enc_trials))],
            "p99": sorted(enc_trials)[int(0.99 * len(enc_trials))]
        },
        "Decaps_us": {
            "mean": statistics.mean(dec_trials),
            "median": statistics.median(dec_trials),
            "std": statistics.stdev(dec_trials),
            "p95": sorted(dec_trials)[int(0.95 * len(dec_trials))],
            "p99": sorted(dec_trials)[int(0.99 * len(dec_trials))]
        }
    }

    # 5. Dual HKDF Combiner
    print("[5/5] Benchmarking Dual HKDF Combiner (HKDF-SHA-256)...")
    hkdf = DualHKDF()
    c_sec = b"\x01" * 32
    p_sec = b"\x02" * 32
    for _ in range(warmup_iters):
        prk, okm = hkdf.derive_hybrid_key(c_sec, p_sec)

    hkdf_trials = []
    for t in range(trials_count):
        for _ in range(trial_iters):
            t0 = time.perf_counter_ns()
            prk, okm = hkdf.derive_hybrid_key(c_sec, p_sec)
            t1 = time.perf_counter_ns()
            hkdf_trials.append((t1 - t0) / 1000.0)

    results["DualHKDF_Combine"] = {
        "Derive_us": {
            "mean": statistics.mean(hkdf_trials),
            "median": statistics.median(hkdf_trials),
            "std": statistics.stdev(hkdf_trials),
            "p95": sorted(hkdf_trials)[int(0.95 * len(hkdf_trials))],
            "p99": sorted(hkdf_trials)[int(0.99 * len(hkdf_trials))]
        }
    }

    return results


def benchmark_e2e_suites(
    warmup_iters: int = 100,
    trial_iters: int = 1000,
    trials_count: int = 5
) -> Dict[str, Any]:
    """
    Measures complete end-to-end handshake cryptographic execution across all 6 suites:
    KeyGen (Initiator) -> Encaps + Process (Responder) -> Decaps + Process (Initiator) -> Combined Key
    """
    print("\n" + "=" * 70)
    print("BENCHMARKING END-TO-END CIPHER SUITES")
    print(f"Config: {warmup_iters} warm-up, {trial_iters} iters/trial, {trials_count} trials")
    print("=" * 70)

    results = {}

    for suite in CipherSuiteType:
        suite_name = suite.value
        print(f"\nEvaluating suite: {suite_name}...")

        # Warmup
        initiator = HybridKEMInitiator(suite=suite)
        responder = HybridKEMResponder(suite=suite)
        for _ in range(warmup_iters):
            pk = initiator.generate_keypair()
            resp, k_server = responder.process_initiator_pk(pk)
            k_client = initiator.decapsulate_response(resp)

        all_keygen, all_encaps, all_decaps, all_total = [], [], [], []

        for t in range(trials_count):
            for _ in range(trial_iters):
                initiator = HybridKEMInitiator(suite=suite)
                responder = HybridKEMResponder(suite=suite)

                # Step 1: Initiator KeyGen
                t0 = time.perf_counter_ns()
                init_pk = initiator.generate_keypair()
                t1 = time.perf_counter_ns()
                kg_us = (t1 - t0) / 1000.0

                # Step 2: Responder Encapsulation + Secret Derivation
                t2 = time.perf_counter_ns()
                resp_payload, server_master = responder.process_initiator_pk(init_pk)
                t3 = time.perf_counter_ns()
                enc_us = (t3 - t2) / 1000.0

                # Step 3: Initiator Decapsulation + Secret Derivation
                t4 = time.perf_counter_ns()
                client_master = initiator.decapsulate_response(resp_payload)
                t5 = time.perf_counter_ns()
                dec_us = (t5 - t4) / 1000.0

                total_us = kg_us + enc_us + dec_us

                all_keygen.append(kg_us)
                all_encaps.append(enc_us)
                all_decaps.append(dec_us)
                all_total.append(total_us)

        results[suite_name] = {
            "security_level": CIPHER_TAXONOMY[suite]["security_level"],
            "pk_size_bytes": CIPHER_TAXONOMY[suite]["pk_size"],
            "ct_size_bytes": CIPHER_TAXONOMY[suite]["ct_size"],
            "total_payload_bytes": CIPHER_TAXONOMY[suite]["total_handshake_crypto_payload"],
            "KeyGen_us": {
                "mean": statistics.mean(all_keygen),
                "median": statistics.median(all_keygen),
                "std": statistics.stdev(all_keygen),
                "p95": sorted(all_keygen)[int(0.95 * len(all_keygen))],
                "p99": sorted(all_keygen)[int(0.99 * len(all_keygen))]
            },
            "Server_Encaps_Derive_us": {
                "mean": statistics.mean(all_encaps),
                "median": statistics.median(all_encaps),
                "std": statistics.stdev(all_encaps),
                "p95": sorted(all_encaps)[int(0.95 * len(all_encaps))],
                "p99": sorted(all_encaps)[int(0.99 * len(all_encaps))]
            },
            "Client_Decaps_Derive_us": {
                "mean": statistics.mean(all_decaps),
                "median": statistics.median(all_decaps),
                "std": statistics.stdev(all_decaps),
                "p95": sorted(all_decaps)[int(0.95 * len(all_decaps))],
                "p99": sorted(all_decaps)[int(0.99 * len(all_decaps))]
            },
            "Total_Crypto_Handshake_us": {
                "mean": statistics.mean(all_total),
                "median": statistics.median(all_total),
                "std": statistics.stdev(all_total),
                "p95": sorted(all_total)[int(0.95 * len(all_total))],
                "p99": sorted(all_total)[int(0.99 * len(all_total))]
            }
        }

    return results


def main():
    start_time = time.time()
    env = get_system_environment()
    print("Environment captured:")
    for k, v in env.items():
        print(f"  {k}: {v}")

    # Run with 100 warmup, 1000 iters/trial, 5 trials (total 5,000 measurements per primitive/suite)
    standalone_data = benchmark_standalone_primitives(warmup_iters=100, trial_iters=1000, trials_count=5)
    suite_data = benchmark_e2e_suites(warmup_iters=100, trial_iters=1000, trials_count=5)

    full_output = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "iterations_per_trial": 1000,
            "trials_count": 5,
            "warmup_iterations": 100,
            "total_samples_per_operation": 5000,
            "elapsed_seconds": round(time.time() - start_time, 2)
        },
        "environment": env,
        "standalone_primitives": standalone_data,
        "cipher_suites": suite_data
    }

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phase1_crypto_benchmark_results.json")
    with open(out_path, "w") as f:
        json.dump(full_output, f, indent=2)

    print("\n" + "=" * 70)
    print("BENCHMARK COMPLETE")
    print(f"Results written to: {out_path}")
    print(f"Total benchmark wall-clock time: {full_output['metadata']['elapsed_seconds']} s")
    print("=" * 70)

    # Print summary table
    print("\nSUMMARY TABLE (E2E Cryptographic Handshake Time):")
    print(f"{'Cipher Suite':<22} | {'PK (B)':<6} | {'CT (B)':<6} | {'KeyGen (us)':<12} | {'Encaps (us)':<12} | {'Decaps (us)':<12} | {'Total (us) Median ± Std':<24}")
    print("-" * 105)
    for s_name, data in suite_data.items():
        kg_med = data["KeyGen_us"]["median"]
        enc_med = data["Server_Encaps_Derive_us"]["median"]
        dec_med = data["Client_Decaps_Derive_us"]["median"]
        tot_med = data["Total_Crypto_Handshake_us"]["median"]
        tot_std = data["Total_Crypto_Handshake_us"]["std"]
        pk_b = data["pk_size_bytes"]
        ct_b = data["ct_size_bytes"]
        print(f"{s_name:<22} | {pk_b:<6} | {ct_b:<6} | {kg_med:<12.1f} | {enc_med:<12.1f} | {dec_med:<12.1f} | {tot_med:8.1f} ± {tot_std:<12.1f}")


if __name__ == "__main__":
    main()
