"""
Throughput Benchmarking Module
Measures concurrent handshake capacity (connections / second) across cipher suites.
"""

import time
import concurrent.futures
from typing import Dict, Any, List
from crypto.hybrid_kem import (
    HybridKEMInitiator,
    HybridKEMResponder,
    CipherSuiteType
)


def _single_handshake_worker(suite: CipherSuiteType) -> bool:
    initiator = HybridKEMInitiator(suite=suite)
    responder = HybridKEMResponder(suite=suite)
    pk = initiator.generate_keypair()
    resp_payload, s_key = responder.process_initiator_pk(pk)
    c_key = initiator.decapsulate_response(resp_payload)
    return s_key == c_key


def benchmark_throughput_concurrency(
    concurrency_levels: List[int] = [1, 5, 10, 25, 50],
    duration_per_level_sec: float = 1.0
) -> Dict[str, Any]:
    """
    Measures connections/second across concurrency thread pools.
    """
    results = {
        "concurrency_levels": concurrency_levels,
        "suites": {}
    }

    test_suites = [
        CipherSuiteType.CLASSIC_X25519,
        CipherSuiteType.HYBRID_X25519_MLKEM512,
        CipherSuiteType.HYBRID_X25519_MLKEM768,
        CipherSuiteType.HYBRID_X25519_MLKEM1024,
        CipherSuiteType.PURE_MLKEM768
    ]

    for suite in test_suites:
        results["suites"][suite.value] = []
        for workers in concurrency_levels:
            total_handshakes = 0
            start_time = time.perf_counter()
            deadline = start_time + duration_per_level_sec

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = []
                while time.perf_counter() < deadline:
                    # Submit batch
                    for _ in range(workers * 2):
                        futures.append(executor.submit(_single_handshake_worker, suite))
                    
                    # Drain completed
                    done, _ = concurrent.futures.wait(futures, timeout=0.1)
                    total_handshakes += len(done)
                    futures = [f for f in futures if not f.done()]

            elapsed = time.perf_counter() - start_time
            throughput_cps = total_handshakes / elapsed
            results["suites"][suite.value].append(round(throughput_cps, 1))

    return results
