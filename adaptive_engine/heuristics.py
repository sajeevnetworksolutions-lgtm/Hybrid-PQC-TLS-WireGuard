"""
Mathematical Heuristics & Handshake Latency Modeling
Implements Section 7, Eq. 3 of Dissertation Synopsis:
  T_handshake = 2 * RTT + T_crypto + ceil((S_cert + S_pqc_pk) / MTU) * (T_trans + P_loss * RTO)
"""

import math
from typing import Dict, Any, Tuple
from crypto.hybrid_kem import CipherSuiteType, CIPHER_TAXONOMY


# Average certificate chain size in modern TLS 1.3 (e.g. ECDSA / Dilithium certs)
DEFAULT_CERT_SIZE = 1200  # bytes


# Baseline crypto execution times (microseconds) across architectures
BENCHMARK_CRYPTO_PROFILES = {
    "x86_64_server": {
        CipherSuiteType.CLASSIC_X25519: 80.0,            # 0.08 ms
        CipherSuiteType.HYBRID_X25519_MLKEM512: 190.0,   # 0.19 ms
        CipherSuiteType.HYBRID_X25519_MLKEM768: 240.0,   # 0.24 ms
        CipherSuiteType.HYBRID_X25519_MLKEM1024: 360.0,  # 0.36 ms
        CipherSuiteType.PURE_MLKEM768: 160.0,
        CipherSuiteType.PURE_MLKEM1024: 280.0
    },
    "arm_cortex_edge": {
        CipherSuiteType.CLASSIC_X25519: 850.0,           # 0.85 ms
        CipherSuiteType.HYBRID_X25519_MLKEM512: 2400.0,  # 2.40 ms
        CipherSuiteType.HYBRID_X25519_MLKEM768: 3200.0,  # 3.20 ms
        CipherSuiteType.HYBRID_X25519_MLKEM1024: 4800.0, # 4.80 ms
        CipherSuiteType.PURE_MLKEM768: 2350.0,
        CipherSuiteType.PURE_MLKEM1024: 3950.0
    }
}


class LatencyModeler:
    """
    Theoretical & Empirical Handshake Latency Modeler.
    Calculates expected Time To First Byte (TTFB), fragmentation overhead,
    and TCP Retransmission penalties.
    """

    @classmethod
    def calculate_fragments(cls, suite: CipherSuiteType, mtu: int, cert_size: int = DEFAULT_CERT_SIZE) -> int:
        """
        Calculates ceil((S_cert + S_pqc_pk) / MTU).
        Effective MSS = MTU - 40 bytes (IP + TCP/UDP framing).
        """
        mss = max(100, mtu - 40)
        pk_size = CIPHER_TAXONOMY[suite]["pk_size"]
        total_payload = cert_size + pk_size
        return math.ceil(total_payload / mss)

    @classmethod
    def predict_handshake_latency(
        cls,
        suite: CipherSuiteType,
        rtt_ms: float,
        loss_rate: float,
        mtu: int = 1500,
        rto_ms: float = 200.0,
        bandwidth_mbps: float = 100.0,
        device_profile: str = "x86_64_server",
        cert_size: int = DEFAULT_CERT_SIZE
    ) -> Dict[str, Any]:
        """
        Computes Eq. 3:
          T_handshake = 2 * RTT + T_crypto + N_frag * (T_trans + P_loss * RTO)
        """
        t_crypto_ms = BENCHMARK_CRYPTO_PROFILES.get(device_profile, BENCHMARK_CRYPTO_PROFILES["x86_64_server"])[suite] / 1000.0
        n_frag = cls.calculate_fragments(suite, mtu, cert_size)

        # Transmission time of total payload (ms)
        pk_size = CIPHER_TAXONOMY[suite]["pk_size"]
        ct_size = CIPHER_TAXONOMY[suite]["ct_size"]
        total_bytes = cert_size + pk_size + ct_size
        t_trans_ms = (total_bytes * 8.0) / (bandwidth_mbps * 1000.0)

        # Expected retransmission penalty for multi-packet fragmentation:
        # Multi-packet drop probability P_any_drop = 1 - (1 - P_loss)^N_frag
        p_any_drop = 1.0 - math.pow(max(0.0, 1.0 - loss_rate), n_frag)
        retransmission_penalty_ms = p_any_drop * rto_ms

        total_handshake_ms = (2.0 * rtt_ms) + t_crypto_ms + (n_frag * t_trans_ms) + retransmission_penalty_ms

        return {
            "suite": suite.value,
            "security_level": CIPHER_TAXONOMY[suite]["security_level"],
            "is_quantum_safe": CIPHER_TAXONOMY[suite]["is_quantum_safe"],
            "rtt_ms": rtt_ms,
            "loss_rate": loss_rate,
            "mtu": mtu,
            "num_fragments": n_frag,
            "t_crypto_ms": round(t_crypto_ms, 3),
            "t_trans_ms": round(t_trans_ms, 3),
            "retransmission_penalty_ms": round(retransmission_penalty_ms, 2),
            "total_handshake_ms": round(total_handshake_ms, 2)
        }
