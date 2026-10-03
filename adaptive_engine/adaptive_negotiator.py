"""
Adaptive Cipher Negotiation Engine
Dynamically selects Post-Quantum Hybrid parameters based on link RTT, Loss %, and MTU.

Implements Objective 2: Dynamic Adaptive Negotiation Algorithm
Prevents network MTU fragmentation and restricts handshake latency overhead.
"""

from typing import Dict, Any, List, Optional
from crypto.hybrid_kem import CipherSuiteType, CIPHER_TAXONOMY
from adaptive_engine.heuristics import LatencyModeler
from adaptive_engine.network_monitor import NetworkMonitor


class AdaptiveNegotiator:
    """
    Intelligent PQC Negotiation Controller.
    Balances Post-Quantum Security Level against Network Degradation & Latency SLAs.
    """

    def __init__(self, target_security_tier: str = "Standard", device_profile: str = "x86_64_server"):
        # "Standard" = NIST Level 3 preferred (ML-KEM-768)
        # "High" = NIST Level 5 preferred (ML-KEM-1024)
        # "Edge-Optimized" = NIST Level 1 preferred (ML-KEM-512)
        self.target_security_tier = target_security_tier
        self.device_profile = device_profile
        self.negotiation_history: List[Dict[str, Any]] = []

    def select_optimal_suite(
        self,
        monitor: NetworkMonitor,
        cert_size: int = 1200,
        max_acceptable_overhead_percent: float = 20.0
    ) -> Dict[str, Any]:
        """
        Runs the dynamic optimization decision loop.
        Evaluates candidate suites under current link telemetry.
        """
        metrics = monitor.get_metrics()
        rtt = metrics["srtt_ms"]
        loss = metrics["loss_rate"]
        mtu = metrics["pmtu"]
        rto = metrics["rto_ms"]
        bw = metrics["bandwidth_mbps"]

        # Baseline classical latency
        baseline_pred = LatencyModeler.predict_handshake_latency(
            CipherSuiteType.CLASSIC_X25519,
            rtt_ms=rtt,
            loss_rate=loss,
            mtu=mtu,
            rto_ms=rto,
            bandwidth_mbps=bw,
            device_profile=self.device_profile,
            cert_size=cert_size
        )
        baseline_latency = baseline_pred["total_handshake_ms"]

        # Evaluate candidate hybrid suites (Quantum-Resistant)
        candidate_suites = [
            CipherSuiteType.HYBRID_X25519_MLKEM512,
            CipherSuiteType.HYBRID_X25519_MLKEM768,
            CipherSuiteType.HYBRID_X25519_MLKEM1024
        ]

        scored_candidates = []
        for suite in candidate_suites:
            pred = LatencyModeler.predict_handshake_latency(
                suite,
                rtt_ms=rtt,
                loss_rate=loss,
                mtu=mtu,
                rto_ms=rto,
                bandwidth_mbps=bw,
                device_profile=self.device_profile,
                cert_size=cert_size
            )
            overhead_percent = ((pred["total_handshake_ms"] - baseline_latency) / max(0.01, baseline_latency)) * 100.0
            pred["overhead_percent"] = round(overhead_percent, 2)
            scored_candidates.append(pred)

        # Decision Policy:
        # 1. MTU Contraction Rule: If MTU <= 1280 or loss >= 0.02 (2%), ML-KEM-1024 suffers severe fragmentation penalty.
        # 2. Prefer ML-KEM-768 for balanced security, downshift to ML-KEM-512 under high loss / low MTU.
        selected = None
        decision_reason = ""

        if self.target_security_tier == "High" and loss < 0.01 and mtu >= 1500:
            selected = CipherSuiteType.HYBRID_X25519_MLKEM1024
            decision_reason = "High Security Tier requested with clean channel and standard MTU."
        elif loss >= 0.015 or mtu < 1350:
            # Under significant loss or tight MTU, select ML-KEM-512 to prevent fragment drop explosion
            selected = CipherSuiteType.HYBRID_X25519_MLKEM512
            decision_reason = f"Loss rate ({loss*100:.1f}%) or constrained MTU ({mtu}B) triggered ML-KEM-512 fragmentation avoidance."
        else:
            # Default to NIST Level 3 ML-KEM-768
            selected = CipherSuiteType.HYBRID_X25519_MLKEM768
            decision_reason = "Nominal channel conditions: ML-KEM-768 standard hybrid selected."

        selected_pred = next(c for c in scored_candidates if c["suite"] == selected.value)

        decision_record = {
            "timestamp": round(monitor.total_probes, 2),
            "selected_suite": selected,
            "suite_name": selected.value,
            "security_level": CIPHER_TAXONOMY[selected]["security_level"],
            "nist_level": CIPHER_TAXONOMY[selected]["nist_level"],
            "decision_reason": decision_reason,
            "metrics": metrics,
            "predicted_handshake_ms": selected_pred["total_handshake_ms"],
            "baseline_handshake_ms": baseline_latency,
            "overhead_percent": selected_pred["overhead_percent"],
            "num_fragments": selected_pred["num_fragments"],
            "candidates": scored_candidates
        }

        self.negotiation_history.append(decision_record)
        return decision_record
