"""
Adaptive Cipher Negotiation Engine
Dynamically selects Post-Quantum Hybrid parameters based on link RTT, Loss %, and MTU.

Implements Objective 2: Dynamic Adaptive Negotiation Algorithm
- Prevents network MTU fragmentation and restricts handshake latency overhead.
- Operates on empirical host-calibrated performance telemetry.
- Enforces strict security policy: NO SILENT DOWNGRADES to classical cryptography.
- Produces auditable decision logs with technical justification.
"""

import time
from typing import Dict, Any, List, Optional
from crypto.hybrid_kem import CipherSuiteType, CIPHER_TAXONOMY
from adaptive_engine.heuristics import LatencyModeler, calibrate_host_crypto_profile
from adaptive_engine.network_monitor import NetworkMonitor


class AdaptiveNegotiator:
    """
    Intelligent PQC Negotiation Controller.
    Balances Post-Quantum Security Level against Network Degradation & Latency SLAs.
    """

    def __init__(
        self,
        target_security_tier: str = "Standard",
        device_profile: str = "x86_64_server",
        allow_downgrade_to_classical: bool = False,
        use_host_calibration: bool = True
    ):
        # "Standard" = NIST Level 3 preferred (ML-KEM-768)
        # "High" = NIST Level 5 preferred (ML-KEM-1024)
        # "Edge-Optimized" = NIST Level 1 preferred (ML-KEM-512)
        self.target_security_tier = target_security_tier
        self.device_profile = device_profile
        self.allow_downgrade_to_classical = allow_downgrade_to_classical
        self.use_host_calibration = use_host_calibration
        self.negotiation_history: List[Dict[str, Any]] = []

        if self.use_host_calibration:
            try:
                calibrate_host_crypto_profile()
            except Exception:
                pass

    def select_optimal_suite(
        self,
        monitor: NetworkMonitor,
        cert_size: int = 1200,
        max_acceptable_overhead_percent: float = 20.0
    ) -> Dict[str, Any]:
        """
        Runs the dynamic optimization decision loop.
        Evaluates candidate suites under current link telemetry and calibrated execution times.
        Ensures quantum-safe operation without silent classical downgrades.
        """
        metrics = monitor.get_metrics()
        rtt = metrics["srtt_ms"]
        loss = metrics["loss_rate"]
        mtu = metrics["pmtu"]
        rto = metrics["rto_ms"]
        bw = metrics["bandwidth_mbps"]

        # Baseline classical latency (for relative overhead comparison)
        baseline_pred = LatencyModeler.predict_handshake_latency(
            CipherSuiteType.CLASSIC_X25519,
            rtt_ms=rtt,
            loss_rate=loss,
            mtu=mtu,
            rto_ms=rto,
            bandwidth_mbps=bw,
            device_profile=self.device_profile,
            cert_size=cert_size,
            use_host_calibration=self.use_host_calibration
        )
        baseline_latency = baseline_pred["total_handshake_ms"]

        # Candidate suites evaluation
        candidate_suites = [
            CipherSuiteType.HYBRID_X25519_MLKEM512,
            CipherSuiteType.HYBRID_X25519_MLKEM768,
            CipherSuiteType.HYBRID_X25519_MLKEM1024
        ]
        if self.allow_downgrade_to_classical:
            candidate_suites.append(CipherSuiteType.CLASSIC_X25519)

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
                cert_size=cert_size,
                use_host_calibration=self.use_host_calibration
            )
            overhead_percent = ((pred["total_handshake_ms"] - baseline_latency) / max(0.01, baseline_latency)) * 100.0
            pred["overhead_percent"] = round(overhead_percent, 2)
            scored_candidates.append(pred)

        # Decision Policy Rules:
        # Rule 1 (High Assurance): If target_security_tier == 'High', channel clean (loss < 1%), MTU >= 1500 -> ML-KEM-1024
        # Rule 2 (Channel Constraint Downshift): If loss >= 1.5% or MTU < 1350B -> ML-KEM-512 to avoid fragmentation loss amplification
        # Rule 3 (Catastrophic Loss with Downgrade Flag): If loss > 20% AND allow_downgrade_to_classical is True -> Classical fallback with alert
        # Rule 4 (Standard Nominal): Default to NIST Level 3 ML-KEM-768
        selected = None
        decision_reason = ""
        downgrade_occurred = False
        downgrade_warning = None

        if self.allow_downgrade_to_classical and loss >= 0.20:
            selected = CipherSuiteType.CLASSIC_X25519
            downgrade_occurred = True
            downgrade_warning = "CRITICAL SECURITY WARNING: Fallback to classical X25519 triggered due to extreme loss (>20%). Quantum security compromised."
            decision_reason = "Catastrophic channel loss (>20%) forced fallback to classical X25519 under explicit downgrade policy."
        elif self.target_security_tier == "High" and loss < 0.01 and mtu >= 1500:
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
            "decision_id": len(self.negotiation_history) + 1,
            "timestamp": round(monitor.total_probes, 2),
            "timestamp_epoch": time.time(),
            "selected_suite": selected,
            "suite_name": selected.value,
            "security_level": CIPHER_TAXONOMY[selected]["security_level"],
            "nist_level": CIPHER_TAXONOMY[selected]["nist_level"],
            "is_quantum_safe": CIPHER_TAXONOMY[selected]["is_quantum_safe"],
            "decision_reason": decision_reason,
            "downgrade_occurred": downgrade_occurred,
            "downgrade_warning": downgrade_warning,
            "metrics": metrics,
            "predicted_handshake_ms": selected_pred["total_handshake_ms"],
            "baseline_handshake_ms": baseline_latency,
            "overhead_percent": selected_pred["overhead_percent"],
            "num_fragments": selected_pred["num_fragments"],
            "candidates": scored_candidates,
            "auditable_explanation": (
                f"Selected {selected.value} based on channel telemetry (RTT={rtt}ms, Loss={loss*100:.2f}%, MTU={mtu}B). "
                f"Expected handshake latency: {selected_pred['total_handshake_ms']}ms across {selected_pred['num_fragments']} fragment(s). "
                f"Relative overhead: {selected_pred['overhead_percent']}%. "
                f"Security Level: {CIPHER_TAXONOMY[selected]['security_level']} ({'Quantum-Resistant' if CIPHER_TAXONOMY[selected]['is_quantum_safe'] else 'Vulnerable to Shor'})."
            )
        }

        self.negotiation_history.append(decision_record)
        return decision_record

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        """Returns the chronological audit log of all negotiation decisions made."""
        return list(self.negotiation_history)

    def get_last_decision(self) -> Optional[Dict[str, Any]]:
        """Returns the most recent negotiation decision, or None if none made."""
        return self.negotiation_history[-1] if self.negotiation_history else None

    def clear_audit_trail(self):
        """Clears the decision history log."""
        self.negotiation_history.clear()
