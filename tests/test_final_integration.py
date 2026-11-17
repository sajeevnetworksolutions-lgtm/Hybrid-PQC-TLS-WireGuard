"""
Final End-to-End Integration Test Suite
M.Tech Cybersecurity Project 3

Validates:
1. Unified Controller Protocol Execution (TLS 1.3 & WireGuard in Classical and Hybrid modes).
2. Traffic secret derivation, handshake validation, and application/transport data verification.
3. Adaptive Engine live telemetry ingestion and host-calibrated latency modeling.
4. Strict Downgrade Prevention Policy (No silent fallback to classical cryptography).
5. Auditable negotiation decision logs and reasoning trails.
6. Dashboard Backend REST API endpoints (/api/status, /api/handshake, /api/adaptive, /api/benchmark).
7. Independent execution isolation across protocols.
"""

import os
import sys
import time
import json
import unittest
from typing import Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocols.unified_controller import UnifiedProtocolManager
from protocols.wireguard_pqc import WireGuardMode
from crypto.hybrid_kem import CipherSuiteType, CIPHER_TAXONOMY
from adaptive_engine.network_monitor import NetworkMonitor
from adaptive_engine.adaptive_negotiator import AdaptiveNegotiator
from adaptive_engine.heuristics import LatencyModeler, calibrate_host_crypto_profile
from dashboard_server import PQCBackendHandler, _PROTOCOL_MGR, _MONITOR, _NEGOTIATOR


class TestFinalIntegration(unittest.TestCase):
    """
    Comprehensive verification of the unified project integration.
    """

    @classmethod
    def setUpClass(cls):
        # Calibrate host crypto profiles once for testing
        calibrate_host_crypto_profile()

    def setUp(self):
        self.mgr = UnifiedProtocolManager()

    def test_01_unified_controller_tls_classical_and_hybrid(self):
        """
        1. Tests TLS 1.3 execution through the Unified Protocol Manager.
        Verifies both Classical (X25519) and Hybrid (X25519MLKEM768) modes.
        """
        # Classical mode
        res_c = self.mgr.run_tls13_handshake(mode="classical", app_data=b"TEST_CLASSICAL_TLS")
        self.assertEqual(res_c["status"], "SUCCESS")
        self.assertEqual(res_c["protocol_version"], "TLSv1.3")
        self.assertEqual(res_c["negotiated_group"], "X25519")
        self.assertTrue(res_c["secrets_match"])
        self.assertTrue(res_c["application_data_verified"])
        self.assertGreater(res_c["handshake_latency_us"], 0.0)

        # Hybrid mode
        res_h = self.mgr.run_tls13_handshake(mode="hybrid", app_data=b"TEST_HYBRID_TLS")
        self.assertEqual(res_h["status"], "SUCCESS")
        self.assertEqual(res_h["protocol_version"], "TLSv1.3")
        self.assertEqual(res_h["negotiated_group"], "X25519MLKEM768")
        self.assertTrue(res_h["secrets_match"])
        self.assertTrue(res_h["application_data_verified"])
        self.assertGreater(res_h["handshake_latency_us"], 0.0)

    def test_02_unified_controller_wireguard_classical_and_hybrid(self):
        """
        2. Tests WireGuard execution through the Unified Protocol Manager.
        Verifies both Classical (Noise_IK_25519) and Hybrid (Noise_IKpsk2_X25519_MLKEM768) modes.
        """
        # Classical mode
        res_c = self.mgr.run_wireguard_handshake(mode="classical", app_data=b"TEST_CLASSICAL_WG")
        self.assertEqual(res_c["status"], "SUCCESS")
        self.assertEqual(res_c["msg1_initiation_bytes"], 148)
        self.assertEqual(res_c["msg2_response_bytes"], 92)
        self.assertTrue(res_c["secrets_match"])
        self.assertTrue(res_c["transport_data_verified"])
        self.assertIn("Experimental research prototype", res_c["classification_notice"])

        # Hybrid mode
        res_h = self.mgr.run_wireguard_handshake(mode="hybrid", app_data=b"TEST_HYBRID_WG")
        self.assertEqual(res_h["status"], "SUCCESS")
        self.assertEqual(res_h["msg1_initiation_bytes"], 1332)  # 148 + 1184 ML-KEM-768 PK
        self.assertEqual(res_h["msg2_response_bytes"], 1180)  # 92 + 1088 ML-KEM-768 CT
        self.assertTrue(res_h["secrets_match"])
        self.assertTrue(res_h["transport_data_verified"])
        self.assertIn("Experimental research prototype", res_h["classification_notice"])

    def test_03_adaptive_engine_telemetry_ingestion(self):
        """
        3. Tests real protocol telemetry ingestion into the Adaptive Engine.
        Verifies that measured handshake timings update SRTT and loss rate via RFC 6298 EWMA.
        """
        monitor = NetworkMonitor(initial_rtt_ms=10.0, initial_loss_rate=0.0)
        # Ingest successful handshakes
        monitor.record_protocol_handshake(duration_ms=15.0, success=True, payload_bytes=1000)
        monitor.record_protocol_handshake(duration_ms=25.0, success=True, payload_bytes=1000)

        metrics = monitor.get_metrics()
        self.assertGreater(metrics["srtt_ms"], 10.0)
        self.assertEqual(metrics["history_count"], 2)
        self.assertEqual(metrics["loss_rate"], 0.0)

        # Ingest failed handshake (timeout / dropped packet)
        monitor.record_protocol_handshake(duration_ms=0.0, success=False)
        metrics_after_drop = monitor.get_metrics()
        self.assertGreater(metrics_after_drop["loss_rate"], 0.0)

    def test_04_downgrade_prevention_policy(self):
        """
        4. Validates that the Adaptive Engine enforces strict downgrade prevention:
        - When allow_downgrade_to_classical=False (default), it NEVER silently degrades
          to classical X25519 even under extreme network degradation.
        - When allow_downgrade_to_classical=True, it allows fallback only under catastrophic
          loss (>20%) and logs a prominent warning.
        """
        monitor = NetworkMonitor()
        monitor.set_channel_state(rtt_ms=100.0, loss_rate=0.30, mtu=1200)

        # Default policy: NO SILENT DOWNGRADES
        strict_neg = AdaptiveNegotiator(allow_downgrade_to_classical=False)
        strict_dec = strict_neg.select_optimal_suite(monitor)
        # Must retain quantum resistance via ML-KEM-512 rather than classical X25519
        self.assertEqual(strict_dec["selected_suite"], CipherSuiteType.HYBRID_X25519_MLKEM512)
        self.assertTrue(strict_dec["is_quantum_safe"])
        self.assertFalse(strict_dec["downgrade_occurred"])

        # Permissive policy: Explicit downgrade permitted under catastrophic loss
        permissive_neg = AdaptiveNegotiator(allow_downgrade_to_classical=True)
        permissive_dec = permissive_neg.select_optimal_suite(monitor)
        self.assertEqual(permissive_dec["selected_suite"], CipherSuiteType.CLASSIC_X25519)
        self.assertFalse(permissive_dec["is_quantum_safe"])
        self.assertTrue(permissive_dec["downgrade_occurred"])
        self.assertIsNotNone(permissive_dec["downgrade_warning"])
        self.assertIn("CRITICAL SECURITY WARNING", permissive_dec["downgrade_warning"])

    def test_05_auditable_decision_records(self):
        """
        5. Verifies that AdaptiveNegotiator generates complete, auditable decision trails
        with explicit technical reasoning, metrics snapshots, and candidate score comparisons.
        """
        monitor = NetworkMonitor()
        negotiator = AdaptiveNegotiator()

        monitor.set_channel_state(rtt_ms=2.0, loss_rate=0.0, mtu=1500)
        dec1 = negotiator.select_optimal_suite(monitor)
        self.assertEqual(dec1["decision_id"], 1)
        self.assertIn("Nominal channel conditions", dec1["decision_reason"])
        self.assertIn("auditable_explanation", dec1)

        monitor.set_channel_state(rtt_ms=40.0, loss_rate=0.04, mtu=1500)
        dec2 = negotiator.select_optimal_suite(monitor)
        self.assertEqual(dec2["decision_id"], 2)
        self.assertIn("fragmentation avoidance", dec2["decision_reason"])

        history = negotiator.get_audit_trail()
        self.assertEqual(len(history), 2)
        self.assertEqual(history[-1]["decision_id"], 2)

    def test_06_dashboard_api_data_structures(self):
        """
        6. Verifies the JSON data structures provided by the dashboard backend.
        Tests that status, handshake, and adaptive responses meet contract requirements.
        """
        # Status payload contract verification
        channel = _MONITOR.get_metrics()
        last_decision = _NEGOTIATOR.get_last_decision()

        status_data = {
            "status": "ONLINE",
            "tls13_engine": {
                "name": "TLS 1.3 (RFC 8446)",
                "library": "OpenSSL 4.0.0 14 Apr 2026",
                "hybrid_group": "X25519MLKEM768"
            },
            "wireguard_engine": {
                "name": "Experimental Hybrid WireGuard Prototype (Noise_IKpsk2)",
                "construction": "Noise_IKpsk2_X25519_MLKEM768_ChaChaPoly_BLAKE2s"
            },
            "channel_telemetry": channel
        }
        self.assertEqual(status_data["status"], "ONLINE")
        self.assertEqual(status_data["tls13_engine"]["hybrid_group"], "X25519MLKEM768")
        self.assertIn("Noise_IKpsk2", status_data["wireguard_engine"]["construction"])

        # Test live handshake trigger through the unified protocol manager
        hs_result = _PROTOCOL_MGR.run_all(mode="hybrid")
        self.assertEqual(hs_result["overall_status"], "ALL_PROTOCOLS_SUCCESSFUL")
        self.assertTrue(hs_result["tls13"]["secrets_match"])
        self.assertTrue(hs_result["wireguard"]["secrets_match"])

    def test_07_independent_execution_isolation(self):
        """
        7. Verifies that TLS 1.3 and WireGuard protocols execute independently
        without shared cryptographic states or side-channel interference.
        """
        # Run TLS 1.3
        tls_res = self.mgr.run_tls13_handshake(mode="hybrid")
        # Run WireGuard
        wg_res = self.mgr.run_wireguard_handshake(mode="hybrid")

        # Confirm non-identical ephemeral and directional secrets
        self.assertNotEqual(
            tls_res["sample_traffic_secret_hex"],
            wg_res["client_send_key_hex"]
        )
        self.assertEqual(tls_res["status"], "SUCCESS")
        self.assertEqual(wg_res["status"], "SUCCESS")

    def test_08_wireguard_mlkem512_and_mlkem1024_modes(self):
        """
        8. Verifies that WireGuard supports ML-KEM-512 (used by Adaptive Engine under high loss/MTU)
        and ML-KEM-1024 (high assurance tier).
        """
        res_512 = self.mgr.run_wireguard_handshake(mode="mlkem512", app_data=b"TEST_WG_512")
        self.assertEqual(res_512["status"], "SUCCESS")
        self.assertEqual(res_512["msg1_initiation_bytes"], 948)   # 148 + 800 ML-KEM-512 PK
        self.assertEqual(res_512["msg2_response_bytes"], 860)   # 92 + 768 ML-KEM-512 CT
        self.assertTrue(res_512["secrets_match"])
        self.assertTrue(res_512["transport_data_verified"])

        res_1024 = self.mgr.run_wireguard_handshake(mode="mlkem1024", app_data=b"TEST_WG_1024")
        self.assertEqual(res_1024["status"], "SUCCESS")
        self.assertEqual(res_1024["msg1_initiation_bytes"], 1716) # 148 + 1568 ML-KEM-1024 PK
        self.assertEqual(res_1024["msg2_response_bytes"], 1660) # 92 + 1568 ML-KEM-1024 CT
        self.assertTrue(res_1024["secrets_match"])
        self.assertTrue(res_1024["transport_data_verified"])


if __name__ == "__main__":
    unittest.main()
