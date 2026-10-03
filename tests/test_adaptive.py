"""
Unit tests for Adaptive Negotiation Engine and Heuristics
"""

import unittest
from adaptive_engine.network_monitor import NetworkMonitor
from adaptive_engine.heuristics import LatencyModeler
from adaptive_engine.adaptive_negotiator import AdaptiveNegotiator
from crypto.hybrid_kem import CipherSuiteType


class TestAdaptiveEngine(unittest.TestCase):

    def test_network_monitor_ewma(self):
        monitor = NetworkMonitor(initial_rtt_ms=20.0, initial_mtu=1500)
        # Add RTT spikes
        monitor.update_rtt_sample(25.0)
        monitor.update_rtt_sample(30.0)
        metrics = monitor.get_metrics()
        self.assertGreater(metrics["srtt_ms"], 20.0)
        self.assertGreater(metrics["rto_ms"], metrics["srtt_ms"])

    def test_latency_modeler_fragment_calculation(self):
        # Classical fits in 1 fragment with 1200B cert
        frag_ec = LatencyModeler.calculate_fragments(CipherSuiteType.CLASSIC_X25519, mtu=1500, cert_size=1200)
        self.assertEqual(frag_ec, 1)

        # ML-KEM-1024 (1200 + 1600 = 2800B) requires >= 2 fragments
        frag_1024 = LatencyModeler.calculate_fragments(CipherSuiteType.HYBRID_X25519_MLKEM1024, mtu=1500, cert_size=1200)
        self.assertEqual(frag_1024, 2)

    def test_adaptive_negotiation_clean_vs_lossy(self):
        monitor = NetworkMonitor()
        negotiator = AdaptiveNegotiator(target_security_tier="Standard")

        # 1. Clean LAN channel (Loss = 0.0%)
        monitor.set_channel_state(rtt_ms=2.0, loss_rate=0.0, mtu=1500)
        res_clean = negotiator.select_optimal_suite(monitor)
        self.assertEqual(res_clean["selected_suite"], CipherSuiteType.HYBRID_X25519_MLKEM768)

        # 2. Lossy WAN link (Loss = 3.0%) -> Adaptive engine must downshift to ML-KEM-512 to avoid multi-packet drops
        monitor.set_channel_state(rtt_ms=45.0, loss_rate=0.03, mtu=1500)
        res_lossy = negotiator.select_optimal_suite(monitor)
        self.assertEqual(res_lossy["selected_suite"], CipherSuiteType.HYBRID_X25519_MLKEM512)

        # 3. Constrained MTU (e.g. 1280B IPv6/Cellular)
        monitor.set_channel_state(rtt_ms=20.0, loss_rate=0.005, mtu=1280)
        res_mtu = negotiator.select_optimal_suite(monitor)
        self.assertEqual(res_mtu["selected_suite"], CipherSuiteType.HYBRID_X25519_MLKEM512)


if __name__ == "__main__":
    unittest.main()
