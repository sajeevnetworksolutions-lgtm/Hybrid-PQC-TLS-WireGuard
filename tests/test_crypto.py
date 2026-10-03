"""
Unit tests for Cryptographic Engine and Dual HKDF
"""

import unittest
from crypto.hybrid_kem import (
    HybridKEMInitiator,
    HybridKEMResponder,
    CipherSuiteType,
    CIPHER_TAXONOMY
)
from crypto.dual_hkdf import DualHKDF
from crypto.packet_framing import PacketFramer, FragmentReassembler


class TestCryptoPipeline(unittest.TestCase):

    def test_dual_hkdf_determinism(self):
        hkdf = DualHKDF()
        ec_secret = b"\x01" * 32
        pqc_secret = b"\x02" * 32
        prk1, key1 = hkdf.derive_hybrid_key(ec_secret, pqc_secret, info=b"test-info")
        prk2, key2 = hkdf.derive_hybrid_key(ec_secret, pqc_secret, info=b"test-info")
        self.assertEqual(prk1, prk2)
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)

    def test_all_cipher_suites_handshake(self):
        for suite in CipherSuiteType:
            with self.subTest(suite=suite.value):
                initiator = HybridKEMInitiator(suite=suite)
                responder = HybridKEMResponder(suite=suite)

                # Client generates public key
                init_pk = initiator.generate_keypair()
                self.assertGreater(len(init_pk), 0)

                # Server processes client public key and encapsulates
                resp_payload, server_master_key = responder.process_initiator_pk(init_pk)
                self.assertGreater(len(resp_payload), 0)
                self.assertEqual(len(server_master_key), 32)

                # Client decapsulates server response
                client_master_key = initiator.decapsulate_response(resp_payload)
                self.assertEqual(len(client_master_key), 32)

                # Verification: Dual-derived secrets must match exactly
                self.assertEqual(client_master_key, server_master_key)

    def test_packet_framing_and_reassembly(self):
        payload = b"X" * 3500  # Large payload > 2x MTU
        for mtu in [576, 1280, 1500]:
            packets = PacketFramer.fragment_payload(msg_type=1, seq_num=42, payload=payload, mtu=mtu)
            self.assertGreater(len(packets), 1)

            # Ensure every single packet fits inside MTU
            for pkt in packets:
                self.assertLessEqual(len(pkt) + PacketFramer.IP_TCP_OVERHEAD, mtu + 1)

            # Reassemble packets
            reassembler = FragmentReassembler()
            reconstructed = None
            for pkt in packets:
                reconstructed = reassembler.add_packet(pkt)

            self.assertIsNotNone(reconstructed)
            msg_type, seq_num, full_body = reconstructed
            self.assertEqual(msg_type, 1)
            self.assertEqual(seq_num, 42)
            self.assertEqual(full_body, payload)


if __name__ == "__main__":
    unittest.main()
