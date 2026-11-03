"""
Unit tests for TLS 1.3 PQC Tunnel and WireGuard PQC Proxy
"""

import unittest
import asyncio
import os
from protocols.tls13_pqc_tunnel import TLS13PQCClient, TLS13PQCServer
from protocols.wireguard_pqc_proxy import WireGuardPQCProxy
from crypto.hybrid_kem import CipherSuiteType, HybridKEMInitiator, HybridKEMResponder
from crypto.packet_framing import PacketFramer, FragmentReassembler
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class TestProtocols(unittest.TestCase):

    def test_wireguard_pqc_handshake(self):
        peer_a = WireGuardPQCProxy("PeerA_Client", suite=CipherSuiteType.HYBRID_X25519_MLKEM768)
        peer_b = WireGuardPQCProxy("PeerB_Server", suite=CipherSuiteType.HYBRID_X25519_MLKEM768)

        # 1. Peer A creates Initiation Message
        msg1, _ = peer_a.initiate_wireguard_handshake(peer_b.static_pub_ec)
        self.assertGreater(len(msg1), 1000)

        # 2. Peer B creates Response Message
        msg2, key_b = peer_b.respond_wireguard_handshake(msg1, peer_a.static_pub_ec)
        self.assertGreater(len(msg2), 1000)
        self.assertEqual(len(key_b), 32)

        # 3. Peer A processes Response
        key_a = peer_a.complete_wireguard_handshake(msg2)
        self.assertEqual(key_a, key_b)

    def test_tls13_pqc_protocol_state_machine(self):
        """
        Tests the end-to-end TLS 1.3 PQC protocol exchange, framing,
        fragmentation, dual HKDF derivation, and AEAD verification.
        """
        suite = CipherSuiteType.HYBRID_X25519_MLKEM768
        client = TLS13PQCClient(suite=suite, mtu=1500)
        session_id = os.urandom(16)

        # 1. ClientHello generation
        client_pk = client.initiator.generate_keypair()
        suite_name_bytes = suite.value.encode('utf-8')
        client_hello_payload = bytes([len(suite_name_bytes)]) + suite_name_bytes + session_id + client_pk

        # Packetize ClientHello
        client_pkts = PacketFramer.fragment_payload(msg_type=1, seq_num=0, payload=client_hello_payload, mtu=1500)
        self.assertGreaterEqual(len(client_pkts), 1)

        # 2. Server reassembly & processing
        server_reasm = FragmentReassembler()
        server_received = None
        for pkt in client_pkts:
            res = server_reasm.add_packet(pkt)
            if res:
                _, _, server_received = res
        self.assertEqual(server_received, client_hello_payload)

        # Server responds
        s_len = server_received[0]
        s_name = server_received[1:1 + s_len].decode('utf-8')
        s_id = server_received[1 + s_len:1 + suite.value.find('+') if False else 1 + s_len + 16]
        c_pk = server_received[1 + s_len + 16:]

        responder = HybridKEMResponder(suite=CipherSuiteType(s_name))
        resp_payload, server_master_key = responder.process_initiator_pk(c_pk, salt=s_id)
        self.assertEqual(len(server_master_key), 32)

        # Packetize ServerHello
        server_pkts = PacketFramer.fragment_payload(msg_type=2, seq_num=0, payload=resp_payload, mtu=1500)

        # 3. Client reassembly & decapsulation
        client_reasm = FragmentReassembler()
        client_received = None
        for pkt in server_pkts:
            res = client_reasm.add_packet(pkt)
            if res:
                _, _, client_received = res
        self.assertEqual(client_received, resp_payload)

        client_master_key = client.initiator.decapsulate_response(client_received, salt=session_id)
        self.assertEqual(client_master_key, server_master_key)

        # 4. AEAD Finished Record Verification
        keys = client.initiator.dual_hkdf.derive_tunnel_keys(client_master_key, session_id=session_id)
        client_aead = AESGCM(keys["client_write_key"])
        nonce = os.urandom(12)
        ciphertext = client_aead.encrypt(nonce, b"CLIENT_FINISHED", b"TLS13_FINISHED")

        server_aead = AESGCM(keys["client_write_key"])
        decrypted = server_aead.decrypt(nonce, ciphertext, b"TLS13_FINISHED")
        self.assertEqual(decrypted, b"CLIENT_FINISHED")


if __name__ == "__main__":
    unittest.main()
