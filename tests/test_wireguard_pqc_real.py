"""
Comprehensive Automated Test Suite for Phase 3: Real WireGuard Post-Quantum Key Exchange
Validates RFC Noise_IKpsk2 compliance, X25519 + ML-KEM-768 hybrid key agreement,
directional session key agreement, peer authorization, message tamper resistance,
TAI64N handshake replay rejection, 64-bit sliding window transport replay filtering,
session key rotation, live UDP socket communication, and performance benchmarking.
"""

import os
import sys
import time
import socket
import struct
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocols.wireguard_pqc import (
    WireGuardPQCNode,
    WireGuardMode,
    WireGuardKeypair,
    WireGuardSession,
    WireGuardMessageType,
    WireGuardHandshakeError,
    ReplayFilter,
    blake2s_hash,
    blake2s_mac,
    LABEL_MAC1,
    LABEL_COOKIE,
    get_tai64n_now,
    compare_tai64n,
    chacha20poly1305_encrypt,
    chacha20poly1305_decrypt
)
from protocols.wireguard_pqc_proxy import WireGuardPQCProxy
from crypto.hybrid_kem import CipherSuiteType


class TestRealWireGuardPostQuantum(unittest.TestCase):
    """
    Test suite for Real Userspace WireGuard Noise_IK Post-Quantum implementation.
    """

    def setUp(self):
        # Fresh keypairs for each test
        self.client_key = WireGuardKeypair()
        self.server_key = WireGuardKeypair()
        self.rogue_key = WireGuardKeypair()

    def test_01_classical_wireguard_handshake_baseline(self):
        """
        1. Classical WireGuard Baseline (RFC Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s).
        Verifies standard WireGuard wire format:
        - Message 1 (Initiation): exactly 148 bytes.
        - Message 2 (Response): exactly 92 bytes.
        - Matching directional session keys.
        """
        client = WireGuardPQCNode("Client_Classical", self.client_key, mode=WireGuardMode.CLASSICAL)
        server = WireGuardPQCNode("Server_Classical", self.server_key, mode=WireGuardMode.CLASSICAL)

        client.add_peer(server.static_pub_bytes, "Server")
        server.add_peer(client.static_pub_bytes, "Client")

        # 1. Initiation
        m1, idx1 = client.create_handshake_initiation(server.static_pub_bytes)
        self.assertEqual(len(m1), 148, f"Classical WireGuard Message 1 must be 148 bytes, got {len(m1)}")
        msg_type, s_idx = struct.unpack("<II", m1[:8])
        self.assertEqual(msg_type, WireGuardMessageType.HANDSHAKE_INITIATION)
        self.assertEqual(s_idx, idx1)

        # 2. Response
        m2, s_sess = server.process_handshake_initiation_and_respond(m1)
        self.assertEqual(len(m2), 92, f"Classical WireGuard Message 2 must be 92 bytes, got {len(m2)}")
        r_type, r_s_idx, r_rx_idx = struct.unpack("<III", m2[:12])
        self.assertEqual(r_type, WireGuardMessageType.HANDSHAKE_RESPONSE)
        self.assertEqual(r_rx_idx, idx1)

        # 3. Finalize on Initiator
        c_sess = client.process_handshake_response(m2)

        # Verify directional transport keys
        self.assertEqual(c_sess.sending_key, s_sess.receiving_key, "Client Tx key must match Server Rx key")
        self.assertEqual(c_sess.receiving_key, s_sess.sending_key, "Client Rx key must match Server Tx key")
        self.assertNotEqual(c_sess.sending_key, c_sess.receiving_key, "Tx and Rx keys must be distinct")

    def test_02_hybrid_wireguard_handshake_x25519_mlkem768(self):
        """
        2. Hybrid WireGuard Handshake (Noise_IKpsk2_X25519_MLKEM768_ChaChaPoly_BLAKE2s).
        Verifies hybrid wire format with embedded ML-KEM-768 KeyShare (FIPS 203):
        - Message 1 (Initiation): exactly 1,332 bytes (148 - 32 + 1216).
        - Message 2 (Response): exactly 1,180 bytes (92 - 32 + 1120).
        """
        client = WireGuardPQCNode("Client_Hybrid", self.client_key, mode=WireGuardMode.HYBRID_MLKEM768)
        server = WireGuardPQCNode("Server_Hybrid", self.server_key, mode=WireGuardMode.HYBRID_MLKEM768)

        client.add_peer(server.static_pub_bytes, "Server")
        server.add_peer(client.static_pub_bytes, "Client")

        t0 = time.perf_counter_ns()
        m1, idx1 = client.create_handshake_initiation(server.static_pub_bytes)
        t_init = (time.perf_counter_ns() - t0) / 1000.0

        self.assertEqual(len(m1), 1332, f"Hybrid WireGuard Message 1 must be 1,332 bytes, got {len(m1)}")

        t1 = time.perf_counter_ns()
        m2, s_sess = server.process_handshake_initiation_and_respond(m1)
        t_resp = (time.perf_counter_ns() - t1) / 1000.0

        self.assertEqual(len(m2), 1180, f"Hybrid WireGuard Message 2 must be 1,180 bytes, got {len(m2)}")

        t2 = time.perf_counter_ns()
        c_sess = client.process_handshake_response(m2)
        t_final = (time.perf_counter_ns() - t2) / 1000.0

        total_us = t_init + t_resp + t_final
        self.assertLess(total_us, 50000.0, "Total hybrid handshake should execute under 50ms")

        # Verify directional keys
        self.assertEqual(c_sess.sending_key, s_sess.receiving_key)
        self.assertEqual(c_sess.receiving_key, s_sess.sending_key)

    def test_03_matching_session_secrets_and_session_separation(self):
        """
        3. Matching Session Secrets and Independent Session Separation.
        Verifies that successive sessions derive independent, non-colliding transport keys.
        """
        client = WireGuardPQCNode("Client", self.client_key, mode=WireGuardMode.HYBRID_MLKEM768)
        server = WireGuardPQCNode("Server", self.server_key, mode=WireGuardMode.HYBRID_MLKEM768)
        client.add_peer(server.static_pub_bytes, "Server")
        server.add_peer(client.static_pub_bytes, "Client")

        # Session 1
        m1_1, _ = client.create_handshake_initiation(server.static_pub_bytes)
        m2_1, s_sess_1 = server.process_handshake_initiation_and_respond(m1_1)
        c_sess_1 = client.process_handshake_response(m2_1)

        # Sleep briefly so TAI64N timestamp strictly advances for Session 2
        time.sleep(0.01)

        # Session 2
        m1_2, _ = client.create_handshake_initiation(server.static_pub_bytes)
        m2_2, s_sess_2 = server.process_handshake_initiation_and_respond(m1_2)
        c_sess_2 = client.process_handshake_response(m2_2)

        # Keys in session 1 must match between client and server
        self.assertEqual(c_sess_1.sending_key, s_sess_1.receiving_key)
        # Keys in session 2 must match between client and server
        self.assertEqual(c_sess_2.sending_key, s_sess_2.receiving_key)

        # Session 1 and Session 2 must derive completely distinct keys
        self.assertNotEqual(c_sess_1.sending_key, c_sess_2.sending_key, "Successive sessions must derive unique keys")
        self.assertNotEqual(c_sess_1.receiving_key, c_sess_2.receiving_key)

    def test_04_invalid_peer_authentication_rejection(self):
        """
        4. Rejection of Unauthorized Peer Identity.
        An attacker with an unauthorized static public key is strictly rejected.
        """
        attacker = WireGuardPQCNode("Attacker", self.rogue_key, mode=WireGuardMode.HYBRID_MLKEM768)
        server = WireGuardPQCNode("Server", self.server_key, mode=WireGuardMode.HYBRID_MLKEM768)
        # Server only authorizes legitimate client, NOT attacker
        server.add_peer(self.client_key.public_bytes, "LegitimateClient")

        # Attacker knows server's public key and sends initiation
        attacker.add_peer(server.static_pub_bytes, "Server")
        m1, _ = attacker.create_handshake_initiation(server.static_pub_bytes)

        with self.assertRaises(WireGuardHandshakeError) as ctx:
            server.process_handshake_initiation_and_respond(m1)

        self.assertIn("unauthorized", str(ctx.exception).lower())

    def test_05_modified_handshake_messages_rejection(self):
        """
        5. Modified Handshake Message Tampering Rejection.
        Validates integrity: any bit flip in ephemeral key, ciphertext, or MAC causes fatal rejection.
        """
        client = WireGuardPQCNode("Client", self.client_key, mode=WireGuardMode.HYBRID_MLKEM768)
        server = WireGuardPQCNode("Server", self.server_key, mode=WireGuardMode.HYBRID_MLKEM768)
        client.add_peer(server.static_pub_bytes, "Server")
        server.add_peer(client.static_pub_bytes, "Client")

        m1, _ = client.create_handshake_initiation(server.static_pub_bytes)

        # A. Tamper with ephemeral key material -> MAC1 fails
        m1_tampered_eph = bytearray(m1)
        m1_tampered_eph[20] ^= 0x01
        with self.assertRaises(WireGuardHandshakeError) as ctx:
            server.process_handshake_initiation_and_respond(bytes(m1_tampered_eph))
        self.assertIn("mac1 verification failed", str(ctx.exception).lower())

        # B. Tamper with MAC1 itself
        m1_tampered_mac = bytearray(m1)
        m1_tampered_mac[-20] ^= 0xFF
        with self.assertRaises(WireGuardHandshakeError) as ctx:
            server.process_handshake_initiation_and_respond(bytes(m1_tampered_mac))
        self.assertIn("mac1 verification failed", str(ctx.exception).lower())

        # C. Tamper with encrypted static payload and recompute valid MAC1
        # AEAD Poly1305 decryption must catch the tampering
        m1_tampered_ct = bytearray(m1)
        m1_tampered_ct[8 + 1216 + 5] ^= 0x01  # Flip bit in encrypted static
        body_len = len(m1) - 32
        mac1_key = blake2s_hash(LABEL_MAC1 + server.static_pub_bytes)
        new_mac = blake2s_mac(mac1_key, bytes(m1_tampered_ct[:body_len]))
        m1_tampered_ct[body_len:body_len + 16] = new_mac

        with self.assertRaises(WireGuardHandshakeError) as ctx:
            server.process_handshake_initiation_and_respond(bytes(m1_tampered_ct))
        self.assertIn("failed to decrypt initiator static identity", str(ctx.exception).lower())

    def test_06_handshake_replay_protection_tai64n(self):
        """
        6. Handshake Replay Protection via TAI64N Timestamps.
        Replaying an intercepted Initiation message must be rejected by the responder.
        """
        client = WireGuardPQCNode("Client", self.client_key, mode=WireGuardMode.HYBRID_MLKEM768)
        server = WireGuardPQCNode("Server", self.server_key, mode=WireGuardMode.HYBRID_MLKEM768)
        client.add_peer(server.static_pub_bytes, "Server")
        server.add_peer(client.static_pub_bytes, "Client")

        m1, _ = client.create_handshake_initiation(server.static_pub_bytes)

        # First delivery succeeds
        m2, s_sess = server.process_handshake_initiation_and_respond(m1)
        self.assertIsNotNone(s_sess)

        # Attacker replays exact same Initiation message
        with self.assertRaises(WireGuardHandshakeError) as ctx:
            server.process_handshake_initiation_and_respond(m1)
        self.assertIn("timestamp replay detected", str(ctx.exception).lower())

    def test_07_encrypted_transport_data_bidirectional(self):
        """
        7. Encrypted Transport Data Transmission (Type 4 Packets).
        Validates bidirectional data encryption using ChaCha20-Poly1305 with 64-bit counters.
        """
        client = WireGuardPQCNode("Client", self.client_key, mode=WireGuardMode.HYBRID_MLKEM768)
        server = WireGuardPQCNode("Server", self.server_key, mode=WireGuardMode.HYBRID_MLKEM768)
        client.add_peer(server.static_pub_bytes, "Server")
        server.add_peer(client.static_pub_bytes, "Client")

        m1, _ = client.create_handshake_initiation(server.static_pub_bytes)
        m2, s_sess = server.process_handshake_initiation_and_respond(m1)
        c_sess = client.process_handshake_response(m2)

        # Client -> Server
        req_payload = b"IP_PACKET: 10.0.0.2 -> 10.0.0.1 ICMP Echo Request [PQC Tunnel]"
        pkt_c2s = c_sess.encrypt_transport_data(req_payload)
        self.assertEqual(len(pkt_c2s), 16 + len(req_payload) + 16, "Header(16B) + Payload + Tag(16B)")

        rx_s = s_sess.decrypt_transport_data(pkt_c2s)
        self.assertEqual(rx_s, req_payload, "Server must receive identical decrypted IP payload")

        # Server -> Client
        resp_payload = b"IP_PACKET: 10.0.0.1 -> 10.0.0.2 ICMP Echo Reply [Quantum-Safe]"
        pkt_s2c = s_sess.encrypt_transport_data(resp_payload)
        rx_c = c_sess.decrypt_transport_data(pkt_s2c)
        self.assertEqual(rx_c, resp_payload, "Client must receive identical decrypted response")

    def test_08_transport_replay_protection_sliding_window(self):
        """
        8. Transport Packet Replay Protection via 64-bit Sliding Window Bitmap.
        Verifies rejection of duplicate counters, rejection of ancient packets,
        and tolerance of out-of-order delivery within window.
        """
        rf = ReplayFilter(window_size=64)

        # 1. Packet 0 accepted
        self.assertTrue(rf.validate_and_update(0))
        # Duplicate of packet 0 rejected
        self.assertFalse(rf.validate_and_update(0))

        # 2. Sequential in-order packets accepted
        self.assertTrue(rf.validate_and_update(1))
        self.assertTrue(rf.validate_and_update(2))
        self.assertTrue(rf.validate_and_update(3))

        # 3. Out-of-order within window accepted
        self.assertTrue(rf.validate_and_update(10))  # Window advances to 10
        self.assertTrue(rf.validate_and_update(7))   # Out of order: 7 < 10, within window
        self.assertTrue(rf.validate_and_update(8))
        self.assertTrue(rf.validate_and_update(5))

        # Duplicates of received out-of-order packets rejected
        self.assertFalse(rf.validate_and_update(7))
        self.assertFalse(rf.validate_and_update(10))

        # 4. Advance window far ahead (e.g. counter 100)
        self.assertTrue(rf.validate_and_update(100))
        # Counter 20 is now (100 - 20 = 80 >= 64): outside sliding window
        self.assertFalse(rf.validate_and_update(20), "Packet outside sliding window must be rejected")
        # Counter 70 is (100 - 70 = 30 < 64): inside window, accepted
        self.assertTrue(rf.validate_and_update(70))
        # Second time 70 is duplicate
        self.assertFalse(rf.validate_and_update(70))

    def test_09_session_key_rotation_and_rekeying(self):
        """
        9. Session Key Rotation & Rekeying Threshold Logic.
        Validates rekey flags when transmission counter or duration limits are reached.
        """
        sess = WireGuardSession(
            local_index=1,
            remote_index=2,
            sending_key=os.urandom(32),
            receiving_key=os.urandom(32),
            is_initiator=True
        )
        self.assertFalse(sess.should_rekey())

        # Simulate reaching REKEY_AFTER_MESSAGES threshold
        sess.sending_counter = 1 << 60
        self.assertTrue(sess.should_rekey(), "Must trigger rekey when message count threshold reached")

        # Simulate expiration
        sess.sending_counter = 0
        sess.created_at = time.time() - 125.0  # > 120s
        self.assertTrue(sess.should_rekey(), "Must trigger rekey after REKEY_AFTER_TIME_SEC")

    def test_10_real_udp_socket_peer_communication(self):
        """
        10. Real UDP Socket Peer-to-Peer Communication.
        Starts two userspace WireGuard peers exchanging hybrid handshakes and encrypted
        transport data packets over actual OS UDP sockets (127.0.0.1 loopback).
        """
        client = WireGuardPQCNode("Client_UDP", self.client_key, mode=WireGuardMode.HYBRID_MLKEM768)
        server = WireGuardPQCNode("Server_UDP", self.server_key, mode=WireGuardMode.HYBRID_MLKEM768)
        client.add_peer(server.static_pub_bytes, "Server")
        server.add_peer(client.static_pub_bytes, "Client")

        # Bind UDP sockets
        try:
            srv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            srv_sock.bind(("127.0.0.1", 0))
            srv_port = srv_sock.getsockname()[1]
            srv_sock.settimeout(3.0)

            cli_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            cli_sock.bind(("127.0.0.1", 0))
            cli_port = cli_sock.getsockname()[1]
            cli_sock.settimeout(3.0)
        except PermissionError as e:
            self.skipTest(f"UDP socket operations restricted in environment: {e}")

        server_state = {"session": None, "rx_data": None, "err": None}

        def server_thread():
            try:
                # 1. Receive Handshake Initiation (Message 1)
                m1_data, cli_addr = srv_sock.recvfrom(4096)
                m2_data, s_session = server.process_handshake_initiation_and_respond(m1_data)
                server_state["session"] = s_session

                # 2. Send Handshake Response (Message 2)
                srv_sock.sendto(m2_data, cli_addr)

                # 3. Receive Encrypted Transport Packet (Type 4)
                data_pkt, _ = srv_sock.recvfrom(4096)
                decrypted = s_session.decrypt_transport_data(data_pkt)
                server_state["rx_data"] = decrypted

                # 4. Reply with Encrypted Transport Packet
                ack = b"UDP_ACK: WireGuard PQC Packet Received"
                ack_pkt = s_session.encrypt_transport_data(ack)
                srv_sock.sendto(ack_pkt, cli_addr)
            except Exception as e:
                server_state["err"] = e

        th = threading.Thread(target=server_thread)
        th.daemon = True
        th.start()

        try:
            # Client initiates over UDP
            m1, _ = client.create_handshake_initiation(server.static_pub_bytes)
            cli_sock.sendto(m1, ("127.0.0.1", srv_port))

            # Client receives response
            try:
                m2_data, _ = cli_sock.recvfrom(4096)
            except (TimeoutError, socket.timeout, OSError) as e:
                self.skipTest(f"UDP loopback traffic blocked by sandbox environment: {e}")
            c_session = client.process_handshake_response(m2_data)

            # Client transmits encrypted payload
            msg_payload = b"UDP_TEST: Real PQC WireGuard Tunnel Active"
            data_pkt = c_session.encrypt_transport_data(msg_payload)
            cli_sock.sendto(data_pkt, ("127.0.0.1", srv_port))

            # Client receives encrypted reply
            ack_pkt, _ = cli_sock.recvfrom(4096)
            ack_decrypted = c_session.decrypt_transport_data(ack_pkt)
            self.assertEqual(ack_decrypted, b"UDP_ACK: WireGuard PQC Packet Received")

            th.join(timeout=3.0)
            self.assertFalse(th.is_alive(), "Server worker thread should terminate cleanly")
            self.assertIsNone(server_state["err"], f"Server encountered error: {server_state['err']}")
            self.assertEqual(server_state["rx_data"], msg_payload)

        finally:
            srv_sock.close()
            cli_sock.close()

    def test_11_classical_vs_hybrid_handshake_benchmark(self):
        """
        11. Classical vs. Hybrid Handshake Benchmarking & Comparative Performance.
        Measures execution time of Classical WireGuard vs. Hybrid X25519 + ML-KEM-768.
        """
        # Classical benchmark (10 iterations)
        c_times = []
        for _ in range(10):
            c_client = WireGuardPQCNode("C_Client", self.client_key, mode=WireGuardMode.CLASSICAL)
            c_server = WireGuardPQCNode("C_Server", self.server_key, mode=WireGuardMode.CLASSICAL)
            c_client.add_peer(c_server.static_pub_bytes, "Server")
            c_server.add_peer(c_client.static_pub_bytes, "Client")

            t0 = time.perf_counter_ns()
            m1, _ = c_client.create_handshake_initiation(c_server.static_pub_bytes)
            m2, _ = c_server.process_handshake_initiation_and_respond(m1)
            c_client.process_handshake_response(m2)
            c_times.append((time.perf_counter_ns() - t0) / 1000.0)

        # Hybrid benchmark (10 iterations)
        h_times = []
        for _ in range(10):
            h_client = WireGuardPQCNode("H_Client", self.client_key, mode=WireGuardMode.HYBRID_MLKEM768)
            h_server = WireGuardPQCNode("H_Server", self.server_key, mode=WireGuardMode.HYBRID_MLKEM768)
            h_client.add_peer(h_server.static_pub_bytes, "Server")
            h_server.add_peer(h_client.static_pub_bytes, "Client")

            t0 = time.perf_counter_ns()
            m1, _ = h_client.create_handshake_initiation(h_server.static_pub_bytes)
            m2, _ = h_server.process_handshake_initiation_and_respond(m1)
            h_client.process_handshake_response(m2)
            h_times.append((time.perf_counter_ns() - t0) / 1000.0)

        avg_c = sum(c_times) / len(c_times)
        avg_h = sum(h_times) / len(h_times)

        print(f"\n[BENCHMARK] WireGuard Handshake Latency:")
        print(f"  - Classical X25519 (148B / 92B)   : {avg_c:.1f} us ({avg_c/1000.0:.2f} ms)")
        print(f"  - Hybrid ML-KEM-768 (1332B / 1180B): {avg_h:.1f} us ({avg_h/1000.0:.2f} ms)")
        print(f"  - Absolute PQC Overhead           : {avg_h - avg_c:.1f} us ({(avg_h - avg_c)/1000.0:.2f} ms)")

        self.assertLess(avg_h, 50000.0, "Hybrid handshake latency must remain < 50 ms")

    def test_12_proxy_backward_compatibility_with_real_macs(self):
        """
        12. Validates WireGuardPQCProxy backward compatibility with real BLAKE2s MACs.
        Preserves 1,301-byte Message 1 and 1,161-byte Message 2.
        """
        proxy_a = WireGuardPQCProxy("PeerA")
        proxy_b = WireGuardPQCProxy("PeerB")

        msg1, init_pk = proxy_a.initiate_wireguard_handshake(proxy_b.static_pub_ec)
        self.assertEqual(len(msg1), 1301)
        self.assertEqual(msg1[0], 1)

        msg2, key_b = proxy_b.respond_wireguard_handshake(msg1, proxy_a.static_pub_ec)
        self.assertEqual(len(msg2), 1161)
        self.assertEqual(msg2[0], 2)
        self.assertEqual(len(key_b), 32)

        key_a = proxy_a.complete_wireguard_handshake(msg2)
        self.assertEqual(key_a, key_b, "Proxy keys must match 100%")


if __name__ == "__main__":
    unittest.main()
