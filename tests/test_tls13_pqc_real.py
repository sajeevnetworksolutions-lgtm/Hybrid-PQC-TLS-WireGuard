"""
Comprehensive Automated Test Suite for Phase 2: Real TLS 1.3 Post-Quantum Key Exchange
Validates RFC 8446 compliance, X25519 + ML-KEM-768 hybrid key exchange (X25519MLKEM768),
Traffic secret agreement, Application data encryption, Certificate authentication and rejection,
Failed handshakes, and Unsupported cipher suite handling.
"""

import os
import sys
import socket
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from protocols.tls_cert_utils import PKIManager
from protocols.tls13_pqc import (
    RealTLS13Config,
    RealTLS13Server,
    RealTLS13Client,
    RealTLS13SocketConnection,
    TLS13SessionPair,
    UnsupportedCipherSuiteError,
    TLSHandshakeError,
    _lib,
    _ffi
)
from protocols.tls13_pqc_tunnel import TLS13PQCClient, TLS13PQCServer
from crypto.hybrid_kem import CipherSuiteType


class TestRealTLS13PostQuantum(unittest.TestCase):
    """
    Test suite for Real TLS 1.3 Post-Quantum Key Exchange implementation.
    """

    @classmethod
    def setUpClass(cls):
        cls.pki = PKIManager()

    @classmethod
    def tearDownClass(cls):
        cls.pki.cleanup()

    def test_01_successful_hybrid_handshake_x25519_mlkem768(self):
        """
        1. Successful TLS 1.3 Handshake with X25519 + ML-KEM-768 Hybrid Key Exchange.
        Validates draft-ietf-tls-hybrid-design (X25519MLKEM768).
        """
        s_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            cert_file=self.pki.server_cert_path,
            key_file=self.pki.server_key_path
        )
        c_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            ca_file=self.pki.ca_cert_path,
            verify_peer=True
        )

        server = RealTLS13Server(s_cfg)
        client = RealTLS13Client(c_cfg)
        session = TLS13SessionPair(server, client)

        success = session.do_handshake()
        self.assertTrue(success, "TLS 1.3 handshake must complete successfully")
        self.assertEqual(session.get_tls_version(), "TLSv1.3", "Must negotiate TLS 1.3 strictly")
        self.assertEqual(session.get_negotiated_group(), "X25519MLKEM768", "Must negotiate X25519MLKEM768 hybrid group")
        self.assertIn("TLS_AES_", session.get_cipher_suite(), "Must negotiate TLS 1.3 AEAD cipher suite")

        session.close()
        server.close()
        client.close()

    def test_02_client_server_traffic_secret_agreement(self):
        """
        2. Client and Server Traffic Secret Agreement Verification.
        Cross-checks derived TLS 1.3 key schedule secrets via OpenSSL keylog callback.
        """
        s_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            cert_file=self.pki.server_cert_path,
            key_file=self.pki.server_key_path,
            record_secrets=True
        )
        c_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            record_secrets=True
        )

        server = RealTLS13Server(s_cfg)
        client = RealTLS13Client(c_cfg)
        session = TLS13SessionPair(server, client)
        session.do_handshake()

        secret_verification = session.verify_traffic_secrets()
        self.assertTrue(
            secret_verification["all_secrets_matched"],
            f"All TLS 1.3 traffic secrets must match between client and server: {secret_verification['details']}"
        )
        self.assertEqual(secret_verification["labels_checked"], 5)

        # Confirm specific key schedule labels are present
        details = secret_verification["details"]
        self.assertTrue(details["CLIENT_HANDSHAKE_TRAFFIC_SECRET"]["matched"])
        self.assertTrue(details["SERVER_HANDSHAKE_TRAFFIC_SECRET"]["matched"])
        self.assertTrue(details["CLIENT_TRAFFIC_SECRET_0"]["matched"])
        self.assertTrue(details["SERVER_TRAFFIC_SECRET_0"]["matched"])
        self.assertTrue(details["EXPORTER_SECRET"]["matched"])

        session.close()
        server.close()
        client.close()

    def test_03_encrypted_application_data_transfer(self):
        """
        3. Encrypted Application-Data Transmission.
        Verifies bidirectional data transfer protected by TLS 1.3 record layer (AES-GCM).
        """
        s_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            cert_file=self.pki.server_cert_path,
            key_file=self.pki.server_key_path
        )
        c_cfg = RealTLS13Config(key_exchange_group="X25519MLKEM768")

        server = RealTLS13Server(s_cfg)
        client = RealTLS13Client(c_cfg)
        session = TLS13SessionPair(server, client)
        session.do_handshake()

        # Client -> Server
        client_payload = b"Quantum-Resistant HTTP/2 Request GET /index.html"
        bytes_sent = session.client_write(client_payload)
        self.assertEqual(bytes_sent, len(client_payload))

        server_received = session.server_read()
        self.assertEqual(server_received, client_payload, "Server must receive identical decrypted payload")

        # Server -> Client
        server_payload = b"HTTP/2 200 OK Content-Type: application/json\r\n\r\n{\"status\": \"secure\"}"
        s_sent = session.server_write(server_payload)
        self.assertEqual(s_sent, len(server_payload))

        client_received = session.client_read()
        self.assertEqual(client_received, server_payload, "Client must receive identical decrypted response")

        session.close()
        server.close()
        client.close()

    def test_04_pure_mlkem768_handshake(self):
        """
        4. Pure Post-Quantum Key Exchange with ML-KEM-768 (NIST Category 3).
        """
        s_cfg = RealTLS13Config(
            key_exchange_group="MLKEM768",
            cert_file=self.pki.server_cert_path,
            key_file=self.pki.server_key_path
        )
        c_cfg = RealTLS13Config(key_exchange_group="MLKEM768")

        server = RealTLS13Server(s_cfg)
        client = RealTLS13Client(c_cfg)
        session = TLS13SessionPair(server, client)
        session.do_handshake()

        self.assertEqual(session.get_negotiated_group(), "MLKEM768")
        self.assertEqual(session.get_tls_version(), "TLSv1.3")

        session.close()
        server.close()
        client.close()

    def test_05_pure_mlkem1024_handshake(self):
        """
        5. Pure Post-Quantum Key Exchange with ML-KEM-1024 (NIST Category 5).
        """
        s_cfg = RealTLS13Config(
            key_exchange_group="MLKEM1024",
            cert_file=self.pki.server_cert_path,
            key_file=self.pki.server_key_path
        )
        c_cfg = RealTLS13Config(key_exchange_group="MLKEM1024")

        server = RealTLS13Server(s_cfg)
        client = RealTLS13Client(c_cfg)
        session = TLS13SessionPair(server, client)
        session.do_handshake()

        self.assertEqual(session.get_negotiated_group(), "MLKEM1024")
        self.assertEqual(session.get_tls_version(), "TLSv1.3")

        session.close()
        server.close()
        client.close()

    def test_06_classical_tls_comparison(self):
        """
        6. Classical TLS 1.3 Key Exchange Comparison (X25519 baseline).
        """
        s_cfg = RealTLS13Config(
            key_exchange_group="X25519",
            cert_file=self.pki.server_cert_path,
            key_file=self.pki.server_key_path
        )
        c_cfg = RealTLS13Config(key_exchange_group="X25519")

        server = RealTLS13Server(s_cfg)
        client = RealTLS13Client(c_cfg)
        session = TLS13SessionPair(server, client)
        session.do_handshake()

        self.assertEqual(session.get_negotiated_group(), "X25519")
        self.assertEqual(session.get_tls_version(), "TLSv1.3")

        session.close()
        server.close()
        client.close()

    def test_07_certificate_verification_success(self):
        """
        7. Real X.509 Certificate Chain of Trust Verification.
        """
        s_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            cert_file=self.pki.server_cert_path,
            key_file=self.pki.server_key_path
        )
        c_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            ca_file=self.pki.ca_cert_path,
            verify_peer=True
        )

        server = RealTLS13Server(s_cfg)
        client = RealTLS13Client(c_cfg)
        session = TLS13SessionPair(server, client)

        # Handshake must succeed when server cert is signed by trusted CA
        self.assertTrue(session.do_handshake())

        session.close()
        server.close()
        client.close()

    def test_08_invalid_certificate_rejection(self):
        """
        8. Rejection of Untrusted / Rogue Server Certificate.
        Verifies that an attacker presenting an unauthorized cert causes handshake failure.
        """
        # Server uses rogue untrusted cert
        s_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            cert_file=self.pki.rogue_cert_path,
            key_file=self.pki.rogue_key_path
        )
        # Client only trusts root CA
        c_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            ca_file=self.pki.ca_cert_path,
            verify_peer=True
        )

        server = RealTLS13Server(s_cfg)
        client = RealTLS13Client(c_cfg)
        session = TLS13SessionPair(server, client)

        with self.assertRaises(TLSHandshakeError) as ctx:
            session.do_handshake()

        self.assertIn("Certificate verification failed", str(ctx.exception))

        session.close()
        server.close()
        client.close()

    def test_09_expired_certificate_rejection(self):
        """
        9. Rejection of Expired Server Certificate.
        Verifies that an expired cert signed by CA causes handshake failure.
        """
        s_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            cert_file=self.pki.expired_cert_path,
            key_file=self.pki.expired_key_path
        )
        c_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            ca_file=self.pki.ca_cert_path,
            verify_peer=True
        )

        server = RealTLS13Server(s_cfg)
        client = RealTLS13Client(c_cfg)
        session = TLS13SessionPair(server, client)

        with self.assertRaises(TLSHandshakeError) as ctx:
            session.do_handshake()

        self.assertIn("Certificate verification failed", str(ctx.exception))

        session.close()
        server.close()
        client.close()

    def test_10_unsupported_hybrid_cipher_suite_handling(self):
        """
        10. Unsupported Cipher Suite Handling (Explicit Rejection, No Silent Downgrade).
        Verifies that requesting ML-KEM-512 in TLS 1.3 raises UnsupportedCipherSuiteError.
        """
        # Attempting to initialize with ML-KEM-512 (omitted by OpenSSL 4.0.0)
        c_cfg = RealTLS13Config(key_exchange_group="X25519+ML-KEM-512")
        with self.assertRaises(UnsupportedCipherSuiteError) as ctx:
            RealTLS13Client(c_cfg)

        self.assertIn("NOT supported", str(ctx.exception))

        # Attempting invalid group name
        c_cfg_bad = RealTLS13Config(key_exchange_group="NonExistentGroup999")
        with self.assertRaises(UnsupportedCipherSuiteError):
            RealTLS13Client(c_cfg_bad)

    def test_11_key_exchange_group_mismatch_failure(self):
        """
        11. Failed Handshake on Named Group Mismatch.
        Client only offers X25519MLKEM768; Server only accepts P-256.
        """
        s_cfg = RealTLS13Config(
            key_exchange_group="P-256",
            cert_file=self.pki.server_cert_path,
            key_file=self.pki.server_key_path
        )
        c_cfg = RealTLS13Config(key_exchange_group="X25519MLKEM768")

        server = RealTLS13Server(s_cfg)
        client = RealTLS13Client(c_cfg)
        session = TLS13SessionPair(server, client)

        with self.assertRaises(TLSHandshakeError):
            session.do_handshake()

        session.close()
        server.close()
        client.close()

    def test_12_tunnel_client_server_wrapper(self):
        """
        12. Validates TLS13PQCClient and TLS13PQCServer tunnel wrappers.
        """
        s = TLS13PQCServer(suite=CipherSuiteType.HYBRID_X25519_MLKEM768)
        c = TLS13PQCClient(suite=CipherSuiteType.HYBRID_X25519_MLKEM768)

        lat = c.execute_handshake(s)
        self.assertGreater(lat, 0.0)
        self.assertEqual(c.negotiated_group, "X25519MLKEM768")
        self.assertEqual(c.tls_version, "TLSv1.3")
        self.assertEqual(s.total_handshakes, 1)

        # Unsupported suite via wrapper must raise UnsupportedCipherSuiteError
        with self.assertRaises(UnsupportedCipherSuiteError):
            TLS13PQCClient(suite=CipherSuiteType.HYBRID_X25519_MLKEM512)

        s.close()

    def test_13_real_tcp_socket_handshake_and_traffic_secrets(self):
        """
        13. Real TCP Socket Handshake, Certificate Authentication, Bidirectional Transfer,
        and TLS 1.3 Traffic Secret Agreement.
        Runs full TLS 1.3 protocol over actual OS TCP socket (127.0.0.1 loopback).
        """
        try:
            srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv_sock.bind(('127.0.0.1', 0))
            srv_sock.settimeout(3.0)
            srv_sock.listen(1)
            port = srv_sock.getsockname()[1]
        except PermissionError as e:
            self.skipTest(f"TCP socket operations restricted in environment: {e}")

        s_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            cert_file=self.pki.server_cert_path,
            key_file=self.pki.server_key_path,
            record_secrets=True
        )
        c_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            ca_file=self.pki.ca_cert_path,
            verify_peer=True,
            record_secrets=True
        )

        server = RealTLS13Server(s_cfg)
        client = RealTLS13Client(c_cfg)

        server_state = {"conn": None, "err": None, "received": None}

        def server_worker():
            try:
                conn, addr = srv_sock.accept()
                conn.settimeout(3.0)
                server_conn = server.accept_socket(conn)
                server_state["conn"] = server_conn
                # Read client request
                server_state["received"] = server_conn.read(4096)
                # Send server response
                resp = b"HTTP/1.3 200 OK\r\nContent-Type: text/plain\r\n\r\nQuantum-Safe TCP TLS 1.3 Verified"
                server_conn.write(resp)
            except Exception as e:
                server_state["err"] = e

        th = threading.Thread(target=server_worker)
        th.daemon = True
        th.start()

        cli_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli_sock.settimeout(3.0)
        try:
            cli_sock.connect(('127.0.0.1', port))
            client_conn = client.connect_socket(cli_sock)
        except PermissionError as e:
            cli_sock.close()
            srv_sock.close()
            th.join(timeout=1.0)
            server.close()
            client.close()
            self.skipTest(f"TCP connect restricted in sandbox: {e}")

        # 1. Verify certificate authentication
        v_res = client_conn.get_verify_result()
        self.assertEqual(v_res, 0, f"Certificate validation must succeed (0 == X509_V_OK), got {v_res}")

        # 2. Verify negotiated group and protocol version from live session
        self.assertEqual(client_conn.get_negotiated_group(), "X25519MLKEM768")
        self.assertEqual(client_conn.get_tls_version(), "TLSv1.3")
        self.assertIn("TLS_AES_", client_conn.get_cipher_suite())

        # 3. Bidirectional data exchange over TCP
        req = b"GET /pqc-test HTTP/1.3\r\nHost: localhost\r\n\r\n"
        n_written = client_conn.write(req)
        self.assertEqual(n_written, len(req))

        resp_data = client_conn.read(4096)
        self.assertIn(b"Quantum-Safe TCP TLS 1.3 Verified", resp_data)

        # 4. Clean shutdown without hanging
        client_conn.shutdown()
        th.join(timeout=5.0)
        self.assertFalse(th.is_alive(), "Server worker thread must terminate cleanly without hanging")
        self.assertIsNone(server_state["err"], f"Server worker encountered error: {server_state['err']}")
        self.assertEqual(server_state["received"], req, "Server must receive identical decrypted request")

        if server_state["conn"]:
            server_state["conn"].shutdown()
        srv_sock.close()

        # 5. Verify all 5 TLS 1.3 traffic secrets match bit-for-bit
        client_map = {}
        for line in client.traffic_secrets:
            parts = line.split()
            if len(parts) >= 3:
                client_map[parts[0]] = parts[-1]

        server_map = {}
        for line in server.traffic_secrets:
            parts = line.split()
            if len(parts) >= 3:
                server_map[parts[0]] = parts[-1]

        required_labels = [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
            "EXPORTER_SECRET"
        ]
        for lbl in required_labels:
            self.assertIn(lbl, client_map, f"Client missing keylog secret {lbl}")
            self.assertIn(lbl, server_map, f"Server missing keylog secret {lbl}")
            self.assertEqual(
                client_map[lbl],
                server_map[lbl],
                f"Secret mismatch between client and server for {lbl}"
            )

        server.close()
        client.close()

    def test_14_negotiated_group_verification_from_session(self):
        """
        14. Direct Negotiated Group Verification from Live OpenSSL SSL Session.
        Extracts actual negotiated TLS group via SSL_get0_group_name directly from
        the SSL session struct, confirming it is not a configured-only string.
        """
        s_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            cert_file=self.pki.server_cert_path,
            key_file=self.pki.server_key_path
        )
        c_cfg = RealTLS13Config(
            key_exchange_group="X25519MLKEM768",
            ca_file=self.pki.ca_cert_path,
            verify_peer=True
        )

        server = RealTLS13Server(s_cfg)
        client = RealTLS13Client(c_cfg)
        session = TLS13SessionPair(server, client)

        # Execute genuine TLS 1.3 handshake
        handshake_ok = session.do_handshake()
        self.assertTrue(handshake_ok, "TLS 1.3 handshake must complete successfully")

        # After handshake, inspect live OpenSSL session struct directly
        post_group_c_ptr = _lib.SSL_get0_group_name(session.client_ssl)
        post_group_s_ptr = _lib.SSL_get0_group_name(session.server_ssl)
        self.assertNotEqual(post_group_c_ptr, _ffi.NULL, "Client session must contain negotiated group pointer")
        self.assertNotEqual(post_group_s_ptr, _ffi.NULL, "Server session must contain negotiated group pointer")

        c_group_name = _ffi.string(post_group_c_ptr).decode("utf-8")
        s_group_name = _ffi.string(post_group_s_ptr).decode("utf-8")
        self.assertEqual(c_group_name, "X25519MLKEM768", "Client session negotiated group must be X25519MLKEM768")
        self.assertEqual(s_group_name, "X25519MLKEM768", "Server session negotiated group must be X25519MLKEM768")

        # Verify negotiated protocol version and cipher suite
        version_c = _ffi.string(_lib.SSL_get_version(session.client_ssl)).decode("utf-8")
        version_s = _ffi.string(_lib.SSL_get_version(session.server_ssl)).decode("utf-8")
        self.assertEqual(version_c, "TLSv1.3", "Negotiated protocol version must be TLSv1.3")
        self.assertEqual(version_s, "TLSv1.3", "Server protocol version must be TLSv1.3")

        cipher_c = _ffi.string(_lib.SSL_CIPHER_get_name(_lib.SSL_get_current_cipher(session.client_ssl))).decode("utf-8")
        cipher_s = _ffi.string(_lib.SSL_CIPHER_get_name(_lib.SSL_get_current_cipher(session.server_ssl))).decode("utf-8")
        self.assertEqual(cipher_c, cipher_s, "Client and server must negotiate identical cipher suites")
        self.assertTrue(cipher_c.startswith("TLS_AES_") or cipher_c.startswith("TLS_CHACHA20_"), f"Unexpected cipher suite: {cipher_c}")

        # Also confirm session wrapper helpers mirror the live session struct
        self.assertEqual(session.get_negotiated_group(), "X25519MLKEM768")
        self.assertEqual(session.get_tls_version(), "TLSv1.3")
        self.assertEqual(session.get_cipher_suite(), cipher_c)

        session.close()
        server.close()
        client.close()


if __name__ == "__main__":
    unittest.main()
