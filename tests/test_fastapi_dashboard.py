"""
FastAPI Dashboard & REST API Test Suite
M.Tech Cybersecurity Project 3 - Master Dissertation

Validates all 10 core capabilities of the FastAPI web dashboard backend:
- Health check & system status APIs
- Real TLS 1.3 hybrid handshake execution
- Experimental WireGuard-based hybrid handshake execution
- Ephemeral NIST FIPS 203 ML-KEM key generation, encapsulation & decapsulation
- Authenticated AEAD symmetric encryption & decryption (AES-256-GCM / ChaCha20-Poly1305)
- Tampered ciphertext integrity rejection (InvalidTag)
- Adaptive engine telemetry evaluation & downgrade prevention
- Empirical benchmark summary & live micro-benchmark execution
- Dashboard HTML delivery in Light Mode
"""

import unittest
import json
from app import (
    health_check,
    get_system_status,
    run_tls_handshake,
    run_wireguard_handshake,
    crypto_keygen,
    crypto_encapsulate,
    crypto_decapsulate,
    symmetric_encrypt,
    symmetric_decrypt,
    evaluate_adaptive,
    get_benchmark_summary,
    run_quick_live_benchmark,
    serve_dashboard,
    HandshakeRequest,
    KeygenRequest,
    EncapsulateRequest,
    DecapsulateRequest,
    EncryptRequest,
    DecryptRequest,
    AdaptiveRequest
)


class TestFastAPIDashboard(unittest.TestCase):
    """Automated unit and integration test suite for the FastAPI backend."""

    def test_01_health_endpoint(self):
        """1. Health check returns healthy status and platform versions."""
        res = health_check()
        self.assertEqual(res["status"], "healthy")
        self.assertEqual(res["service"], "Hybrid-PQC-Framework")
        self.assertEqual(res["version"], "1.0.0")
        self.assertIn("openssl_backend", res["environment"])
        self.assertIn("mlkem_backend", res["environment"])

    def test_02_status_endpoint(self):
        """2. System status endpoint reports cryptographic and engine state."""
        res = get_system_status()
        self.assertEqual(res["status"], "ONLINE")
        self.assertIn("fips_203", res["pqc_primitives"])
        self.assertIn("X25519MLKEM768", res["tls13_engine"]["hybrid_group"])
        self.assertIn("Noise_IKpsk2", res["wireguard_engine"]["construction"])

    def test_03_tls_hybrid_handshake_endpoint(self):
        """3. Live TLS 1.3 hybrid handshake negotiates X25519MLKEM768."""
        req = HandshakeRequest(mode="hybrid")
        res = run_tls_handshake(req)
        self.assertEqual(res["status"], "SUCCESS")
        r = res["result"]
        self.assertEqual(r["negotiated_group"], "X25519MLKEM768")
        self.assertTrue(r["secrets_match"])
        self.assertTrue(r["certificate_authenticated"])
        self.assertTrue(r["application_data_verified"])

    def test_04_wireguard_hybrid_handshake_endpoint(self):
        """4. Live WireGuard hybrid handshake executes Noise_IKpsk2."""
        # Test ML-KEM-768
        req768 = HandshakeRequest(mode="hybrid")
        res768 = run_wireguard_handshake(req768)
        self.assertEqual(res768["status"], "SUCCESS")
        r768 = res768["result"]
        self.assertEqual(r768["msg1_initiation_bytes"], 1332)
        self.assertEqual(r768["msg2_response_bytes"], 1180)
        self.assertTrue(r768["secrets_match"])

        # Test ML-KEM-512 (fits IPv6 minimum MTU 1,280B)
        req512 = HandshakeRequest(mode="mlkem512")
        res512 = run_wireguard_handshake(req512)
        self.assertEqual(res512["status"], "SUCCESS")
        r512 = res512["result"]
        self.assertEqual(r512["msg1_initiation_bytes"], 948)
        self.assertEqual(r512["msg2_response_bytes"], 860)
        self.assertTrue(r512["secrets_match"])

    def test_05_crypto_keygen_and_encapsulation_endpoints(self):
        """5. Real FIPS 203 ML-KEM keygen, encapsulation, and decapsulation roundtrip."""
        kg_res = crypto_keygen(KeygenRequest(suite="X25519+ML-KEM-768"))
        self.assertEqual(kg_res["status"], "SUCCESS")
        self.assertEqual(kg_res["public_key_bytes"], 1216)
        session_id = kg_res["session_id"]
        pk_hex = kg_res["public_key_hex"]

        enc_res = crypto_encapsulate(EncapsulateRequest(suite="X25519+ML-KEM-768", public_key_hex=pk_hex))
        self.assertEqual(enc_res["status"], "SUCCESS")
        self.assertEqual(enc_res["ciphertext_bytes"], 1120)
        ct_hex = enc_res["ciphertext_hex"]
        server_secret = enc_res["shared_secret_hex"]

        dec_res = crypto_decapsulate(DecapsulateRequest(suite="X25519+ML-KEM-768", session_id=session_id, ciphertext_hex=ct_hex))
        self.assertEqual(dec_res["status"], "SUCCESS")
        client_secret = dec_res["shared_secret_hex"]

        # Cryptographic equality of derived 256-bit secrets
        self.assertEqual(server_secret, client_secret)

    def test_06_aead_encrypt_and_decrypt(self):
        """6. AEAD encryption and decryption for AES-256-GCM and ChaCha20-Poly1305."""
        for algo in ["AES-256-GCM", "ChaCha20-Poly1305"]:
            plaintext = f"Unit test authenticated payload for {algo}!"
            enc_res = symmetric_encrypt(EncryptRequest(plaintext=plaintext, algorithm=algo))
            self.assertEqual(enc_res["status"], "SUCCESS")
            self.assertEqual(enc_res["algorithm"], algo)

            dec_res = symmetric_decrypt(DecryptRequest(
                ciphertext_hex=enc_res["full_ciphertext_hex"],
                nonce_hex=enc_res["nonce_hex"],
                key_hex=enc_res["key_hex"],
                algorithm=algo,
                tamper=False
            ))
            self.assertEqual(dec_res["status"], "SUCCESS")
            self.assertTrue(dec_res["integrity_verified"])
            self.assertEqual(dec_res["plaintext"], plaintext)

    def test_07_aead_tamper_rejection(self):
        """7. Tampered ciphertext is strictly rejected with AUTHENTICATION_FAILED."""
        plaintext = "Tamper detection test message"
        enc_res = symmetric_encrypt(EncryptRequest(plaintext=plaintext, algorithm="AES-256-GCM"))

        dec_tamper = symmetric_decrypt(DecryptRequest(
            ciphertext_hex=enc_res["full_ciphertext_hex"],
            nonce_hex=enc_res["nonce_hex"],
            key_hex=enc_res["key_hex"],
            algorithm="AES-256-GCM",
            tamper=True  # Bit-flip attack
        ))
        self.assertEqual(dec_tamper["status"], "AUTHENTICATION_FAILED")
        self.assertFalse(dec_tamper["integrity_verified"])
        self.assertTrue(dec_tamper["tampered"])
        self.assertIn("InvalidTag", dec_tamper["error"])

    def test_08_adaptive_evaluation_endpoint(self):
        """8. Adaptive engine evaluation and downgrade prevention verification."""
        # Clean LAN -> ML-KEM-768
        res_clean = evaluate_adaptive(AdaptiveRequest(rtt=1.5, loss=0.0, mtu=1500, allow_downgrade=False))
        self.assertEqual(res_clean["status"], "SUCCESS")
        self.assertEqual(res_clean["decision"]["suite_name"], "X25519+ML-KEM-768")

        # Lossy WAN (3%) -> Downshifts to ML-KEM-512 (does NOT downgrade to classical!)
        res_loss = evaluate_adaptive(AdaptiveRequest(rtt=45.0, loss=3.0, mtu=1500, allow_downgrade=False))
        self.assertEqual(res_loss["status"], "SUCCESS")
        self.assertEqual(res_loss["decision"]["suite_name"], "X25519+ML-KEM-512")
        self.assertTrue(res_loss["decision"]["is_quantum_safe"])

    def test_09_benchmark_endpoints(self):
        """9. Benchmark summary serving and live micro-benchmark execution."""
        # Summary
        summary = get_benchmark_summary()
        self.assertIn("cryptographic_primitives", summary)
        self.assertIn("tls13_handshake", summary)
        self.assertIn("wireguard_handshake", summary)

        # Live micro-benchmark
        live_res = run_quick_live_benchmark()
        self.assertEqual(live_res["status"], "SUCCESS")
        self.assertIn("X25519+ML-KEM-768", live_res["primitives"])
        self.assertTrue(live_res["primitives"]["X25519+ML-KEM-768"]["secrets_match"])

    def test_10_serve_dashboard_html(self):
        """10. Serves the primary Light Mode HTML dashboard."""
        html_res = serve_dashboard()
        self.assertEqual(html_res.status_code, 200)
        body = html_res.body.decode("utf-8")
        self.assertIn("Hybrid Post-Quantum Cryptography", body)
        self.assertIn("Light Mode", body)
        self.assertIn("NIST FIPS 203 ML-KEM", body)


if __name__ == "__main__":
    unittest.main()
