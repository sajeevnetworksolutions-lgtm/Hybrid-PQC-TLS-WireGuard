"""
Comprehensive Test Suite for Phase 1: Cryptographic Foundation Remediation
Validates NIST FIPS 203 ML-KEM (512, 768, 1024), RFC 7748 X25519,
Domain-Separated Dual HKDF, Input Validation, and Known Answer Tests.
"""

import os
import sys
import unittest
from typing import Tuple

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import mlkem as py_mlkem
import mlkem

from crypto.dual_hkdf import DualHKDF
from crypto.kyber512_reference import MLKEM512PrivateKey, MLKEM512PublicKey
from crypto.hybrid_kem import (
    HybridKEMInitiator,
    HybridKEMResponder,
    CipherSuiteType,
    CIPHER_TAXONOMY
)


class TestPhase1CryptographicFoundation(unittest.TestCase):
    """
    Independent Phase 1 verification tests covering all 12 required verification aspects.
    """

    # -------------------------------------------------------------------------
    # 1. ML-KEM-512 Key Generation
    # -------------------------------------------------------------------------
    def test_01_mlkem512_keygen(self):
        priv = MLKEM512PrivateKey.generate()
        pub = priv.public_key()
        raw_pk = pub.public_bytes_raw()
        
        self.assertEqual(len(raw_pk), 800, "ML-KEM-512 public key must be exactly 800 bytes (FIPS 203)")
        self.assertIsInstance(raw_pk, bytes)
        # Ensure key is non-trivial (not all zero)
        self.assertNotEqual(raw_pk, b"\x00" * 800)

    # -------------------------------------------------------------------------
    # 2. ML-KEM-768 Key Generation
    # -------------------------------------------------------------------------
    def test_02_mlkem768_keygen(self):
        kem = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_768)
        ek, dk = kem.key_gen()
        raw_pk = ek.to_bytes()
        
        self.assertEqual(len(raw_pk), 1184, "ML-KEM-768 public key must be exactly 1,184 bytes (FIPS 203)")
        self.assertIsInstance(raw_pk, bytes)
        self.assertNotEqual(raw_pk, b"\x00" * 1184)

    # -------------------------------------------------------------------------
    # 3. ML-KEM-1024 Key Generation
    # -------------------------------------------------------------------------
    def test_03_mlkem1024_keygen(self):
        kem = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_1024)
        ek, dk = kem.key_gen()
        raw_pk = ek.to_bytes()
        
        self.assertEqual(len(raw_pk), 1568, "ML-KEM-1024 public key must be exactly 1,568 bytes (FIPS 203)")
        self.assertIsInstance(raw_pk, bytes)
        self.assertNotEqual(raw_pk, b"\x00" * 1568)

    # -------------------------------------------------------------------------
    # 4. Encapsulation and Decapsulation Round-Trip Across All Parameter Sets
    # -------------------------------------------------------------------------
    def test_04_encaps_decaps_roundtrip(self):
        test_cases = [
            ("ML-KEM-512", mlkem.ParameterSet.ML_KEM_512, 800, 768),
            ("ML-KEM-768", mlkem.ParameterSet.ML_KEM_768, 1184, 1088),
            ("ML-KEM-1024", mlkem.ParameterSet.ML_KEM_1024, 1568, 1568),
        ]

        for name, param, expected_pk_len, expected_ct_len in test_cases:
            with self.subTest(algorithm=name):
                kem = mlkem.ML_KEM(param)
                ek, dk = kem.key_gen()
                ss_enc, ct = kem.encaps(ek)
                ss_dec = kem.decaps(dk, ct)

                self.assertEqual(len(bytes(ek)), expected_pk_len)
                self.assertEqual(len(bytes(ct)), expected_ct_len)
                self.assertEqual(len(bytes(ss_enc)), 32)
                self.assertEqual(len(bytes(ss_dec)), 32)
                self.assertEqual(ss_enc, ss_dec, f"{name} encapsulated and decapsulated secrets must match")

    # -------------------------------------------------------------------------
    # 5. Shared-Secret Agreement Consistency
    # -------------------------------------------------------------------------
    def test_05_shared_secret_agreement(self):
        # Verify agreement using MLKEM512 reference wrapper
        priv512 = MLKEM512PrivateKey.generate()
        pub512 = priv512.public_key()
        ss_enc, ct = pub512.encapsulate()
        ss_dec = priv512.decapsulate(ct)
        self.assertEqual(ss_enc, ss_dec)
        self.assertEqual(len(ss_enc), 32)

        # Verify agreement using ML-KEM-768
        kem768 = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_768)
        ek768, dk768 = kem768.key_gen()
        ss_enc768, ct768 = kem768.encaps(ek768)
        ss_dec768 = kem768.decaps(dk768, ct768)
        self.assertEqual(ss_enc768, ss_dec768)

    # -------------------------------------------------------------------------
    # 6. X25519 Classical ECDH Agreement
    # -------------------------------------------------------------------------
    def test_06_x25519_agreement(self):
        priv_client = x25519.X25519PrivateKey.generate()
        pub_client = priv_client.public_key()

        priv_server = x25519.X25519PrivateKey.generate()
        pub_server = priv_server.public_key()

        ss_client = priv_client.exchange(pub_server)
        ss_server = priv_server.exchange(pub_client)

        self.assertEqual(len(pub_client.public_bytes_raw()), 32)
        self.assertEqual(len(pub_server.public_bytes_raw()), 32)
        self.assertEqual(len(ss_client), 32)
        self.assertEqual(ss_client, ss_server, "X25519 ECDH secrets must match exactly")

    # -------------------------------------------------------------------------
    # 7. Hybrid Key Agreement Across All Cipher Suites
    # -------------------------------------------------------------------------
    def test_07_hybrid_key_agreement_all_suites(self):
        for suite in CipherSuiteType:
            with self.subTest(suite=suite.value):
                initiator = HybridKEMInitiator(suite=suite)
                responder = HybridKEMResponder(suite=suite)

                # 1. Initiator generates keypair
                init_pk = initiator.generate_keypair()
                expected_pk_size = CIPHER_TAXONOMY[suite]["pk_size"]
                self.assertEqual(len(init_pk), expected_pk_size)

                # 2. Responder processes initiator public key and encapsulates
                resp_payload, server_master_key = responder.process_initiator_pk(init_pk)
                expected_ct_size = CIPHER_TAXONOMY[suite]["ct_size"]
                self.assertEqual(len(resp_payload), expected_ct_size)
                self.assertEqual(len(server_master_key), 32)

                # 3. Initiator decapsulates responder payload
                client_master_key = initiator.decapsulate_response(resp_payload)
                self.assertEqual(len(client_master_key), 32)

                # 4. Master secrets must match 100%
                self.assertEqual(
                    client_master_key,
                    server_master_key,
                    f"Hybrid master key derivation must agree for suite {suite.value}"
                )

    # -------------------------------------------------------------------------
    # 8. Invalid Ciphertexts & Fujisaki-Okamoto Implicit Rejection
    # -------------------------------------------------------------------------
    def test_08_invalid_ciphertext_implicit_rejection(self):
        suite = CipherSuiteType.HYBRID_X25519_MLKEM768
        initiator = HybridKEMInitiator(suite=suite)
        responder = HybridKEMResponder(suite=suite)

        init_pk = initiator.generate_keypair()
        resp_payload, server_master_key = responder.process_initiator_pk(init_pk)

        # Flip bit 50 inside the ciphertext segment
        tampered_payload = bytearray(resp_payload)
        tampered_payload[50] ^= 0xFF
        client_master_key = initiator.decapsulate_response(bytes(tampered_payload))

        # Because of Fujisaki-Okamoto implicit rejection:
        # Decapsulation does NOT crash, but derives a pseudorandom distinct key
        self.assertEqual(len(client_master_key), 32)
        self.assertNotEqual(
            client_master_key,
            server_master_key,
            "Tampered ciphertext must result in mismatched key due to FO implicit rejection"
        )

    # -------------------------------------------------------------------------
    # 9. Invalid Public Keys Rejection
    # -------------------------------------------------------------------------
    def test_09_invalid_public_key_rejection(self):
        # 1. Truncated ML-KEM-512 EncapsKey
        with self.assertRaises(ValueError):
            mlkem.EncapsKey.from_bytes(b"\x00" * 799)

        # 2. Oversized ML-KEM-768 EncapsKey
        with self.assertRaises(ValueError):
            mlkem.EncapsKey.from_bytes(b"\x00" * 1185)

        # 3. Truncated initiator PK in Hybrid responder
        responder = HybridKEMResponder(suite=CipherSuiteType.HYBRID_X25519_MLKEM768)
        with self.assertRaises(ValueError):
            responder.process_initiator_pk(b"\xaa" * 500)

    # -------------------------------------------------------------------------
    # 10. Incorrect Key and Parameter Lengths Validation
    # -------------------------------------------------------------------------
    def test_10_incorrect_lengths_validation(self):
        hkdf = DualHKDF()

        # Both secrets empty -> ValueError
        with self.assertRaises(ValueError):
            hkdf.derive_hybrid_key(b"", b"")

        # Classical secret invalid length (not 32) -> ValueError
        with self.assertRaises(ValueError):
            hkdf.derive_hybrid_key(b"short", b"B" * 32)

        # PQC secret invalid length (not 32) -> ValueError
        with self.assertRaises(ValueError):
            hkdf.derive_hybrid_key(b"A" * 32, b"long" * 10)

        # Invalid PRK length for expand -> ValueError
        with self.assertRaises(ValueError):
            hkdf.expand(prk=b"too_short_prk", length=32)

    # -------------------------------------------------------------------------
    # 11. Independent Session Separation
    # -------------------------------------------------------------------------
    def test_11_session_separation(self):
        hkdf = DualHKDF()
        ec_ss = b"\x01" * 32
        pqc_ss = b"\x02" * 32

        # Same secrets, different salts -> distinct keys
        _, key_salt_a = hkdf.derive_hybrid_key(ec_ss, pqc_ss, salt=b"SESSION_A")
        _, key_salt_b = hkdf.derive_hybrid_key(ec_ss, pqc_ss, salt=b"SESSION_B")
        self.assertNotEqual(key_salt_a, key_salt_b, "Different salts must produce different keys")

        # Same secrets, different contexts -> distinct keys
        _, key_ctx_a = hkdf.derive_hybrid_key(ec_ss, pqc_ss, context=b"CLIENT_RANDOM_1")
        _, key_ctx_b = hkdf.derive_hybrid_key(ec_ss, pqc_ss, context=b"CLIENT_RANDOM_2")
        self.assertNotEqual(key_ctx_a, key_ctx_b, "Different contexts must produce different keys")

        # Same secrets, different suite_ids -> distinct keys (cross-suite domain separation)
        _, key_suite_768 = hkdf.derive_hybrid_key(ec_ss, pqc_ss, suite_id="X25519+ML-KEM-768")
        _, key_suite_1024 = hkdf.derive_hybrid_key(ec_ss, pqc_ss, suite_id="X25519+ML-KEM-1024")
        self.assertNotEqual(key_suite_768, key_suite_1024, "Different suite_ids must produce different keys")

        # Dual security property (freshness in either primitive ensures fresh output)
        ec_ss_alt = b"\x03" * 32
        pqc_ss_alt = b"\x04" * 32
        _, key_alt_ec = hkdf.derive_hybrid_key(ec_ss_alt, pqc_ss)
        _, key_alt_pqc = hkdf.derive_hybrid_key(ec_ss, pqc_ss_alt)
        self.assertNotEqual(key_suite_768, key_alt_ec, "Changing EC secret must alter derived key")
        self.assertNotEqual(key_suite_768, key_alt_pqc, "Changing PQC secret must alter derived key")
        self.assertNotEqual(key_alt_ec, key_alt_pqc, "Independent secret changes must produce distinct keys")

        # Directional tunnel key separation
        prk = hkdf.extract(ec_ss, pqc_ss)
        tunnel_keys = hkdf.derive_tunnel_keys(prk, session_id=b"sess_42")
        keys_set = {
            tunnel_keys["client_write_key"],
            tunnel_keys["server_write_key"],
            tunnel_keys["client_write_iv"],
            tunnel_keys["server_write_iv"]
        }
        self.assertEqual(len(keys_set), 4, "All directional tunnel keys and IVs must be mutually distinct")

    # -------------------------------------------------------------------------
    # 12. NIST FIPS 203 Official ACVP Known-Answer Test (KAT) Vectors
    # -------------------------------------------------------------------------
    def test_12_known_answer_test_vectors(self):
        """
        Validates ML-KEM-512, ML-KEM-768, and ML-KEM-1024 against official NIST ACVP
        Known Answer Test (KAT) vectors from the NIST Post-Quantum Cryptography project.
        Verifies:
        1. Deterministic KeyGen from seed (d || z) per FIPS 203 Section 6.1 Algorithm 16.
        2. Exact bit-for-bit public key match against official NIST KAT pk.
        3. Decapsulation of official NIST KAT ciphertext yields exact NIST KAT shared secret.
        4. Rejection behavior on corrupted ciphertext (Fujisaki-Okamoto implicit rejection).
        5. Cross-library interoperability (OpenSSL 4.0.0 <-> Rust mlkem).
        """
        import json
        kat_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "kat_vectors.json")
        self.assertTrue(os.path.exists(kat_file), f"KAT vectors file missing: {kat_file}")
        with open(kat_file, "r") as f:
            kat_data = json.load(f)

        # --- A. ML-KEM-512 Official NIST KAT ---
        kat512 = kat_data["MLKEM_512"]
        pk512_exp = bytes.fromhex(kat512["pk"])
        sk512_raw = bytes.fromhex(kat512["sk"])
        ct512_kat = bytes.fromhex(kat512["ct"])
        ss512_exp = bytes.fromhex(kat512["ss"])

        self.assertEqual(len(pk512_exp), 800)
        self.assertEqual(len(sk512_raw), 1632)
        self.assertEqual(len(ct512_kat), 768)
        self.assertEqual(len(ss512_exp), 32)

        kem512 = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_512)
        dk512 = mlkem.DecapsKey.from_bytes(sk512_raw)
        ss512_derived = kem512.decaps(dk512, ct512_kat)
        self.assertEqual(
            bytes(ss512_derived),
            ss512_exp,
            "ML-KEM-512 decapsulation must match official NIST ACVP KAT shared secret"
        )

        # Implicit rejection check: corrupted ciphertext must NOT yield the valid secret
        ct512_corrupt = bytearray(ct512_kat)
        ct512_corrupt[0] ^= 0xFF
        ss512_corrupt = kem512.decaps(dk512, bytes(ct512_corrupt))
        self.assertNotEqual(
            bytes(ss512_corrupt),
            ss512_exp,
            "ML-KEM-512 corrupted ciphertext must implicitly reject and produce distinct secret"
        )

        # --- B. ML-KEM-768 Official NIST KAT ---
        kat768 = kat_data["MLKEM_768"]
        d768 = bytes.fromhex(kat768["d"])
        z768 = bytes.fromhex(kat768["z"])
        pk768_exp = bytes.fromhex(kat768["pk"])
        sk768_raw = bytes.fromhex(kat768["sk"])
        ct768_kat = bytes.fromhex(kat768["ct"])
        ss768_exp = bytes.fromhex(kat768["ss"])

        self.assertEqual(len(pk768_exp), 1184)
        self.assertEqual(len(sk768_raw), 2400)
        self.assertEqual(len(ct768_kat), 1088)
        self.assertEqual(len(ss768_exp), 32)

        # 1. Deterministic KeyGen from seed (d || z) via OpenSSL backend
        priv_768 = py_mlkem.MLKEM768PrivateKey.from_seed_bytes(d768 + z768)
        pk768_gen = priv_768.public_key().public_bytes_raw()
        self.assertEqual(
            pk768_gen,
            pk768_exp,
            "ML-KEM-768 KeyGen from seed (d||z) must produce exact official NIST ACVP public key"
        )

        # 2. OpenSSL decapsulation of official KAT ciphertext
        ss768_ossl = priv_768.decapsulate(ct768_kat)
        self.assertEqual(
            ss768_ossl,
            ss768_exp,
            "ML-KEM-768 OpenSSL decapsulation must match official NIST ACVP KAT shared secret"
        )

        # 3. Rust mlkem decapsulation of official KAT ciphertext
        kem768 = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_768)
        dk768 = mlkem.DecapsKey.from_bytes(sk768_raw)
        ss768_rust = kem768.decaps(dk768, ct768_kat)
        self.assertEqual(
            bytes(ss768_rust),
            ss768_exp,
            "ML-KEM-768 Rust decapsulation must match official NIST ACVP KAT shared secret"
        )

        # 4. Cross-library interoperability
        # Rust encaps with OpenSSL public key -> OpenSSL decaps
        ek768_rust = mlkem.EncapsKey.from_bytes(pk768_exp)
        ss768_cross_rust, ct768_cross = kem768.encaps(ek768_rust)
        ss768_cross_ossl = priv_768.decapsulate(ct768_cross)
        self.assertEqual(
            ss768_cross_rust,
            ss768_cross_ossl,
            "ML-KEM-768 Rust encaps -> OpenSSL decaps must match"
        )

        # --- C. ML-KEM-1024 Official NIST KAT ---
        kat1024 = kat_data["MLKEM_1024"]
        d1024 = bytes.fromhex(kat1024["d"])
        z1024 = bytes.fromhex(kat1024["z"])
        pk1024_exp = bytes.fromhex(kat1024["pk"])
        sk1024_raw = bytes.fromhex(kat1024["sk"])
        ct1024_kat = bytes.fromhex(kat1024["ct"])
        ss1024_exp = bytes.fromhex(kat1024["ss"])

        self.assertEqual(len(pk1024_exp), 1568)
        self.assertEqual(len(sk1024_raw), 3168)
        self.assertEqual(len(ct1024_kat), 1568)
        self.assertEqual(len(ss1024_exp), 32)

        # 1. Deterministic KeyGen from seed (d || z) via OpenSSL backend
        priv_1024 = py_mlkem.MLKEM1024PrivateKey.from_seed_bytes(d1024 + z1024)
        pk1024_gen = priv_1024.public_key().public_bytes_raw()
        self.assertEqual(
            pk1024_gen,
            pk1024_exp,
            "ML-KEM-1024 KeyGen from seed (d||z) must produce exact official NIST ACVP public key"
        )

        # 2. OpenSSL decapsulation of official KAT ciphertext
        ss1024_ossl = priv_1024.decapsulate(ct1024_kat)
        self.assertEqual(
            ss1024_ossl,
            ss1024_exp,
            "ML-KEM-1024 OpenSSL decapsulation must match official NIST ACVP KAT shared secret"
        )

        # 3. Rust mlkem decapsulation of official KAT ciphertext
        kem1024 = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_1024)
        dk1024 = mlkem.DecapsKey.from_bytes(sk1024_raw)
        ss1024_rust = kem1024.decaps(dk1024, ct1024_kat)
        self.assertEqual(
            bytes(ss1024_rust),
            ss1024_exp,
            "ML-KEM-1024 Rust decapsulation must match official NIST ACVP KAT shared secret"
        )

        # 4. Cross-library interoperability
        ek1024_rust = mlkem.EncapsKey.from_bytes(pk1024_exp)
        ss1024_cross_rust, ct1024_cross = kem1024.encaps(ek1024_rust)
        ss1024_cross_ossl = priv_1024.decapsulate(ct1024_cross)
        self.assertEqual(
            ss1024_cross_rust,
            ss1024_cross_ossl,
            "ML-KEM-1024 Rust encaps -> OpenSSL decaps must match"
        )


if __name__ == "__main__":
    unittest.main()
