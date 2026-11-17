"""
Independent Cross-Library Cryptographic Interoperability Verification
Validates interoperability between:
1. Rust mlkem 0.2.0 (FIPS 203 Rust backend via PyO3)
2. pyca/cryptography 48.0.0 (OpenSSL 4.0.0 backend via rust_openssl)

Covers:
- ML-KEM-768 Bidirectional Interoperability (Rust Encaps -> OpenSSL Decaps & OpenSSL Encaps -> Rust Decaps)
- ML-KEM-1024 Bidirectional Interoperability (Rust Encaps -> OpenSSL Decaps & OpenSSL Encaps -> Rust Decaps)
- ML-KEM-512 Platform Support Analysis (Documenting OpenSSL deliberate absence per CNSA 2.0 / IETF)
- Serialization compatibility
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import mlkem as pyca_mlkem
import mlkem as rust_mlkem


class TestCrossLibraryInteroperability(unittest.TestCase):
    """
    Cross-Library Interoperability Test Suite between OpenSSL 4.0.0 and Rust mlkem.
    """

    def test_01_mlkem768_rust_encaps_openssl_decaps(self):
        """Direction A: OpenSSL KeyGen -> Rust Encapsulation -> OpenSSL Decapsulation."""
        # 1. Generate keypair in OpenSSL
        sk_ossl = pyca_mlkem.MLKEM768PrivateKey.generate()
        pk_ossl_bytes = sk_ossl.public_key().public_bytes_raw()
        self.assertEqual(len(pk_ossl_bytes), 1184)

        # 2. Import into Rust and encapsulate
        kem_rust = rust_mlkem.ML_KEM(rust_mlkem.ParameterSet.ML_KEM_768)
        ek_rust = rust_mlkem.EncapsKey.from_bytes(pk_ossl_bytes)
        ss_rust, ct_rust = kem_rust.encaps(ek_rust)
        self.assertEqual(len(ss_rust), 32)
        self.assertEqual(len(ct_rust), 1088)

        # 3. Decapsulate in OpenSSL
        ss_ossl = sk_ossl.decapsulate(ct_rust)
        self.assertEqual(len(ss_ossl), 32)

        # 4. Compare shared secrets
        self.assertEqual(
            bytes(ss_rust),
            ss_ossl,
            "Direction A shared secret mismatch between Rust Encaps and OpenSSL Decaps"
        )
        print(f"\n[PASS] ML-KEM-768 Dir A (Rust Encaps -> OpenSSL Decaps): SS = {ss_ossl.hex()[:16]}...")

    def test_02_mlkem768_openssl_encaps_rust_decaps(self):
        """Direction B: Rust KeyGen -> OpenSSL Encapsulation -> Rust Decapsulation."""
        # 1. Generate keypair in Rust
        kem_rust = rust_mlkem.ML_KEM(rust_mlkem.ParameterSet.ML_KEM_768)
        ek_rust, dk_rust = kem_rust.key_gen()
        pk_rust_bytes = ek_rust.to_bytes()
        self.assertEqual(len(pk_rust_bytes), 1184)

        # 2. Import into OpenSSL and encapsulate
        pk_ossl = pyca_mlkem.MLKEM768PublicKey.from_public_bytes(pk_rust_bytes)
        ss_ossl, ct_ossl = pk_ossl.encapsulate()
        self.assertEqual(len(ss_ossl), 32)
        self.assertEqual(len(ct_ossl), 1088)

        # 3. Decapsulate in Rust
        ss_rust = kem_rust.decaps(dk_rust, ct_ossl)
        self.assertEqual(len(ss_rust), 32)

        # 4. Compare shared secrets
        self.assertEqual(
            ss_ossl,
            bytes(ss_rust),
            "Direction B shared secret mismatch between OpenSSL Encaps and Rust Decaps"
        )
        print(f"[PASS] ML-KEM-768 Dir B (OpenSSL Encaps -> Rust Decaps): SS = {ss_ossl.hex()[:16]}...")

    def test_03_mlkem1024_rust_encaps_openssl_decaps(self):
        """Direction A: OpenSSL KeyGen -> Rust Encapsulation -> OpenSSL Decapsulation."""
        sk_ossl = pyca_mlkem.MLKEM1024PrivateKey.generate()
        pk_ossl_bytes = sk_ossl.public_key().public_bytes_raw()
        self.assertEqual(len(pk_ossl_bytes), 1568)

        kem_rust = rust_mlkem.ML_KEM(rust_mlkem.ParameterSet.ML_KEM_1024)
        ek_rust = rust_mlkem.EncapsKey.from_bytes(pk_ossl_bytes)
        ss_rust, ct_rust = kem_rust.encaps(ek_rust)
        self.assertEqual(len(ss_rust), 32)
        self.assertEqual(len(ct_rust), 1568)

        ss_ossl = sk_ossl.decapsulate(ct_rust)
        self.assertEqual(len(ss_ossl), 32)

        self.assertEqual(
            bytes(ss_rust),
            ss_ossl,
            "ML-KEM-1024 Direction A shared secret mismatch"
        )
        print(f"[PASS] ML-KEM-1024 Dir A (Rust Encaps -> OpenSSL Decaps): SS = {ss_ossl.hex()[:16]}...")

    def test_04_mlkem1024_openssl_encaps_rust_decaps(self):
        """Direction B: Rust KeyGen -> OpenSSL Encapsulation -> Rust Decapsulation."""
        kem_rust = rust_mlkem.ML_KEM(rust_mlkem.ParameterSet.ML_KEM_1024)
        ek_rust, dk_rust = kem_rust.key_gen()
        pk_rust_bytes = ek_rust.to_bytes()
        self.assertEqual(len(pk_rust_bytes), 1568)

        pk_ossl = pyca_mlkem.MLKEM1024PublicKey.from_public_bytes(pk_rust_bytes)
        ss_ossl, ct_ossl = pk_ossl.encapsulate()
        self.assertEqual(len(ss_ossl), 32)
        self.assertEqual(len(ct_ossl), 1568)

        ss_rust = kem_rust.decaps(dk_rust, ct_ossl)
        self.assertEqual(len(ss_rust), 32)

        self.assertEqual(
            ss_ossl,
            bytes(ss_rust),
            "ML-KEM-1024 Direction B shared secret mismatch"
        )
        print(f"[PASS] ML-KEM-1024 Dir B (OpenSSL Encaps -> Rust Decaps): SS = {ss_ossl.hex()[:16]}...")

    def test_05_mlkem512_platform_support_analysis(self):
        """
        Validates ML-KEM-512 support status:
        - Rust backend natively supports ML-KEM-512.
        - OpenSSL 4.0.0 deliberately omits ML-KEM-512 (consistent with CNSA 2.0 / IETF draft-ietf-tls-hybrid-design).
        """
        # 1. Rust supports ML-KEM-512
        kem512_rust = rust_mlkem.ML_KEM(rust_mlkem.ParameterSet.ML_KEM_512)
        ek512, dk512 = kem512_rust.key_gen()
        self.assertEqual(len(ek512.to_bytes()), 800)
        ss512, ct512 = kem512_rust.encaps(ek512)
        self.assertEqual(len(ss512), 32)
        self.assertEqual(len(ct512), 768)
        ss512_dec = kem512_rust.decaps(dk512, ct512)
        self.assertEqual(ss512, ss512_dec)

        # 2. OpenSSL does NOT support ML-KEM-512
        has_ossl_512 = hasattr(pyca_mlkem, "MLKEM512PrivateKey")
        self.assertFalse(
            has_ossl_512,
            "pyca/cryptography (OpenSSL 4.0.0) should not export MLKEM512PrivateKey"
        )
        print(
            "[PASS] ML-KEM-512 Platform Constraint Verified: Supported in Rust, "
            "deliberately omitted in OpenSSL 4.0.0 (per NSA CNSA 2.0 guidance)."
        )


if __name__ == "__main__":
    unittest.main()
