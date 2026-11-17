"""
Hybrid Post-Quantum Key Encapsulation Engine (NIST FIPS 203 + RFC 7748 X25519)
Remediated in Phase 1: Replaces all simulated/random-byte implementations
with genuine, constant-time FIPS 203 ML-KEM-512, ML-KEM-768, and ML-KEM-1024
and domain-separated Dual HKDF key derivation.
"""

import os
import time
from enum import Enum
from typing import Tuple, Dict, Any, Optional

from cryptography.hazmat.primitives.asymmetric import x25519
import mlkem

from crypto.dual_hkdf import DualHKDF
from crypto.kyber512_reference import MLKEM512PrivateKey, MLKEM512PublicKey


class CipherSuiteType(Enum):
    CLASSIC_X25519 = "X25519"
    HYBRID_X25519_MLKEM512 = "X25519+ML-KEM-512"
    HYBRID_X25519_MLKEM768 = "X25519+ML-KEM-768"
    HYBRID_X25519_MLKEM1024 = "X25519+ML-KEM-1024"
    PURE_MLKEM768 = "ML-KEM-768"
    PURE_MLKEM1024 = "ML-KEM-1024"


CIPHER_TAXONOMY = {
    CipherSuiteType.CLASSIC_X25519: {
        "security_level": "128-bit Classical",
        "nist_level": 0,
        "is_quantum_safe": False,
        "pk_size": 32,
        "ct_size": 32,
        "total_handshake_crypto_payload": 64,
        "mtu_fragmentation_risk": "Zero Risk (< 100 B)"
    },
    CipherSuiteType.HYBRID_X25519_MLKEM512: {
        "security_level": "Dual (Classical 128-bit + NIST Level 1)",
        "nist_level": 1,
        "is_quantum_safe": True,
        "pk_size": 32 + 800,  # 832 bytes
        "ct_size": 32 + 768,  # 800 bytes
        "total_handshake_crypto_payload": 1632,
        "mtu_fragmentation_risk": "Moderate (Near 1500B boundary)"
    },
    CipherSuiteType.HYBRID_X25519_MLKEM768: {
        "security_level": "Dual (Classical 128-bit + NIST Level 3)",
        "nist_level": 3,
        "is_quantum_safe": True,
        "pk_size": 32 + 1184,  # 1216 bytes
        "ct_size": 32 + 1088,  # 1120 bytes
        "total_handshake_crypto_payload": 2336,
        "mtu_fragmentation_risk": "High (Multi-packet fragmentation)"
    },
    CipherSuiteType.HYBRID_X25519_MLKEM1024: {
        "security_level": "Dual (Classical 128-bit + NIST Level 5)",
        "nist_level": 5,
        "is_quantum_safe": True,
        "pk_size": 32 + 1568,  # 1600 bytes
        "ct_size": 32 + 1568,  # 1600 bytes
        "total_handshake_crypto_payload": 3200,
        "mtu_fragmentation_risk": "Severe (Guaranteed multi-fragmentation)"
    },
    CipherSuiteType.PURE_MLKEM768: {
        "security_level": "NIST Level 3 (PQC Only)",
        "nist_level": 3,
        "is_quantum_safe": True,
        "pk_size": 1184,
        "ct_size": 1088,
        "total_handshake_crypto_payload": 2272,
        "mtu_fragmentation_risk": "High"
    },
    CipherSuiteType.PURE_MLKEM1024: {
        "security_level": "NIST Level 5 (PQC Only)",
        "nist_level": 5,
        "is_quantum_safe": True,
        "pk_size": 1568,
        "ct_size": 1568,
        "total_handshake_crypto_payload": 3136,
        "mtu_fragmentation_risk": "Severe"
    }
}


class HybridKEMInitiator:
    """
    Client-side initiator for Classical, Hybrid, and Pure Post-Quantum Key Encapsulation.
    """

    def __init__(self, suite: CipherSuiteType = CipherSuiteType.HYBRID_X25519_MLKEM768):
        self.suite = suite
        self.dual_hkdf = DualHKDF()
        self.x25519_priv: Optional[x25519.X25519PrivateKey] = None
        self.x25519_pub_bytes: bytes = b""
        
        # PQC keys
        self.pqc_kem = None
        self.pqc_dk = None
        self.pqc_ek_bytes: bytes = b""
        
        self.shared_master_key: Optional[bytes] = None
        self.keygen_time_us: float = 0.0

    def generate_keypair(self) -> bytes:
        """
        Generates ephemeral public key(s) according to the selected cipher suite.
        Returns the serialized composite public key bytes.
        """
        t0 = time.perf_counter_ns()

        # 1. Classical X25519 Key Generation
        if self.suite in [
            CipherSuiteType.CLASSIC_X25519,
            CipherSuiteType.HYBRID_X25519_MLKEM512,
            CipherSuiteType.HYBRID_X25519_MLKEM768,
            CipherSuiteType.HYBRID_X25519_MLKEM1024
        ]:
            self.x25519_priv = x25519.X25519PrivateKey.generate()
            self.x25519_pub_bytes = self.x25519_priv.public_key().public_bytes_raw()
        else:
            self.x25519_priv = None
            self.x25519_pub_bytes = b""

        # 2. Post-Quantum FIPS 203 ML-KEM Key Generation
        if self.suite == CipherSuiteType.HYBRID_X25519_MLKEM512:
            self.pqc_kem = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_512)
            ek, dk = self.pqc_kem.key_gen()
            self.pqc_dk = dk
            self.pqc_ek_bytes = ek.to_bytes()

        elif self.suite in [CipherSuiteType.HYBRID_X25519_MLKEM768, CipherSuiteType.PURE_MLKEM768]:
            self.pqc_kem = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_768)
            ek, dk = self.pqc_kem.key_gen()
            self.pqc_dk = dk
            self.pqc_ek_bytes = ek.to_bytes()

        elif self.suite in [CipherSuiteType.HYBRID_X25519_MLKEM1024, CipherSuiteType.PURE_MLKEM1024]:
            self.pqc_kem = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_1024)
            ek, dk = self.pqc_kem.key_gen()
            self.pqc_dk = dk
            self.pqc_ek_bytes = ek.to_bytes()

        else:
            self.pqc_kem = None
            self.pqc_dk = None
            self.pqc_ek_bytes = b""

        composite_pk = self.x25519_pub_bytes + self.pqc_ek_bytes
        self.keygen_time_us = (time.perf_counter_ns() - t0) / 1000.0
        return composite_pk

    def decapsulate_response(
        self,
        server_payload: bytes,
        salt: Optional[bytes] = None,
        context: bytes = b""
    ) -> bytes:
        """
        Processes server responder payload, decapsulates shared secrets,
        and derives the authenticated master secret.
        """
        if not isinstance(server_payload, (bytes, bytearray)):
            raise TypeError("server_payload must be bytes or bytearray")

        expected_size = CIPHER_TAXONOMY[self.suite]["ct_size"]
        if len(server_payload) != expected_size:
            raise ValueError(
                f"Invalid server payload length: {len(server_payload)} bytes; "
                f"expected {expected_size} bytes for suite {self.suite.value}"
            )

        # 1. Classical X25519 ECDH
        if self.suite == CipherSuiteType.CLASSIC_X25519:
            server_ec_pub = x25519.X25519PublicKey.from_public_bytes(server_payload[:32])
            ec_ss = self.x25519_priv.exchange(server_ec_pub)
            _, master_key = self.dual_hkdf.derive_hybrid_key(
                classical_secret=ec_ss,
                pqc_secret=b"",
                suite_id=self.suite.value,
                salt=salt,
                context=context
            )
            self.shared_master_key = master_key
            return master_key

        # 2. Hybrid Suites
        elif self.suite == CipherSuiteType.HYBRID_X25519_MLKEM512:
            server_ec_pub = x25519.X25519PublicKey.from_public_bytes(server_payload[:32])
            ec_ss = self.x25519_priv.exchange(server_ec_pub)
            ct_pqc = server_payload[32:32 + 768]
            pqc_ss = self.pqc_kem.decaps(self.pqc_dk, ct_pqc)
            _, master_key = self.dual_hkdf.derive_hybrid_key(
                classical_secret=ec_ss,
                pqc_secret=bytes(pqc_ss),
                suite_id=self.suite.value,
                salt=salt,
                context=context
            )
            self.shared_master_key = master_key
            return master_key

        elif self.suite == CipherSuiteType.HYBRID_X25519_MLKEM768:
            server_ec_pub = x25519.X25519PublicKey.from_public_bytes(server_payload[:32])
            ec_ss = self.x25519_priv.exchange(server_ec_pub)
            ct_pqc = server_payload[32:32 + 1088]
            pqc_ss = self.pqc_kem.decaps(self.pqc_dk, ct_pqc)
            _, master_key = self.dual_hkdf.derive_hybrid_key(
                classical_secret=ec_ss,
                pqc_secret=bytes(pqc_ss),
                suite_id=self.suite.value,
                salt=salt,
                context=context
            )
            self.shared_master_key = master_key
            return master_key

        elif self.suite == CipherSuiteType.HYBRID_X25519_MLKEM1024:
            server_ec_pub = x25519.X25519PublicKey.from_public_bytes(server_payload[:32])
            ec_ss = self.x25519_priv.exchange(server_ec_pub)
            ct_pqc = server_payload[32:32 + 1568]
            pqc_ss = self.pqc_kem.decaps(self.pqc_dk, ct_pqc)
            _, master_key = self.dual_hkdf.derive_hybrid_key(
                classical_secret=ec_ss,
                pqc_secret=bytes(pqc_ss),
                suite_id=self.suite.value,
                salt=salt,
                context=context
            )
            self.shared_master_key = master_key
            return master_key

        # 3. Pure PQC Suites
        elif self.suite == CipherSuiteType.PURE_MLKEM768:
            ct_pqc = server_payload[:1088]
            pqc_ss = self.pqc_kem.decaps(self.pqc_dk, ct_pqc)
            _, master_key = self.dual_hkdf.derive_hybrid_key(
                classical_secret=b"",
                pqc_secret=bytes(pqc_ss),
                suite_id=self.suite.value,
                salt=salt,
                context=context
            )
            self.shared_master_key = master_key
            return master_key

        elif self.suite == CipherSuiteType.PURE_MLKEM1024:
            ct_pqc = server_payload[:1568]
            pqc_ss = self.pqc_kem.decaps(self.pqc_dk, ct_pqc)
            _, master_key = self.dual_hkdf.derive_hybrid_key(
                classical_secret=b"",
                pqc_secret=bytes(pqc_ss),
                suite_id=self.suite.value,
                salt=salt,
                context=context
            )
            self.shared_master_key = master_key
            return master_key

        raise ValueError(f"Unsupported cipher suite: {self.suite}")

    def zeroize(self):
        """
        Best-effort cleanup of sensitive private keys and derived secret material.

        IMPORTANT MEMORY LIMITATION:
        Python's memory management model uses an immutable object allocator and garbage
        collector. Setting references to None or assigning new zero-filled bytes does NOT
        perform in-place memory wiping (memset) on the previously allocated heap buffer.
        Residual key material may remain in memory pools until overwritten by subsequent
        allocations. True constant-time zeroization requires native C/Rust buffers with
        explicit secure-erase primitives (e.g. `memset_s` or `zeroize` crate).
        """
        self.x25519_priv = None
        self.pqc_dk = None
        if self.shared_master_key is not None:
            self.shared_master_key = b"\x00" * len(self.shared_master_key)


class HybridKEMResponder:
    """
    Server-side responder for Classical, Hybrid, and Pure Post-Quantum Key Encapsulation.
    """

    def __init__(self, suite: CipherSuiteType = CipherSuiteType.HYBRID_X25519_MLKEM768):
        self.suite = suite
        self.dual_hkdf = DualHKDF()
        self.shared_master_key: Optional[bytes] = None
        self.encaps_time_us: float = 0.0

    def process_initiator_pk(
        self,
        initiator_composite_pk: bytes,
        salt: Optional[bytes] = None,
        context: bytes = b""
    ) -> Tuple[bytes, bytes]:
        """
        Validates initiator composite public key, encapsulates secrets,
        derives master key, and constructs the responder payload.
        Returns: (response_payload, master_key)
        """
        t0 = time.perf_counter_ns()

        if not isinstance(initiator_composite_pk, (bytes, bytearray)):
            raise TypeError("initiator_composite_pk must be bytes or bytearray")

        expected_pk_size = CIPHER_TAXONOMY[self.suite]["pk_size"]
        if len(initiator_composite_pk) != expected_pk_size:
            raise ValueError(
                f"Invalid initiator public key length: {len(initiator_composite_pk)} bytes; "
                f"expected {expected_pk_size} bytes for suite {self.suite.value}"
            )

        # 1. Classical X25519
        if self.suite == CipherSuiteType.CLASSIC_X25519:
            init_ec_pub = x25519.X25519PublicKey.from_public_bytes(initiator_composite_pk[:32])
            server_ec_priv = x25519.X25519PrivateKey.generate()
            server_ec_raw = server_ec_priv.public_key().public_bytes_raw()
            ec_ss = server_ec_priv.exchange(init_ec_pub)
            _, master_key = self.dual_hkdf.derive_hybrid_key(
                classical_secret=ec_ss,
                pqc_secret=b"",
                suite_id=self.suite.value,
                salt=salt,
                context=context
            )
            self.shared_master_key = master_key
            self.encaps_time_us = (time.perf_counter_ns() - t0) / 1000.0
            return server_ec_raw, master_key

        # 2. Hybrid ML-KEM-512
        elif self.suite == CipherSuiteType.HYBRID_X25519_MLKEM512:
            init_ec_pub = x25519.X25519PublicKey.from_public_bytes(initiator_composite_pk[:32])
            pqc_pk_bytes = initiator_composite_pk[32:32 + 800]
            kem = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_512)
            ek = mlkem.EncapsKey.from_bytes(pqc_pk_bytes)

            server_ec_priv = x25519.X25519PrivateKey.generate()
            server_ec_raw = server_ec_priv.public_key().public_bytes_raw()
            ec_ss = server_ec_priv.exchange(init_ec_pub)
            pqc_ss, ct_pqc = kem.encaps(ek)

            _, master_key = self.dual_hkdf.derive_hybrid_key(
                classical_secret=ec_ss,
                pqc_secret=bytes(pqc_ss),
                suite_id=self.suite.value,
                salt=salt,
                context=context
            )
            response_payload = server_ec_raw + bytes(ct_pqc)
            self.shared_master_key = master_key
            self.encaps_time_us = (time.perf_counter_ns() - t0) / 1000.0
            return response_payload, master_key

        # 3. Hybrid ML-KEM-768
        elif self.suite == CipherSuiteType.HYBRID_X25519_MLKEM768:
            init_ec_pub = x25519.X25519PublicKey.from_public_bytes(initiator_composite_pk[:32])
            pqc_pk_bytes = initiator_composite_pk[32:32 + 1184]
            kem = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_768)
            ek = mlkem.EncapsKey.from_bytes(pqc_pk_bytes)

            server_ec_priv = x25519.X25519PrivateKey.generate()
            server_ec_raw = server_ec_priv.public_key().public_bytes_raw()
            ec_ss = server_ec_priv.exchange(init_ec_pub)
            pqc_ss, ct_pqc = kem.encaps(ek)

            _, master_key = self.dual_hkdf.derive_hybrid_key(
                classical_secret=ec_ss,
                pqc_secret=bytes(pqc_ss),
                suite_id=self.suite.value,
                salt=salt,
                context=context
            )
            response_payload = server_ec_raw + bytes(ct_pqc)
            self.shared_master_key = master_key
            self.encaps_time_us = (time.perf_counter_ns() - t0) / 1000.0
            return response_payload, master_key

        # 4. Hybrid ML-KEM-1024
        elif self.suite == CipherSuiteType.HYBRID_X25519_MLKEM1024:
            init_ec_pub = x25519.X25519PublicKey.from_public_bytes(initiator_composite_pk[:32])
            pqc_pk_bytes = initiator_composite_pk[32:32 + 1568]
            kem = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_1024)
            ek = mlkem.EncapsKey.from_bytes(pqc_pk_bytes)

            server_ec_priv = x25519.X25519PrivateKey.generate()
            server_ec_raw = server_ec_priv.public_key().public_bytes_raw()
            ec_ss = server_ec_priv.exchange(init_ec_pub)
            pqc_ss, ct_pqc = kem.encaps(ek)

            _, master_key = self.dual_hkdf.derive_hybrid_key(
                classical_secret=ec_ss,
                pqc_secret=bytes(pqc_ss),
                suite_id=self.suite.value,
                salt=salt,
                context=context
            )
            response_payload = server_ec_raw + bytes(ct_pqc)
            self.shared_master_key = master_key
            self.encaps_time_us = (time.perf_counter_ns() - t0) / 1000.0
            return response_payload, master_key

        # 5. Pure ML-KEM-768
        elif self.suite == CipherSuiteType.PURE_MLKEM768:
            kem = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_768)
            ek = mlkem.EncapsKey.from_bytes(initiator_composite_pk)
            pqc_ss, ct_pqc = kem.encaps(ek)

            _, master_key = self.dual_hkdf.derive_hybrid_key(
                classical_secret=b"",
                pqc_secret=bytes(pqc_ss),
                suite_id=self.suite.value,
                salt=salt,
                context=context
            )
            self.shared_master_key = master_key
            self.encaps_time_us = (time.perf_counter_ns() - t0) / 1000.0
            return bytes(ct_pqc), master_key

        # 6. Pure ML-KEM-1024
        elif self.suite == CipherSuiteType.PURE_MLKEM1024:
            kem = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_1024)
            ek = mlkem.EncapsKey.from_bytes(initiator_composite_pk)
            pqc_ss, ct_pqc = kem.encaps(ek)

            _, master_key = self.dual_hkdf.derive_hybrid_key(
                classical_secret=b"",
                pqc_secret=bytes(pqc_ss),
                suite_id=self.suite.value,
                salt=salt,
                context=context
            )
            self.shared_master_key = master_key
            self.encaps_time_us = (time.perf_counter_ns() - t0) / 1000.0
            return bytes(ct_pqc), master_key

        raise ValueError(f"Unsupported cipher suite: {self.suite}")

    def zeroize(self):
        """
        Best-effort cleanup of sensitive derived secret material.

        IMPORTANT MEMORY LIMITATION:
        Python's memory management model uses an immutable object allocator and garbage
        collector. Setting references to None or assigning new zero-filled bytes does NOT
        perform in-place memory wiping (memset) on the previously allocated heap buffer.
        Residual key material may remain in memory pools until overwritten by subsequent
        allocations. True constant-time zeroization requires native C/Rust buffers with
        explicit secure-erase primitives (e.g. `memset_s` or `zeroize` crate).
        """
        if self.shared_master_key is not None:
            self.shared_master_key = b"\x00" * len(self.shared_master_key)
