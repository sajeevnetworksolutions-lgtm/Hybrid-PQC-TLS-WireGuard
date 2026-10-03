"""
Hybrid Post-Quantum Key Encapsulation Engine
Combines Classical X25519 (ECDH) with NIST FIPS 203 ML-KEM (512 / 768 / 1024).

Implements:
- Objective 1: Modular Hybrid Key Exchange Pipeline
- Dual-security key derivation with Dual HKDF (Eq. 2)
"""

import os
import time
from enum import Enum
from typing import Tuple, Dict, Any, Optional

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import mlkem

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
    def __init__(self, suite: CipherSuiteType = CipherSuiteType.HYBRID_X25519_MLKEM768):
        self.suite = suite
        self.dual_hkdf = DualHKDF()
        self.x25519_priv = None
        self.x25519_pub = None
        self.pqc_priv = None
        self.pqc_pub = None
        self.shared_master_key = None
        self.keygen_time_us = 0.0

    def generate_keypair(self) -> bytes:
        t0 = time.perf_counter_ns()

        if self.suite in [
            CipherSuiteType.CLASSIC_X25519,
            CipherSuiteType.HYBRID_X25519_MLKEM512,
            CipherSuiteType.HYBRID_X25519_MLKEM768,
            CipherSuiteType.HYBRID_X25519_MLKEM1024
        ]:
            self.x25519_priv = x25519.X25519PrivateKey.generate()
            self.x25519_pub = self.x25519_priv.public_key()
            x25519_raw = self.x25519_pub.public_bytes_raw()
        else:
            x25519_raw = b""

        pqc_raw = b""
        if self.suite == CipherSuiteType.HYBRID_X25519_MLKEM512:
            self.pqc_priv = MLKEM512PrivateKey.generate()
            self.pqc_pub = self.pqc_priv.public_key()
            pqc_raw = self.pqc_pub.public_bytes_raw()
        elif self.suite in [CipherSuiteType.HYBRID_X25519_MLKEM768, CipherSuiteType.PURE_MLKEM768]:
            self.pqc_priv = mlkem.MLKEM768PrivateKey.generate()
            self.pqc_pub = self.pqc_priv.public_key()
            pqc_raw = self.pqc_pub.public_bytes_raw()
        elif self.suite in [CipherSuiteType.HYBRID_X25519_MLKEM1024, CipherSuiteType.PURE_MLKEM1024]:
            self.pqc_priv = mlkem.MLKEM1024PrivateKey.generate()
            self.pqc_pub = self.pqc_priv.public_key()
            pqc_raw = self.pqc_pub.public_bytes_raw()

        composite_pk = x25519_raw + pqc_raw
        self.keygen_time_us = (time.perf_counter_ns() - t0) / 1000.0
        return composite_pk

    def decapsulate_response(self, server_payload: bytes, salt: Optional[bytes] = None) -> bytes:
        if self.suite == CipherSuiteType.CLASSIC_X25519:
            server_ec_pk_bytes = server_payload[:32]
            server_ec_pub = x25519.X25519PublicKey.from_public_bytes(server_ec_pk_bytes)
            ec_ss = self.x25519_priv.exchange(server_ec_pub)
            _, master_key = self.dual_hkdf.derive_hybrid_key(ec_ss, b"", salt=salt)
            self.shared_master_key = master_key
            return master_key

        elif self.suite == CipherSuiteType.HYBRID_X25519_MLKEM512:
            server_ec_pk_bytes = server_payload[:32]
            ct_pqc = server_payload[32:32 + 768]
            server_ec_pub = x25519.X25519PublicKey.from_public_bytes(server_ec_pk_bytes)
            ec_ss = self.x25519_priv.exchange(server_ec_pub)
            pqc_ss = self.pqc_priv.decapsulate(ct_pqc)
            _, master_key = self.dual_hkdf.derive_hybrid_key(ec_ss, pqc_ss, salt=salt)
            self.shared_master_key = master_key
            return master_key

        elif self.suite == CipherSuiteType.HYBRID_X25519_MLKEM768:
            server_ec_pk_bytes = server_payload[:32]
            ct_pqc = server_payload[32:32 + 1088]
            server_ec_pub = x25519.X25519PublicKey.from_public_bytes(server_ec_pk_bytes)
            ec_ss = self.x25519_priv.exchange(server_ec_pub)
            pqc_ss = self.pqc_priv.decapsulate(ct_pqc)
            _, master_key = self.dual_hkdf.derive_hybrid_key(ec_ss, pqc_ss, salt=salt)
            self.shared_master_key = master_key
            return master_key

        elif self.suite == CipherSuiteType.HYBRID_X25519_MLKEM1024:
            server_ec_pk_bytes = server_payload[:32]
            ct_pqc = server_payload[32:32 + 1568]
            server_ec_pub = x25519.X25519PublicKey.from_public_bytes(server_ec_pk_bytes)
            ec_ss = self.x25519_priv.exchange(server_ec_pub)
            pqc_ss = self.pqc_priv.decapsulate(ct_pqc)
            _, master_key = self.dual_hkdf.derive_hybrid_key(ec_ss, pqc_ss, salt=salt)
            self.shared_master_key = master_key
            return master_key

        elif self.suite == CipherSuiteType.PURE_MLKEM768:
            ct_pqc = server_payload[:1088]
            pqc_ss = self.pqc_priv.decapsulate(ct_pqc)
            _, master_key = self.dual_hkdf.derive_hybrid_key(b"", pqc_ss, salt=salt)
            self.shared_master_key = master_key
            return master_key

        elif self.suite == CipherSuiteType.PURE_MLKEM1024:
            ct_pqc = server_payload[:1568]
            pqc_ss = self.pqc_priv.decapsulate(ct_pqc)
            _, master_key = self.dual_hkdf.derive_hybrid_key(b"", pqc_ss, salt=salt)
            self.shared_master_key = master_key
            return master_key

        raise ValueError(f"Unsupported cipher suite: {self.suite}")


class HybridKEMResponder:
    def __init__(self, suite: CipherSuiteType = CipherSuiteType.HYBRID_X25519_MLKEM768):
        self.suite = suite
        self.dual_hkdf = DualHKDF()
        self.shared_master_key = None
        self.encaps_time_us = 0.0

    def process_initiator_pk(self, initiator_composite_pk: bytes, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        t0 = time.perf_counter_ns()

        if self.suite == CipherSuiteType.CLASSIC_X25519:
            init_ec_pk_bytes = initiator_composite_pk[:32]
            init_ec_pub = x25519.X25519PublicKey.from_public_bytes(init_ec_pk_bytes)
            server_ec_priv = x25519.X25519PrivateKey.generate()
            server_ec_pub = server_ec_priv.public_key()
            server_ec_raw = server_ec_pub.public_bytes_raw()
            ec_ss = server_ec_priv.exchange(init_ec_pub)
            _, master_key = self.dual_hkdf.derive_hybrid_key(ec_ss, b"", salt=salt)
            self.shared_master_key = master_key
            self.encaps_time_us = (time.perf_counter_ns() - t0) / 1000.0
            return server_ec_raw, master_key

        elif self.suite == CipherSuiteType.HYBRID_X25519_MLKEM512:
            init_ec_pk_bytes = initiator_composite_pk[:32]
            init_pqc_pk_bytes = initiator_composite_pk[32:32 + 800]
            init_ec_pub = x25519.X25519PublicKey.from_public_bytes(init_ec_pk_bytes)
            init_pqc_pub = MLKEM512PublicKey.from_public_bytes(init_pqc_pk_bytes)
            server_ec_priv = x25519.X25519PrivateKey.generate()
            server_ec_pub = server_ec_priv.public_key()
            server_ec_raw = server_ec_pub.public_bytes_raw()
            ec_ss = server_ec_priv.exchange(init_ec_pub)
            pqc_ss, ct_pqc = init_pqc_pub.encapsulate()
            _, master_key = self.dual_hkdf.derive_hybrid_key(ec_ss, pqc_ss, salt=salt)
            response_payload = server_ec_raw + ct_pqc
            self.shared_master_key = master_key
            self.encaps_time_us = (time.perf_counter_ns() - t0) / 1000.0
            return response_payload, master_key

        elif self.suite == CipherSuiteType.HYBRID_X25519_MLKEM768:
            init_ec_pk_bytes = initiator_composite_pk[:32]
            init_pqc_pk_bytes = initiator_composite_pk[32:32 + 1184]
            init_ec_pub = x25519.X25519PublicKey.from_public_bytes(init_ec_pk_bytes)
            init_pqc_pub = mlkem.MLKEM768PublicKey.from_public_bytes(init_pqc_pk_bytes)
            server_ec_priv = x25519.X25519PrivateKey.generate()
            server_ec_pub = server_ec_priv.public_key()
            server_ec_raw = server_ec_pub.public_bytes_raw()
            ec_ss = server_ec_priv.exchange(init_ec_pub)
            pqc_ss, ct_pqc = init_pqc_pub.encapsulate()
            _, master_key = self.dual_hkdf.derive_hybrid_key(ec_ss, pqc_ss, salt=salt)
            response_payload = server_ec_raw + ct_pqc
            self.shared_master_key = master_key
            self.encaps_time_us = (time.perf_counter_ns() - t0) / 1000.0
            return response_payload, master_key

        elif self.suite == CipherSuiteType.HYBRID_X25519_MLKEM1024:
            init_ec_pk_bytes = initiator_composite_pk[:32]
            init_pqc_pk_bytes = initiator_composite_pk[32:32 + 1568]
            init_ec_pub = x25519.X25519PublicKey.from_public_bytes(init_ec_pk_bytes)
            init_pqc_pub = mlkem.MLKEM1024PublicKey.from_public_bytes(init_pqc_pk_bytes)
            server_ec_priv = x25519.X25519PrivateKey.generate()
            server_ec_pub = server_ec_priv.public_key()
            server_ec_raw = server_ec_pub.public_bytes_raw()
            ec_ss = server_ec_priv.exchange(init_ec_pub)
            pqc_ss, ct_pqc = init_pqc_pub.encapsulate()
            _, master_key = self.dual_hkdf.derive_hybrid_key(ec_ss, pqc_ss, salt=salt)
            response_payload = server_ec_raw + ct_pqc
            self.shared_master_key = master_key
            self.encaps_time_us = (time.perf_counter_ns() - t0) / 1000.0
            return response_payload, master_key

        elif self.suite == CipherSuiteType.PURE_MLKEM768:
            init_pqc_pk_bytes = initiator_composite_pk[:1184]
            init_pqc_pub = mlkem.MLKEM768PublicKey.from_public_bytes(init_pqc_pk_bytes)
            pqc_ss, ct_pqc = init_pqc_pub.encapsulate()
            _, master_key = self.dual_hkdf.derive_hybrid_key(b"", pqc_ss, salt=salt)
            self.shared_master_key = master_key
            self.encaps_time_us = (time.perf_counter_ns() - t0) / 1000.0
            return ct_pqc, master_key

        elif self.suite == CipherSuiteType.PURE_MLKEM1024:
            init_pqc_pk_bytes = initiator_composite_pk[:1568]
            init_pqc_pub = mlkem.MLKEM1024PublicKey.from_public_bytes(init_pqc_pk_bytes)
            pqc_ss, ct_pqc = init_pqc_pub.encapsulate()
            _, master_key = self.dual_hkdf.derive_hybrid_key(b"", pqc_ss, salt=salt)
            self.shared_master_key = master_key
            self.encaps_time_us = (time.perf_counter_ns() - t0) / 1000.0
            return ct_pqc, master_key

        raise ValueError(f"Unsupported cipher suite: {self.suite}")
