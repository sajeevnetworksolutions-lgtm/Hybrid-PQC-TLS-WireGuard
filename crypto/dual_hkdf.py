"""
Dual HKDF Module - Cryptographically Sound Hybrid Secret Derivation Engine
Implements domain-separated HKDF-SHA-256 secret combination per NIST SP 800-56C Rev 2
and IETF hybrid key-agreement principles.

Design Properties:
- Dual Security: The derived master key remains secure as long as either the classical
  primitive (X25519) or the post-quantum primitive (ML-KEM) remains unbroken.
- Strict Domain Separation: Input keying material (IKM) and expanded output keying
  material (OKM) are tagged with explicit protocol and suite identifiers.
- Parameter Binding: Derived keys are bound to the negotiated cipher suite and session context.
- Input Validation: Rejects malformed, truncated, or oversized component secrets.
- Independent Session Isolation: Unique salts and session contexts guarantee non-colliding
  keys across concurrent and sequential sessions.

Note on Standards & Protocol Separation:
This module implements a generic, domain-separated HKDF hybrid combiner per NIST SP 800-56C Rev 2.
- It does NOT claim RFC 9180 (HPKE) compliance, as HPKE defines a full DHKEM/KDF/AEAD scheme.
- It is NOT the TLS 1.3 key schedule (RFC 8446 Section 7.1), which utilizes HKDF-Extract and
  Derive-Secret across transcript hashes (Early Secret, Handshake Secret, Master Secret).
- It is NOT the WireGuard / Noise IK key schedule (Noise Protocol Framework Section 5), which
  chains Diffie-Hellman tokens through Chaining Keys (ck) and Hash (h) chaining.
Protocol-specific key schedules are implemented separately in `protocols/` using proper
transcript hash bindings and state machines.
"""

import os
from typing import Tuple, Optional, Dict
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC


# Constant domain separation labels
DOMAIN_SEPARATOR = b"Hybrid-PQC-KEM-v1"
LABEL_IKM = b":IKM:"
LABEL_EXPAND = b":EXPAND:"


class DualHKDF:
    """
    Domain-Separated Dual HKDF Secret Derivation Engine.
    Combines classical shared secret (e.g., X25519 ECDH) and Post-Quantum KEM secret (e.g., ML-KEM)
    via HKDF-SHA-256 with cryptographic domain separation and context binding.
    """

    def __init__(self, hash_algorithm=None):
        self.hash_algo = hash_algorithm if hash_algorithm is not None else hashes.SHA256()
        self.hash_len = self.hash_algo.digest_size

    def extract(
        self,
        classical_secret: bytes,
        pqc_secret: bytes,
        suite_id: str = "X25519+ML-KEM-768",
        salt: Optional[bytes] = None
    ) -> bytes:
        """
        HKDF-Extract step over domain-separated classical and post-quantum secrets.
        
        Input Keying Material (IKM) construction:
            IKM = DOMAIN_SEPARATOR || ":IKM:" || len(suite) || suite ||
                  len(classical_secret) || classical_secret ||
                  len(pqc_secret) || pqc_secret
        
        Validations:
        - classical_secret must be 32 bytes (or 0 for pure PQC).
        - pqc_secret must be 32 bytes (or 0 for pure classical).
        - At least one secret component must be non-empty.
        """
        if not isinstance(classical_secret, (bytes, bytearray)):
            raise TypeError("classical_secret must be bytes or bytearray")
        if not isinstance(pqc_secret, (bytes, bytearray)):
            raise TypeError("pqc_secret must be bytes or bytearray")

        # Length validation
        c_len = len(classical_secret)
        p_len = len(pqc_secret)

        if c_len == 0 and p_len == 0:
            raise ValueError("At least one secret component (classical or PQC) must be non-empty")
        if c_len not in (0, 32):
            raise ValueError(f"Invalid classical secret length: {c_len} bytes; expected 32 bytes or 0")
        if p_len not in (0, 32):
            raise ValueError(f"Invalid post-quantum secret length: {p_len} bytes; expected 32 bytes or 0")

        suite_bytes = suite_id.encode("utf-8") if isinstance(suite_id, str) else suite_id

        # Salt defaulting per RFC 5869: If salt is None or empty, use a string of HashLen zeros
        salt_bytes = salt if (salt is not None and len(salt) > 0) else (b"\x00" * self.hash_len)

        # Unambiguous domain-separated IKM serialization
        ikm = (
            DOMAIN_SEPARATOR +
            LABEL_IKM +
            len(suite_bytes).to_bytes(2, "big") + suite_bytes +
            c_len.to_bytes(2, "big") + bytes(classical_secret) +
            p_len.to_bytes(2, "big") + bytes(pqc_secret)
        )

        # HKDF-Extract using HMAC-SHA256
        h = HMAC(salt_bytes, self.hash_algo)
        h.update(ikm)
        prk = h.finalize()
        return prk

    def expand(
        self,
        prk: bytes,
        info: bytes = b"Hybrid Master Secret",
        suite_id: str = "X25519+ML-KEM-768",
        context: bytes = b"",
        length: int = 32
    ) -> bytes:
        """
        HKDF-Expand step: Expands PRK with context-bound info tag.
        
        Info construction:
            expanded_info = DOMAIN_SEPARATOR || ":EXPAND:" || len(suite) || suite ||
                            len(context) || context || info
        """
        if not isinstance(prk, (bytes, bytearray)):
            raise TypeError("prk must be bytes or bytearray")
        if len(prk) != self.hash_len:
            raise ValueError(f"Invalid PRK length: {len(prk)} bytes; expected {self.hash_len} bytes")
        if length <= 0 or length > 255 * self.hash_len:
            raise ValueError(f"Invalid expansion length: {length} bytes")

        suite_bytes = suite_id.encode("utf-8") if isinstance(suite_id, str) else suite_id

        expand_info = (
            DOMAIN_SEPARATOR +
            LABEL_EXPAND +
            len(suite_bytes).to_bytes(2, "big") + suite_bytes +
            len(context).to_bytes(2, "big") + bytes(context) +
            bytes(info)
        )

        hkdf_expand = HKDFExpand(
            algorithm=self.hash_algo,
            length=length,
            info=expand_info
        )
        return hkdf_expand.derive(prk)

    def derive_hybrid_key(
        self,
        classical_secret: bytes,
        pqc_secret: bytes,
        suite_id: str = "X25519+ML-KEM-768",
        salt: Optional[bytes] = None,
        context: bytes = b"",
        info: bytes = b"Hybrid Master Secret",
        length: int = 32
    ) -> Tuple[bytes, bytes]:
        """
        Full Dual HKDF Pipeline:
        Combines classical and post-quantum secrets with domain separation.
        Returns: (PRK (32 bytes), OKM (length bytes))
        """
        prk = self.extract(classical_secret, pqc_secret, suite_id=suite_id, salt=salt)
        okm = self.expand(prk, info=info, suite_id=suite_id, context=context, length=length)
        return prk, okm

    def derive_tunnel_keys(
        self,
        prk: bytes,
        session_id: bytes = b"",
        suite_id: str = "X25519+ML-KEM-768"
    ) -> Dict[str, bytes]:
        """
        Derive directional transport keys from PRK:
        - client_write_key (32 bytes)
        - server_write_key (32 bytes)
        - client_write_iv (12 bytes)
        - server_write_iv (12 bytes)
        """
        client_key = self.expand(prk, info=b"client_write_key", suite_id=suite_id, context=session_id, length=32)
        server_key = self.expand(prk, info=b"server_write_key", suite_id=suite_id, context=session_id, length=32)
        client_iv = self.expand(prk, info=b"client_write_iv", suite_id=suite_id, context=session_id, length=12)
        server_iv = self.expand(prk, info=b"server_write_iv", suite_id=suite_id, context=session_id, length=12)

        return {
            "client_write_key": client_key,
            "server_write_key": server_key,
            "client_write_iv": client_iv,
            "server_write_iv": server_iv
        }
