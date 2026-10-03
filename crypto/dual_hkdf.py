"""
Dual HKDF Module - Dual Hybrid Secret Derivation
Compliant with RFC 5869 and NIST SP 800-56C Rev 2.

Implements Eq. 2 from Dissertation Synopsis:
  K_hybrid = HKDF-Extract(Salt, ECDH(sk_ec, pk_ec) || ML-KEM.Decaps(sk_pqc, c_pqc))
"""

import os
from typing import Tuple, Optional
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC


class DualHKDF:
    """
    Dual HKDF Secret Derivation Engine.
    Combines classical shared secret (e.g. X25519) and Post-Quantum KEM secret (e.g. ML-KEM)
    to provide dual-security: secure against classical adversaries even if PQC is broken,
    and secure against quantum adversaries even if classical discrete-log/ECC is broken.
    """

    def __init__(self, hash_algorithm=hashes.SHA256(), salt: Optional[bytes] = None):
        self.hash_algo = hash_algorithm
        self.hash_len = hash_algorithm.digest_size
        self.salt = salt if salt is not None else b"\x00" * self.hash_len

    def extract(self, classical_secret: bytes, pqc_secret: bytes, custom_salt: Optional[bytes] = None) -> bytes:
        """
        HKDF-Extract step over concatenated classical and post-quantum secrets.
        PRK = HMAC-Hash(Salt, IKM) where IKM = ECDH_ss || PQC_ss.
        """
        salt = custom_salt if custom_salt is not None else self.salt
        ikm = classical_secret + pqc_secret
        
        h = HMAC(salt, self.hash_algo)
        h.update(ikm)
        prk = h.finalize()
        return prk

    def expand(self, prk: bytes, info: bytes, length: int = 32) -> bytes:
        """
        HKDF-Expand step: expands PRK with context-specific info tag to generate derived keys.
        """
        hkdf_expand = HKDFExpand(
            algorithm=self.hash_algo,
            length=length,
            info=info
        )
        return hkdf_expand.derive(prk)

    def derive_hybrid_key(
        self,
        classical_secret: bytes,
        pqc_secret: bytes,
        info: bytes = b"TLS 1.3 / WireGuard Hybrid Master Key",
        length: int = 32,
        salt: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """
        Full Dual HKDF Pipeline:
        Returns (Pseudorandom Key (PRK), Derived Hybrid Output Key (OKM)).
        """
        prk = self.extract(classical_secret, pqc_secret, custom_salt=salt)
        okm = self.expand(prk, info=info, length=length)
        return prk, okm

    def derive_tunnel_keys(
        self,
        prk: bytes,
        session_id: bytes = b""
    ) -> dict:
        """
        Derive directional keys for secure bidirectional transport tunnel:
        - client_write_key (32 bytes)
        - server_write_key (32 bytes)
        - client_write_iv (12 bytes)
        - server_write_iv (12 bytes)
        """
        client_key = self.expand(prk, b"c_key" + session_id, length=32)
        server_key = self.expand(prk, b"s_key" + session_id, length=32)
        client_iv = self.expand(prk, b"c_iv" + session_id, length=12)
        server_iv = self.expand(prk, b"s_iv" + session_id, length=12)

        return {
            "client_write_key": client_key,
            "server_write_key": server_key,
            "client_write_iv": client_iv,
            "server_write_iv": server_iv
        }
