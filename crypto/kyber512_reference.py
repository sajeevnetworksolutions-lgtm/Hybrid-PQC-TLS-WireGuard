"""
ML-KEM-512 Cryptographic Module (NIST FIPS 203)
Remediated in Phase 1: Replaces legacy non-compliant polynomial simulation
with the verified, constant-time, KAT-tested FIPS 203 ML-KEM-512 engine.

Parameters (NIST Security Category 1 / AES-128 equivalent):
- k = 2
- eta_1 = 3, eta_2 = 2
- d_u = 10, d_v = 4
- Public Key Size: 800 Bytes
- Ciphertext Size: 768 Bytes
- Shared Secret Size: 32 Bytes
"""

import os
from typing import Tuple, Optional
import mlkem


class MLKEM512PublicKey:
    """
    NIST FIPS 203 ML-KEM-512 Public Key (Encapsulation Key)
    Size: Exactly 800 bytes.
    """

    def __init__(self, raw_bytes: bytes):
        if not isinstance(raw_bytes, (bytes, bytearray)):
            raise TypeError("Public key bytes must be bytes or bytearray")
        if len(raw_bytes) != 800:
            raise ValueError(f"Invalid ML-KEM-512 public key size: {len(raw_bytes)} bytes; expected 800 bytes")

        self._raw_bytes = bytes(raw_bytes)
        self._encaps_key = mlkem.EncapsKey.from_bytes(self._raw_bytes)
        self._kem = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_512)

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "MLKEM512PublicKey":
        return cls(data)

    def public_bytes_raw(self) -> bytes:
        return self._raw_bytes

    def encapsulate(self) -> Tuple[bytes, bytes]:
        """
        NIST FIPS 203 ML-KEM-512 Encapsulation.
        Returns: (shared_secret [32 bytes], ciphertext [768 bytes])
        """
        shared_secret, ciphertext = self._kem.encaps(self._encaps_key)
        return bytes(shared_secret), bytes(ciphertext)


class MLKEM512PrivateKey:
    """
    NIST FIPS 203 ML-KEM-512 Private Key (Decapsulation Key)
    """

    def __init__(self, decaps_key: mlkem.DecapsKey, pub_bytes: bytes):
        self._decaps_key = decaps_key
        self._pub_bytes = pub_bytes
        self._kem = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_512)

    @classmethod
    def generate(cls) -> "MLKEM512PrivateKey":
        """
        Generates a new authentic ML-KEM-512 keypair using cryptographically secure RNG.
        """
        kem = mlkem.ML_KEM(mlkem.ParameterSet.ML_KEM_512)
        ek, dk = kem.key_gen()
        return cls(dk, bytes(ek))

    def public_key(self) -> MLKEM512PublicKey:
        return MLKEM512PublicKey(self._pub_bytes)

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        NIST FIPS 203 ML-KEM-512 Decapsulation with Fujisaki-Okamoto implicit rejection.
        Returns: 32-byte shared secret.
        """
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("Ciphertext must be bytes or bytearray")
        if len(ciphertext) != 768:
            raise ValueError(f"Invalid ML-KEM-512 ciphertext size: {len(ciphertext)} bytes; expected 768 bytes")

        shared_secret = self._kem.decaps(self._decaps_key, bytes(ciphertext))
        return bytes(shared_secret)

    def zeroize(self):
        """
        Best-effort cleanup of internal key references.

        IMPORTANT MEMORY LIMITATION:
        Python's memory management model uses an immutable object allocator and garbage
        collector. Setting references to None or assigning new zero-filled bytes does NOT
        perform in-place memory wiping (memset) on the previously allocated heap buffer.
        Residual key material may remain in memory pools until overwritten by subsequent
        allocations. True constant-time zeroization requires native C/Rust buffers with
        explicit secure-erase primitives (e.g. `memset_s` or `zeroize` crate).
        """
        self._decaps_key = None
        self._pub_bytes = b"\x00" * len(self._pub_bytes)
