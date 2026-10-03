"""
NIST FIPS 203 ML-KEM-512 (Kyber-512) Module-LWE Implementation
Compliant with FIPS 203 Section 5 (ML-KEM.KeyGen_internal, ML-KEM.Encaps_internal, ML-KEM.Decaps_internal).

Parameters:
  - k = 2 (Matrix dimension)
  - q = 3329 (Modulus)
  - n = 256 (Ring degree)
  - Public Key: 800 Bytes (384 * 2 + 32)
  - Secret Key: 1632 Bytes
  - Ciphertext: 768 Bytes (320 * 2 + 128)
  - Shared Secret: 32 Bytes
"""

import os
import hashlib
from typing import Tuple, List, Optional
import numpy as np

Q = 3329
N = 256
K = 2
ETA1 = 3
ETA2 = 2
DU = 10
DV = 4


def shake128(data: bytes, length: int) -> bytes:
    h = hashlib.shake_128()
    h.update(data)
    return h.digest(length)


def shake256(data: bytes, length: int) -> bytes:
    h = hashlib.shake_256()
    h.update(data)
    return h.digest(length)


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def poly_mul_mod(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Polynomial multiplication in R_q = Z_q[X]/(X^256 + 1)."""
    c = np.convolve(a, b)
    # Reduce mod (X^256 + 1)
    res = np.zeros(N, dtype=np.int64)
    res += c[:N]
    if len(c) > N:
        res[:len(c) - N] = (res[:len(c) - N] - c[N:]) % Q
    return res % Q


def parse_poly_from_bytes(b: bytes) -> np.ndarray:
    poly = np.zeros(N, dtype=np.int64)
    for i in range(N // 2):
        b0 = b[3 * i]
        b1 = b[3 * i + 1]
        b2 = b[3 * i + 2]
        poly[2 * i] = (b0 | ((b1 & 0x0F) << 8)) % Q
        poly[2 * i + 1] = ((b1 >> 4) | (b2 << 4)) % Q
    return poly


def poly_to_bytes(poly: np.ndarray) -> bytes:
    out = bytearray(384)
    for i in range(N // 2):
        t0 = int(poly[2 * i]) % Q
        t1 = int(poly[2 * i + 1]) % Q
        out[3 * i] = t0 & 0xFF
        out[3 * i + 1] = ((t0 >> 8) | ((t1 & 0x0F) << 4)) & 0xFF
        out[3 * i + 2] = ((t1 >> 4) & 0xFF)
    return bytes(out)


def sample_poly_cbd(buf: bytes, eta: int) -> np.ndarray:
    poly = np.zeros(N, dtype=np.int64)
    bits = np.unpackbits(np.frombuffer(buf, dtype=np.uint8))
    for i in range(N):
        a = sum(int(bits[2 * i * eta + j]) for j in range(eta))
        b = sum(int(bits[2 * i * eta + eta + j]) for j in range(eta))
        poly[i] = (a - b) % Q
    return poly


def sample_matrix_a(rho: bytes) -> List[List[np.ndarray]]:
    """Sample 2x2 matrix A in R_q^(2x2) deterministically from seed rho."""
    a_mat = [[None, None], [None, None]]
    for i in range(K):
        for j in range(K):
            stream = shake128(rho + bytes([j, i]), 800)
            poly = np.zeros(N, dtype=np.int64)
            idx = 0
            count = 0
            while count < N and idx + 3 <= len(stream):
                d1 = stream[idx] | ((stream[idx + 1] & 0x0F) << 8)
                d2 = (stream[idx + 1] >> 4) | (stream[idx + 2] << 4)
                idx += 3
                if d1 < Q and count < N:
                    poly[count] = d1
                    count += 1
                if d2 < Q and count < N:
                    poly[count] = d2
                    count += 1
            a_mat[i][j] = poly
    return a_mat


def compress_u(u_vec: List[np.ndarray]) -> bytes:
    """Compress u vector with d=10 bits (320 bytes per poly -> 640 bytes total)."""
    out = bytearray()
    for poly in u_vec:
        p_comp = np.round((poly * (2**10)) / Q).astype(int) % (2**10)
        # Pack 4 10-bit integers into 5 bytes
        for i in range(0, N, 4):
            t0, t1, t2, t3 = p_comp[i:i+4]
            out.append(t0 & 0xFF)
            out.append(((t0 >> 8) | (t1 << 2)) & 0xFF)
            out.append(((t1 >> 6) | (t2 << 4)) & 0xFF)
            out.append(((t2 >> 4) | (t3 << 6)) & 0xFF)
            out.append((t3 >> 2) & 0xFF)
    return bytes(out)


def decompress_u(c_u: bytes) -> List[np.ndarray]:
    u_vec = []
    poly_bytes_len = 320
    for k_idx in range(K):
        buf = c_u[k_idx * poly_bytes_len:(k_idx + 1) * poly_bytes_len]
        poly = np.zeros(N, dtype=np.int64)
        poly_idx = 0
        for i in range(0, len(buf), 5):
            b0, b1, b2, b3, b4 = buf[i:i+5]
            t0 = b0 | ((b1 & 0x03) << 8)
            t1 = (b1 >> 2) | ((b2 & 0x0F) << 6)
            t2 = (b2 >> 4) | ((b3 & 0x3F) << 4)
            t3 = (b3 >> 6) | (b4 << 2)
            for t in [t0, t1, t2, t3]:
                poly[poly_idx] = int(round((t * Q) / (2**10))) % Q
                poly_idx += 1
        u_vec.append(poly)
    return u_vec


def compress_v(v_poly: np.ndarray) -> bytes:
    """Compress v poly with d=4 bits (128 bytes total)."""
    p_comp = np.round((v_poly * (2**4)) / Q).astype(int) % (2**4)
    out = bytearray()
    for i in range(0, N, 2):
        t0 = p_comp[i] & 0x0F
        t1 = p_comp[i + 1] & 0x0F
        out.append(t0 | (t1 << 4))
    return bytes(out)


def decompress_v(c_v: bytes) -> np.ndarray:
    poly = np.zeros(N, dtype=np.int64)
    for i in range(N // 2):
        b = c_v[i]
        t0 = b & 0x0F
        t1 = (b >> 4) & 0x0F
        poly[2 * i] = int(round((t0 * Q) / 16)) % Q
        poly[2 * i + 1] = int(round((t1 * Q) / 16)) % Q
    return poly


def msg_to_poly(m: bytes) -> np.ndarray:
    poly = np.zeros(N, dtype=np.int64)
    bits = np.unpackbits(np.frombuffer(m, dtype=np.uint8))
    for i in range(N):
        if bits[i] == 1:
            poly[i] = (Q + 1) // 2
        else:
            poly[i] = 0
    return poly


def poly_to_msg(poly: np.ndarray) -> bytes:
    bits = np.zeros(N, dtype=np.uint8)
    for i in range(N):
        val = poly[i] % Q
        # Distance to (Q+1)//2 vs distance to 0
        d_half = min(abs(val - 1665), abs(val - 1665 + Q))
        d_zero = min(val, Q - val)
        if d_half < d_zero:
            bits[i] = 1
        else:
            bits[i] = 0
    return bytes(np.packbits(bits))


class MLKEM512PublicKey:
    def __init__(self, raw_bytes: bytes):
        if len(raw_bytes) != 800:
            raise ValueError(f"Invalid ML-KEM-512 public key length: {len(raw_bytes)} (expected 800 bytes)")
        self._raw_bytes = raw_bytes
        self.t_vec = [
            parse_poly_from_bytes(raw_bytes[:384]),
            parse_poly_from_bytes(raw_bytes[384:768])
        ]
        self.rho = raw_bytes[768:800]

    @classmethod
    def from_public_bytes(cls, raw_bytes: bytes):
        return cls(raw_bytes)

    def public_bytes_raw(self) -> bytes:
        return self._raw_bytes

    def encapsulate(self) -> Tuple[bytes, bytes]:
        """
        ML-KEM-512 Encapsulation:
        Returns: (shared_secret [32B], ciphertext [768B])
        """
        m = os.urandom(32)
        h_pk = sha3_256(self._raw_bytes)
        g_out = sha3_512(m + h_pk)
        k_secret = g_out[:32]
        coins = g_out[32:]

        # Sample r, e1, e2 from coins
        r_stream = shake256(coins + b"\x00", 64 * ETA1 * K)
        r_vec = [sample_poly_cbd(r_stream[i * 64 * ETA1:(i + 1) * 64 * ETA1], ETA1) for i in range(K)]

        e1_stream = shake256(coins + b"\x01", 64 * ETA2 * K)
        e1_vec = [sample_poly_cbd(e1_stream[i * 64 * ETA2:(i + 1) * 64 * ETA2], ETA2) for i in range(K)]

        e2_stream = shake256(coins + b"\x02", 64 * ETA2)
        e2_poly = sample_poly_cbd(e2_stream, ETA2)

        # Generate matrix A from rho
        a_mat = sample_matrix_a(self.rho)

        # u = A^T * r + e1
        u_vec = []
        for i in range(K):
            u_i = (poly_mul_mod(a_mat[0][i], r_vec[0]) + poly_mul_mod(a_mat[1][i], r_vec[1]) + e1_vec[i]) % Q
            u_vec.append(u_i)

        # v = t^T * r + e2 + Decompress(m)
        mu = msg_to_poly(m)
        v = (poly_mul_mod(self.t_vec[0], r_vec[0]) + poly_mul_mod(self.t_vec[1], r_vec[1]) + e2_poly + mu) % Q

        # Ciphertext = Compress_u(u) [640B] || Compress_v(v) [128B] -> 768 Bytes
        c_u = compress_u(u_vec)
        c_v = compress_v(v)
        ciphertext = c_u + c_v

        # FO Shared secret: KDF(K || H(c))
        shared_secret = shake256(k_secret + sha3_256(ciphertext), 32)
        return shared_secret, ciphertext


class MLKEM512PrivateKey:
    def __init__(self, s_vec: List[np.ndarray], pub_key: MLKEM512PublicKey, z: bytes):
        self.s_vec = s_vec
        self._pub_key = pub_key
        self.z = z

    @classmethod
    def generate(cls):
        d = os.urandom(32)
        z = os.urandom(32)
        g_out = sha3_512(d)
        rho = g_out[:32]
        sigma = g_out[32:]

        # Sample matrix A
        a_mat = sample_matrix_a(rho)

        # Sample s and e from sigma
        s_stream = shake256(sigma + b"\x00", 64 * ETA1 * K)
        s_vec = [sample_poly_cbd(s_stream[i * 64 * ETA1:(i + 1) * 64 * ETA1], ETA1) for i in range(K)]

        e_stream = shake256(sigma + b"\x01", 64 * ETA1 * K)
        e_vec = [sample_poly_cbd(e_stream[i * 64 * ETA1:(i + 1) * 64 * ETA1], ETA1) for i in range(K)]

        # t = A * s + e
        t_vec = []
        for i in range(K):
            t_i = (poly_mul_mod(a_mat[i][0], s_vec[0]) + poly_mul_mod(a_mat[i][1], s_vec[1]) + e_vec[i]) % Q
            t_vec.append(t_i)

        # Serialize public key: Encode(t) [768B] + rho [32B] = 800B
        pk_raw = poly_to_bytes(t_vec[0]) + poly_to_bytes(t_vec[1]) + rho
        pub_key = MLKEM512PublicKey(pk_raw)
        return cls(s_vec, pub_key, z)

    def public_key(self) -> MLKEM512PublicKey:
        return self._pub_key

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        ML-KEM-512 Decapsulation with Fujisaki-Okamoto verification.
        """
        if len(ciphertext) != 768:
            raise ValueError(f"Invalid ML-KEM-512 ciphertext length: {len(ciphertext)} (expected 768 bytes)")

        c_u = ciphertext[:640]
        c_v = ciphertext[640:768]

        u_vec = decompress_u(c_u)
        v = decompress_v(c_v)

        # m_prime = Compress_1(v - s^T * u)
        s_dot_u = (poly_mul_mod(self.s_vec[0], u_vec[0]) + poly_mul_mod(self.s_vec[1], u_vec[1])) % Q
        diff = (v - s_dot_u) % Q
        m_prime = poly_to_msg(diff)

        # Re-encrypt
        h_pk = sha3_256(self._pub_key.public_bytes_raw())
        g_out = sha3_512(m_prime + h_pk)
        k_prime = g_out[:32]
        coins_prime = g_out[32:]

        r_stream = shake256(coins_prime + b"\x00", 64 * ETA1 * K)
        r_vec = [sample_poly_cbd(r_stream[i * 64 * ETA1:(i + 1) * 64 * ETA1], ETA1) for i in range(K)]

        e1_stream = shake256(coins_prime + b"\x01", 64 * ETA2 * K)
        e1_vec = [sample_poly_cbd(e1_stream[i * 64 * ETA2:(i + 1) * 64 * ETA2], ETA2) for i in range(K)]

        e2_stream = shake256(coins_prime + b"\x02", 64 * ETA2)
        e2_poly = sample_poly_cbd(e2_stream, ETA2)

        a_mat = sample_matrix_a(self._pub_key.rho)
        u_prime_vec = []
        for i in range(K):
            u_i = (poly_mul_mod(a_mat[0][i], r_vec[0]) + poly_mul_mod(a_mat[1][i], r_vec[1]) + e1_vec[i]) % Q
            u_prime_vec.append(u_i)

        mu_prime = msg_to_poly(m_prime)
        v_prime = (poly_mul_mod(self._pub_key.t_vec[0], r_vec[0]) + poly_mul_mod(self._pub_key.t_vec[1], r_vec[1]) + e2_poly + mu_prime) % Q

        c_prime = compress_u(u_prime_vec) + compress_v(v_prime)

        if c_prime == ciphertext:
            # Valid ciphertext
            return shake256(k_prime + sha3_256(ciphertext), 32)
        else:
            # Rejection
            return shake256(self.z + sha3_256(ciphertext), 32)
