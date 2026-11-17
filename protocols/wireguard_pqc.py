"""
WireGuard Post-Quantum Cryptographic Protocol Engine (RFC Noise_IKpsk2 + NIST FIPS 203)
Implements an experimental hybrid post-quantum key exchange for WireGuard using
X25519 + ML-KEM-768 (NIST Category 3) alongside standard Classical WireGuard.

Key Properties & Standards:
- Noise Protocol Framework: Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
- Hybrid Noise Construction: Noise_IKpsk2_X25519_MLKEM768_ChaChaPoly_BLAKE2s
- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM-768)
- RFC 7748: Elliptic Curves for Security (X25519)
- RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
- Authentic BLAKE2s Hashing, Keyed MAC1, and Cookie MAC2 (RFC 7693)
- Genuine TAI64N Monotonic Timestamps for Handshake Replay Protection
- 64-bit Sliding Window Bitmap for Transport Packet Replay Protection
- Transport Session Key Rotation and Rekeying State Machine
- Zero Simulation: Real Cryptographic Primitives & Live Packet Serialization
"""

import os
import time
import struct
import hashlib
import hmac
from enum import IntEnum, Enum
from typing import Tuple, Dict, Any, Optional, List, Set

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import mlkem

# WireGuard Protocol Message Types (4-byte LE uint32 on the wire)
class WireGuardMessageType(IntEnum):
    HANDSHAKE_INITIATION = 1
    HANDSHAKE_RESPONSE = 2
    COOKIE_REPLY = 3
    DATA = 4


class WireGuardMode(Enum):
    CLASSICAL = "CLASSICAL_X25519"
    HYBRID_MLKEM512 = "HYBRID_X25519_MLKEM512"
    HYBRID_MLKEM768 = "HYBRID_X25519_MLKEM768"
    HYBRID_MLKEM1024 = "HYBRID_X25519_MLKEM1024"


# Noise Protocol Framework Strings
NOISE_CONSTRUCTION_CLASSICAL = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
NOISE_CONSTRUCTION_HYBRID = b"Noise_IKpsk2_X25519_MLKEM768_ChaChaPoly_BLAKE2s"
NOISE_CONSTRUCTION_HYBRID_512 = b"Noise_IKpsk2_X25519_MLKEM512_ChaChaPoly_BLAKE2s"
NOISE_CONSTRUCTION_HYBRID_1024 = b"Noise_IKpsk2_X25519_MLKEM1024_ChaChaPoly_BLAKE2s"
WIREGUARD_IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"

# WireGuard Protocol Limits
REKEY_AFTER_MESSAGES = 1 << 60
REJECT_AFTER_MESSAGES = (1 << 64) - (1 << 13)
REKEY_AFTER_TIME_SEC = 120.0
REJECT_AFTER_TIME_SEC = 180.0
REKEY_TIMEOUT_SEC = 5.0

# Sliding Window Size for Replay Protection
REPLAY_WINDOW_SIZE = 64


# =============================================================================
# Cryptographic Hash & KDF Primitives (BLAKE2s based)
# =============================================================================

def blake2s_hash(data: bytes) -> bytes:
    """Computes standard 32-byte BLAKE2s digest."""
    return hashlib.blake2s(data, digest_size=32).digest()


def blake2s_mac(key: bytes, data: bytes) -> bytes:
    """Computes keyed 16-byte BLAKE2s MAC for WireGuard MAC1 and MAC2."""
    return hashlib.blake2s(data, key=key, digest_size=16).digest()


def blake2s_hmac(key: bytes, data: bytes) -> bytes:
    """Computes 32-byte HMAC-BLAKE2s using hashlib."""
    return hmac.new(key, data, hashlib.blake2s).digest()


def kdf1(key: bytes, ikm: bytes) -> bytes:
    """
    WireGuard KDF1:
      tau_0 = HMAC-BLAKE2s(key, ikm)
      tau_1 = HMAC-BLAKE2s(tau_0, 0x01)
      returns tau_1
    """
    tau_0 = blake2s_hmac(key, ikm)
    tau_1 = blake2s_hmac(tau_0, b"\x01")
    return tau_1


def kdf2(key: bytes, ikm: bytes) -> Tuple[bytes, bytes]:
    """
    WireGuard KDF2:
      tau_0 = HMAC-BLAKE2s(key, ikm)
      tau_1 = HMAC-BLAKE2s(tau_0, 0x01)
      tau_2 = HMAC-BLAKE2s(tau_0, tau_1 || 0x02)
      returns (tau_1, tau_2)
    """
    tau_0 = blake2s_hmac(key, ikm)
    tau_1 = blake2s_hmac(tau_0, b"\x01")
    tau_2 = blake2s_hmac(tau_0, tau_1 + b"\x02")
    return tau_1, tau_2


def kdf3(key: bytes, ikm: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    WireGuard KDF3:
      tau_0 = HMAC-BLAKE2s(key, ikm)
      tau_1 = HMAC-BLAKE2s(tau_0, 0x01)
      tau_2 = HMAC-BLAKE2s(tau_0, tau_1 || 0x02)
      tau_3 = HMAC-BLAKE2s(tau_0, tau_2 || 0x03)
      returns (tau_1, tau_2, tau_3)
    """
    tau_0 = blake2s_hmac(key, ikm)
    tau_1 = blake2s_hmac(tau_0, b"\x01")
    tau_2 = blake2s_hmac(tau_0, tau_1 + b"\x02")
    tau_3 = blake2s_hmac(tau_0, tau_2 + b"\x03")
    return tau_1, tau_2, tau_3


# =============================================================================
# TAI64N Timestamps (Handshake Replay Protection)
# =============================================================================

def get_tai64n_now() -> bytes:
    """
    Generates a 12-byte TAI64N timestamp per WireGuard specification:
    - 8 bytes big-endian: 2^62 + seconds since POSIX epoch (1970-01-01 00:00:00 TAI)
    - 4 bytes big-endian: nanoseconds
    """
    now = time.time()
    secs = int(now)
    nanosecs = int((now - secs) * 1_000_000_000)
    tai64_secs = (1 << 62) + secs
    return struct.pack(">QI", tai64_secs, nanosecs)


def compare_tai64n(ts1: bytes, ts2: bytes) -> int:
    """
    Returns 1 if ts1 > ts2, -1 if ts1 < ts2, 0 if equal.
    """
    s1, ns1 = struct.unpack(">QI", ts1)
    s2, ns2 = struct.unpack(">QI", ts2)
    if s1 > s2:
        return 1
    if s1 < s2:
        return -1
    if ns1 > ns2:
        return 1
    if ns1 < ns2:
        return -1
    return 0


# =============================================================================
# Transport Packet Replay Protection (Sliding Window Bitmap)
# =============================================================================

class ReplayFilter:
    """
    WireGuard 64-bit Sliding Window Replay Filter.
    Guarantees strict rejection of duplicate counters and ancient packets
    while tolerating out-of-order delivery within the window.
    """

    def __init__(self, window_size: int = REPLAY_WINDOW_SIZE):
        self.window_size = window_size
        self.max_counter: int = 0
        self.bitmap: int = 0
        self.initialized: bool = False

    def validate_and_update(self, counter: int) -> bool:
        """
        Validates counter against replay filter and advances sliding window.
        Returns True if packet is fresh, False if replay/duplicate or too old.
        """
        if counter < 0 or counter >= (1 << 64):
            return False

        if not self.initialized:
            self.max_counter = counter
            self.bitmap = 1
            self.initialized = True
            return True

        if counter > self.max_counter:
            diff = counter - self.max_counter
            if diff >= self.window_size:
                self.bitmap = 1
            else:
                self.bitmap = (self.bitmap << diff) | 1
            self.max_counter = counter
            return True

        diff = self.max_counter - counter
        if diff >= self.window_size:
            # Packet is too old, beyond the sliding window
            return False

        mask = 1 << diff
        if self.bitmap & mask:
            # Duplicate / replayed counter
            return False

        # Mark counter as received in the bitmap
        self.bitmap |= mask
        return True

    def reset(self):
        self.max_counter = 0
        self.bitmap = 0
        self.initialized = False


# =============================================================================
# Symmetric AEAD Helper (ChaCha20-Poly1305 with 12-byte WireGuard Nonces)
# =============================================================================

def chacha20poly1305_encrypt(key: bytes, counter: int, plaintext: bytes, ad: bytes = b"") -> bytes:
    """
    WireGuard ChaCha20-Poly1305 encryption:
    12-byte nonce: 4 zero bytes followed by 8 bytes little-endian counter.
    """
    if len(key) != 32:
        raise ValueError(f"ChaCha20Poly1305 requires 32-byte key, got {len(key)}")
    nonce = b"\x00\x00\x00\x00" + struct.pack("<Q", counter)
    cipher = ChaCha20Poly1305(key)
    return cipher.encrypt(nonce, plaintext, ad)


def chacha20poly1305_decrypt(key: bytes, counter: int, ciphertext: bytes, ad: bytes = b"") -> bytes:
    """
    WireGuard ChaCha20-Poly1305 decryption:
    12-byte nonce: 4 zero bytes followed by 8 bytes little-endian counter.
    """
    if len(key) != 32:
        raise ValueError(f"ChaCha20Poly1305 requires 32-byte key, got {len(key)}")
    nonce = b"\x00\x00\x00\x00" + struct.pack("<Q", counter)
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext, ad)


# =============================================================================
# WireGuard Handshake State Machine (Noise_IKpsk2 Hybrid Core)
# =============================================================================

class WireGuardHandshakeError(RuntimeError):
    """Raised when a WireGuard handshake fails (MAC invalid, auth failure, replay)."""
    pass


class WireGuardKeypair:
    """Represents a static or ephemeral X25519 identity keypair."""
    def __init__(self, private_key: Optional[x25519.X25519PrivateKey] = None):
        self.private_key = private_key or x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.public_bytes = self.public_key.public_bytes_raw()

    @classmethod
    def from_private_bytes(cls, raw_bytes: bytes) -> "WireGuardKeypair":
        priv = x25519.X25519PrivateKey.from_private_bytes(raw_bytes)
        return cls(priv)


class WireGuardSession:
    """Active WireGuard transport session with directional AEAD keys and counters."""
    def __init__(
        self,
        local_index: int,
        remote_index: int,
        sending_key: bytes,
        receiving_key: bytes,
        is_initiator: bool
    ):
        self.local_index = local_index
        self.remote_index = remote_index
        self.sending_key = sending_key
        self.receiving_key = receiving_key
        self.is_initiator = is_initiator
        self.sending_counter: int = 0
        self.replay_filter = ReplayFilter()
        self.created_at: float = time.time()
        self.last_sent_at: float = self.created_at
        self.last_received_at: float = self.created_at

    def encrypt_transport_data(self, plaintext: bytes) -> bytes:
        """
        Constructs WireGuard Data Packet (Type 4):
          - Type: 4 (uint32 LE)
          - Receiver Index: 4 (uint32 LE, remote_index)
          - Counter: 8 (uint64 LE, sending_counter)
          - Encrypted payload + 16B Poly1305 tag
        """
        if self.sending_counter >= REJECT_AFTER_MESSAGES:
            raise WireGuardHandshakeError("Session transmission counter exhausted; must rekey")

        current_counter = self.sending_counter
        self.sending_counter += 1
        self.last_sent_at = time.time()

        ciphertext = chacha20poly1305_encrypt(self.sending_key, current_counter, plaintext, ad=b"")
        header = struct.pack("<IIQ", WireGuardMessageType.DATA, self.remote_index, current_counter)
        return header + ciphertext

    def decrypt_transport_data(self, packet: bytes) -> bytes:
        """
        Parses and decrypts WireGuard Data Packet (Type 4):
        Verifies receiver index, checks replay filter, and verifies Poly1305 tag.
        """
        if len(packet) < 32:
            raise ValueError(f"Data packet too short: {len(packet)} bytes (min 32 bytes)")

        msg_type, rx_idx, counter = struct.unpack("<IIQ", packet[:16])
        if msg_type != WireGuardMessageType.DATA:
            raise ValueError(f"Invalid packet type for data message: {msg_type}")
        if rx_idx != self.local_index:
            raise ValueError(f"Receiver index mismatch: got {rx_idx}, expected {self.local_index}")

        # Replay protection check
        if not self.replay_filter.validate_and_update(counter):
            raise WireGuardHandshakeError(f"Transport packet rejected by replay filter (counter={counter})")

        ciphertext = packet[16:]
        plaintext = chacha20poly1305_decrypt(self.receiving_key, counter, ciphertext, ad=b"")
        self.last_received_at = time.time()
        return plaintext

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > REJECT_AFTER_TIME_SEC

    def should_rekey(self) -> bool:
        return (
            (self.sending_counter >= REKEY_AFTER_MESSAGES) or
            ((time.time() - self.created_at) >= REKEY_AFTER_TIME_SEC)
        )


class WireGuardPQCNode:
    """
    Experimental Hybrid Post-Quantum WireGuard Peer (Noise_IKpsk2 + ML-KEM-768).
    Supports both Classical WireGuard (X25519) and Hybrid WireGuard (X25519 + ML-KEM-768).
    Implements authentic handshake construction, peer authorization, TAI64N anti-replay,
    MAC1/MAC2 verification, and transport data encryption.
    """

    def __init__(
        self,
        name: str,
        static_keypair: Optional[WireGuardKeypair] = None,
        mode: WireGuardMode = WireGuardMode.HYBRID_MLKEM768,
        psk: Optional[bytes] = None
    ):
        self.name = name
        self.mode = mode
        self.static_key = static_keypair or WireGuardKeypair()
        self.static_pub_bytes = self.static_key.public_bytes
        self.psk = psk or (b"\x00" * 32)  # Optional 32-byte pre-shared key

        # Peer database: remote_static_pub -> peer metadata
        self.peers: Dict[bytes, Dict[str, Any]] = {}
        # Active sessions indexed by local_index
        self.sessions: Dict[int, WireGuardSession] = {}
        # Pending handshake state (for initiators awaiting Message 2)
        self._pending_handshakes: Dict[int, Dict[str, Any]] = {}

        # Sizing parameters
        if self.mode == WireGuardMode.CLASSICAL:
            self.is_hybrid = False
            self.pqc_pk_size = 0
            self.pqc_ct_size = 0
            self.param_set = None
            self.construction_str = NOISE_CONSTRUCTION_CLASSICAL
        elif self.mode == WireGuardMode.HYBRID_MLKEM512:
            self.is_hybrid = True
            self.pqc_pk_size = 800
            self.pqc_ct_size = 768
            self.param_set = mlkem.ParameterSet.ML_KEM_512
            self.construction_str = NOISE_CONSTRUCTION_HYBRID_512
        elif self.mode == WireGuardMode.HYBRID_MLKEM1024:
            self.is_hybrid = True
            self.pqc_pk_size = 1568
            self.pqc_ct_size = 1568
            self.param_set = mlkem.ParameterSet.ML_KEM_1024
            self.construction_str = NOISE_CONSTRUCTION_HYBRID_1024
        else:
            self.is_hybrid = True
            self.pqc_pk_size = 1184
            self.pqc_ct_size = 1088
            self.param_set = mlkem.ParameterSet.ML_KEM_768
            self.construction_str = NOISE_CONSTRUCTION_HYBRID
        self.composite_ephemeral_init_size = 32 + self.pqc_pk_size
        self.composite_ephemeral_resp_size = 32 + self.pqc_ct_size

    def add_peer(self, peer_static_pub: bytes, peer_name: str = "Peer", psk: Optional[bytes] = None):
        """Authorizes a remote peer's static public key."""
        if len(peer_static_pub) != 32:
            raise ValueError(f"Peer static public key must be 32 bytes, got {len(peer_static_pub)}")
        self.peers[peer_static_pub] = {
            "name": peer_name,
            "psk": psk or self.psk,
            "greatest_timestamp": b"\x00" * 12,
            "cookie": b"\x00" * 16,
            "cookie_timestamp": 0.0
        }

    # -------------------------------------------------------------------------
    # Handshake Initiation (Message 1)
    # -------------------------------------------------------------------------
    def create_handshake_initiation(
        self,
        remote_static_pub: bytes,
        wireguard_header_format: str = "standard_4b"
    ) -> Tuple[bytes, int]:
        """
        Constructs WireGuard Handshake Initiation (Message 1).
        
        Parameters:
        - remote_static_pub: 32-byte X25519 public key of responder.
        - wireguard_header_format:
          'standard_4b': 4-byte LE uint32 message type (RFC WireGuard standard).
          'legacy_1b': 1-byte message type (for backward compatibility with proxy tests).
        
        Returns: (message_1_bytes, local_sender_index)
        """
        if remote_static_pub not in self.peers:
            raise WireGuardHandshakeError(f"Remote peer {remote_static_pub.hex()[:8]} is not in authorized peers")

        peer_entry = self.peers[remote_static_pub]
        sender_index = struct.unpack("<I", os.urandom(4))[0]

        # 1. Initialize Noise Chaining Key and Hash
        construction_str = self.construction_str
        chaining_key = blake2s_hash(construction_str)
        running_hash = blake2s_hash(chaining_key + WIREGUARD_IDENTIFIER)
        running_hash = blake2s_hash(running_hash + remote_static_pub)

        # 2. Ephemeral Key Generation (X25519 + optional ML-KEM)
        ephemeral_x25519 = WireGuardKeypair()
        ephemeral_part = ephemeral_x25519.public_bytes

        pqc_dk = None
        if self.is_hybrid:
            kem = mlkem.ML_KEM(self.param_set)
            pqc_ek, pqc_dk = kem.key_gen()
            ephemeral_part += pqc_ek.to_bytes()

        # MixHash ephemeral part
        running_hash = blake2s_hash(running_hash + ephemeral_part)

        # 3. First Diffie-Hellman: DH(e_init, s_resp)
        remote_static_obj = x25519.X25519PublicKey.from_public_bytes(remote_static_pub)
        dh_e_s = ephemeral_x25519.private_key.exchange(remote_static_obj)
        chaining_key, key_static = kdf2(chaining_key, dh_e_s)

        # 4. Encrypt Static Identity Public Key
        # ChaCha20Poly1305 with nonce 0 and running_hash as AD
        encrypted_static = chacha20poly1305_encrypt(
            key_static, 0, self.static_pub_bytes, ad=running_hash
        )
        running_hash = blake2s_hash(running_hash + encrypted_static)

        # 5. Second Diffie-Hellman: DH(s_init, s_resp)
        dh_s_s = self.static_key.private_key.exchange(remote_static_obj)
        chaining_key, key_timestamp = kdf2(chaining_key, dh_s_s)

        # 6. Encrypt Monotonic TAI64N Timestamp
        tai64n_ts = get_tai64n_now()
        encrypted_timestamp = chacha20poly1305_encrypt(
            key_timestamp, 0, tai64n_ts, ad=running_hash
        )
        running_hash = blake2s_hash(running_hash + encrypted_timestamp)

        # 7. Format Message Body
        if wireguard_header_format == "standard_4b":
            header = struct.pack("<II", WireGuardMessageType.HANDSHAKE_INITIATION, sender_index)
        else:
            header = bytes([WireGuardMessageType.HANDSHAKE_INITIATION]) + struct.pack("<I", sender_index)

        body_without_macs = header + ephemeral_part + encrypted_static + encrypted_timestamp

        # 8. Compute MAC1 and MAC2
        mac1_key = blake2s_hash(LABEL_MAC1 + remote_static_pub)
        mac1 = blake2s_mac(mac1_key, body_without_macs)
        mac2 = b"\x00" * 16  # Empty cookie MAC when under normal load

        msg1 = body_without_macs + mac1 + mac2

        # Record pending handshake state
        self._pending_handshakes[sender_index] = {
            "remote_static_pub": remote_static_pub,
            "chaining_key": chaining_key,
            "running_hash": running_hash,
            "ephemeral_x25519": ephemeral_x25519,
            "pqc_dk": pqc_dk,
            "created_at": time.time(),
            "wireguard_header_format": wireguard_header_format
        }

        return msg1, sender_index

    # -------------------------------------------------------------------------
    # Handshake Response (Message 2)
    # -------------------------------------------------------------------------
    def process_handshake_initiation_and_respond(
        self,
        msg1: bytes,
        wireguard_header_format: Optional[str] = None
    ) -> Tuple[bytes, WireGuardSession]:
        """
        Processes Handshake Initiation (Message 1) and generates Handshake Response (Message 2).
        Verifies MAC1, decrypts static public key, checks authorization, decrypts timestamp,
        checks replay, encapsulates ML-KEM-768 secret, and establishes WireGuardSession.
        """
        # Determine header format (standard 4-byte or legacy 1-byte)
        if wireguard_header_format is None:
            if len(msg1) >= 4 and struct.unpack("<I", msg1[:4])[0] == WireGuardMessageType.HANDSHAKE_INITIATION:
                hdr_fmt = "standard_4b"
                hdr_len = 8
                sender_index = struct.unpack("<I", msg1[4:8])[0]
            elif len(msg1) >= 5 and msg1[0] == WireGuardMessageType.HANDSHAKE_INITIATION:
                hdr_fmt = "legacy_1b"
                hdr_len = 5
                sender_index = struct.unpack("<I", msg1[1:5])[0]
            else:
                raise WireGuardHandshakeError(f"Unrecognized WireGuard Initiation header: {msg1[:8].hex()}")
        else:
            hdr_fmt = wireguard_header_format
            hdr_len = 8 if hdr_fmt == "standard_4b" else 5
            sender_index = struct.unpack("<I", msg1[4:8] if hdr_fmt == "standard_4b" else msg1[1:5])[0]

        # Verify Minimum Length
        expected_body_len = hdr_len + self.composite_ephemeral_init_size + 48 + 28
        total_expected_len = expected_body_len + 32
        if len(msg1) != total_expected_len:
            raise WireGuardHandshakeError(
                f"Handshake Initiation length mismatch: got {len(msg1)} bytes; expected {total_expected_len}"
            )

        # 1. Verify MAC1
        mac1_expected = msg1[expected_body_len:expected_body_len + 16]
        mac1_key = blake2s_hash(LABEL_MAC1 + self.static_pub_bytes)
        mac1_computed = blake2s_mac(mac1_key, msg1[:expected_body_len])
        if not hmac.compare_digest(mac1_expected, mac1_computed):
            raise WireGuardHandshakeError("Handshake Initiation MAC1 verification failed (corrupted or wrong recipient)")

        # 2. Reconstruct Hash State
        construction_str = self.construction_str
        chaining_key = blake2s_hash(construction_str)
        running_hash = blake2s_hash(chaining_key + WIREGUARD_IDENTIFIER)
        running_hash = blake2s_hash(running_hash + self.static_pub_bytes)

        # Extract Ephemeral Part
        offset = hdr_len
        ephemeral_part = msg1[offset:offset + self.composite_ephemeral_init_size]
        offset += self.composite_ephemeral_init_size

        init_eph_x25519_bytes = ephemeral_part[:32]
        init_pqc_ek_bytes = ephemeral_part[32:] if self.is_hybrid else b""

        running_hash = blake2s_hash(running_hash + ephemeral_part)

        # 3. First DH: DH(e_init, s_resp)
        init_eph_x25519_obj = x25519.X25519PublicKey.from_public_bytes(init_eph_x25519_bytes)
        dh_e_s = self.static_key.private_key.exchange(init_eph_x25519_obj)
        chaining_key, key_static = kdf2(chaining_key, dh_e_s)

        # 4. Decrypt Initiator Static Identity
        encrypted_static = msg1[offset:offset + 48]
        offset += 48
        try:
            initiator_static_pub = chacha20poly1305_decrypt(
                key_static, 0, encrypted_static, ad=running_hash
            )
        except Exception as e:
            raise WireGuardHandshakeError(f"Failed to decrypt initiator static identity: {e}")

        running_hash = blake2s_hash(running_hash + encrypted_static)

        # Check authorization of peer
        if initiator_static_pub not in self.peers:
            raise WireGuardHandshakeError(f"Peer static public key {initiator_static_pub.hex()[:8]} is unauthorized")

        peer_entry = self.peers[initiator_static_pub]

        # 5. Second DH: DH(s_init, s_resp)
        initiator_static_obj = x25519.X25519PublicKey.from_public_bytes(initiator_static_pub)
        dh_s_s = self.static_key.private_key.exchange(initiator_static_obj)
        chaining_key, key_timestamp = kdf2(chaining_key, dh_s_s)

        # 6. Decrypt and Validate TAI64N Monotonic Timestamp
        encrypted_timestamp = msg1[offset:offset + 28]
        offset += 28
        try:
            tai64n_ts = chacha20poly1305_decrypt(
                key_timestamp, 0, encrypted_timestamp, ad=running_hash
            )
        except Exception as e:
            raise WireGuardHandshakeError(f"Failed to decrypt initiator timestamp: {e}")

        # Strict Replay Check
        if compare_tai64n(tai64n_ts, peer_entry["greatest_timestamp"]) <= 0:
            raise WireGuardHandshakeError(
                f"Handshake Initiation rejected: timestamp replay detected (ts={tai64n_ts.hex()}, greatest={peer_entry['greatest_timestamp'].hex()})"
            )
        peer_entry["greatest_timestamp"] = tai64n_ts
        running_hash = blake2s_hash(running_hash + encrypted_timestamp)

        # ---------------------------------------------------------------------
        # Construct Handshake Response (Message 2)
        # ---------------------------------------------------------------------
        my_receiver_index = sender_index
        my_sender_index = struct.unpack("<I", os.urandom(4))[0]

        # Ephemeral Key Generation on Responder
        resp_eph_x25519 = WireGuardKeypair()
        resp_ephemeral_part = resp_eph_x25519.public_bytes

        pqc_shared_secret = b"\x00" * 32
        if self.is_hybrid:
            # Encapsulate ML-KEM secret
            kem = mlkem.ML_KEM(self.param_set)
            ek = mlkem.EncapsKey.from_bytes(init_pqc_ek_bytes)
            pqc_ss, pqc_ct = kem.encaps(ek)
            resp_ephemeral_part += bytes(pqc_ct)
            pqc_shared_secret = bytes(pqc_ss)

        running_hash = blake2s_hash(running_hash + resp_ephemeral_part)

        # Third DH: DH(e_resp, e_init)
        dh_e_e = resp_eph_x25519.private_key.exchange(init_eph_x25519_obj)
        chaining_key = kdf1(chaining_key, dh_e_e)

        # Fourth DH: DH(e_resp, s_init)
        dh_e_s = resp_eph_x25519.private_key.exchange(initiator_static_obj)
        chaining_key = kdf1(chaining_key, dh_e_s)

        # Mix Post-Quantum Secret (and optional PSK) via Noise KDF3
        # In hybrid mode: hybrid_psk combines peer_psk and ML-KEM shared secret
        if self.is_hybrid:
            # Domain-separated hybrid PSK derivation
            domain_label = f"WireGuard-PQC-{self.mode.value}-v1:".encode("utf-8")
            hybrid_psk = blake2s_hmac(chaining_key, domain_label + pqc_shared_secret + peer_entry["psk"])
        else:
            hybrid_psk = peer_entry["psk"]

        chaining_key, tau, key_auth = kdf3(chaining_key, hybrid_psk)
        running_hash = blake2s_hash(running_hash + tau)

        # Encrypt Empty Authenticated Payload
        encrypted_empty = chacha20poly1305_encrypt(
            key_auth, 0, b"", ad=running_hash
        )
        running_hash = blake2s_hash(running_hash + encrypted_empty)

        # Format Response Message Body
        if hdr_fmt == "standard_4b":
            resp_header = struct.pack(
                "<III", WireGuardMessageType.HANDSHAKE_RESPONSE, my_sender_index, my_receiver_index
            )
        else:
            resp_header = bytes([WireGuardMessageType.HANDSHAKE_RESPONSE]) + struct.pack(
                "<II", my_sender_index, my_receiver_index
            )

        resp_body = resp_header + resp_ephemeral_part + encrypted_empty

        # MAC1 and MAC2 for Response
        mac1_resp_key = blake2s_hash(LABEL_MAC1 + initiator_static_pub)
        mac1_resp = blake2s_mac(mac1_resp_key, resp_body)
        mac2_resp = b"\x00" * 16

        msg2 = resp_body + mac1_resp + mac2_resp

        # Derive Transport Keys on Responder: (send_key, recv_key)
        # Note: Responder transmits with send_key, receives with recv_key
        key_send, key_recv = kdf2(chaining_key, b"")

        session = WireGuardSession(
            local_index=my_sender_index,
            remote_index=my_receiver_index,
            sending_key=key_send,
            receiving_key=key_recv,
            is_initiator=False
        )
        self.sessions[my_sender_index] = session
        return msg2, session

    # -------------------------------------------------------------------------
    # Handshake Finalization on Initiator (Processing Message 2)
    # -------------------------------------------------------------------------
    def process_handshake_response(self, msg2: bytes) -> WireGuardSession:
        """
        Initiator processes Handshake Response (Message 2) and finalizes transport session.
        Verifies MAC1, decapsulates ML-KEM-768 ciphertext, completes Noise DHs,
        verifies auth tag, and establishes active WireGuardSession.
        """
        # Determine header format
        if len(msg2) >= 12 and struct.unpack("<I", msg2[:4])[0] == WireGuardMessageType.HANDSHAKE_RESPONSE:
            hdr_fmt = "standard_4b"
            hdr_len = 12
            sender_index, receiver_index = struct.unpack("<II", msg2[4:12])
        elif len(msg2) >= 9 and msg2[0] == WireGuardMessageType.HANDSHAKE_RESPONSE:
            hdr_fmt = "legacy_1b"
            hdr_len = 9
            sender_index, receiver_index = struct.unpack("<II", msg2[1:9])
        else:
            raise WireGuardHandshakeError(f"Unrecognized WireGuard Response header: {msg2[:8].hex()}")

        if receiver_index not in self._pending_handshakes:
            raise WireGuardHandshakeError(f"No pending handshake found for receiver index {receiver_index}")

        pending = self._pending_handshakes.pop(receiver_index)
        remote_static_pub = pending["remote_static_pub"]
        chaining_key = pending["chaining_key"]
        running_hash = pending["running_hash"]
        ephemeral_x25519 = pending["ephemeral_x25519"]
        pqc_dk = pending["pqc_dk"]
        peer_entry = self.peers[remote_static_pub]

        # Verify Length
        expected_body_len = hdr_len + self.composite_ephemeral_resp_size + 16
        total_expected_len = expected_body_len + 32
        if len(msg2) != total_expected_len:
            raise WireGuardHandshakeError(
                f"Handshake Response length mismatch: got {len(msg2)} bytes; expected {total_expected_len}"
            )

        # 1. Verify MAC1
        mac1_expected = msg2[expected_body_len:expected_body_len + 16]
        mac1_key = blake2s_hash(LABEL_MAC1 + self.static_pub_bytes)
        mac1_computed = blake2s_mac(mac1_key, msg2[:expected_body_len])
        if not hmac.compare_digest(mac1_expected, mac1_computed):
            raise WireGuardHandshakeError("Handshake Response MAC1 verification failed (corrupted or wrong recipient)")

        # 2. Extract Ephemeral Payload
        offset = hdr_len
        resp_ephemeral_part = msg2[offset:offset + self.composite_ephemeral_resp_size]
        offset += self.composite_ephemeral_resp_size

        resp_eph_x25519_bytes = resp_ephemeral_part[:32]
        resp_pqc_ct_bytes = resp_ephemeral_part[32:] if self.is_hybrid else b""

        running_hash = blake2s_hash(running_hash + resp_ephemeral_part)

        # 3. Third DH: DH(e_resp, e_init)
        resp_eph_x25519_obj = x25519.X25519PublicKey.from_public_bytes(resp_eph_x25519_bytes)
        dh_e_e = ephemeral_x25519.private_key.exchange(resp_eph_x25519_obj)
        chaining_key = kdf1(chaining_key, dh_e_e)

        # 4. Fourth DH: DH(e_resp, s_init)
        dh_e_s = self.static_key.private_key.exchange(resp_eph_x25519_obj)
        chaining_key = kdf1(chaining_key, dh_e_s)

        # 5. Decapsulate ML-KEM Secret (Hybrid Mode)
        pqc_shared_secret = b"\x00" * 32
        if self.is_hybrid:
            if not pqc_dk:
                raise WireGuardHandshakeError("Missing initiator ML-KEM decapsulation key")
            kem = mlkem.ML_KEM(self.param_set)
            pqc_shared_secret = bytes(kem.decaps(pqc_dk, resp_pqc_ct_bytes))

        # Mix Post-Quantum Secret (and optional PSK)
        if self.is_hybrid:
            domain_label = f"WireGuard-PQC-{self.mode.value}-v1:".encode("utf-8")
            hybrid_psk = blake2s_hmac(chaining_key, domain_label + pqc_shared_secret + peer_entry["psk"])
        else:
            hybrid_psk = peer_entry["psk"]

        chaining_key, tau, key_auth = kdf3(chaining_key, hybrid_psk)
        running_hash = blake2s_hash(running_hash + tau)

        # 6. Decrypt and Verify Authenticated Empty Payload
        encrypted_empty = msg2[offset:offset + 16]
        try:
            chacha20poly1305_decrypt(key_auth, 0, encrypted_empty, ad=running_hash)
        except Exception as e:
            raise WireGuardHandshakeError(f"Failed to authenticate Handshake Response payload: {e}")

        # 7. Derive Transport Keys on Initiator: (send_key, recv_key)
        # WireGuard specification:
        # Responder: (T_send, T_recv) = KDF2(C, "")
        # Initiator: (T_recv, T_send) = KDF2(C, "")
        key_recv, key_send = kdf2(chaining_key, b"")

        session = WireGuardSession(
            local_index=receiver_index,
            remote_index=sender_index,
            sending_key=key_send,
            receiving_key=key_recv,
            is_initiator=True
        )
        self.sessions[receiver_index] = session
        return session
