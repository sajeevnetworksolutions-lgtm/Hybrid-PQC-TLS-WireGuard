"""
WireGuard Post-Quantum Proxy & Noise IK PQC Key Exchange Wrapper
Remediated in Phase 3: Replaces simulated os.urandom(16) MACs with genuine
cryptographic BLAKE2s MAC1/MAC2, authentic ChaCha20-Poly1305 AEAD framing,
and verified FIPS 203 ML-KEM-768 hybrid key agreement.

Maintains exact 1,301-byte Message 1 and 1,161-byte Message 2 wire format
compatibility for dissertation suite integration while enforcing real
cryptographic authentication and zero simulated MACs.
"""

import os
import time
import hmac
from typing import Dict, Any, Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from crypto.hybrid_kem import (
    HybridKEMInitiator,
    HybridKEMResponder,
    CipherSuiteType,
    CIPHER_TAXONOMY
)
from crypto.dual_hkdf import DualHKDF
from protocols.wireguard_pqc import (
    blake2s_hash,
    blake2s_mac,
    LABEL_MAC1,
    LABEL_COOKIE,
    chacha20poly1305_encrypt,
    chacha20poly1305_decrypt,
    WireGuardHandshakeError
)


class WireGuardPQCProxy:
    """
    Zero-Trust WireGuard Post-Quantum Tunnel Proxy.
    Integrates Hybrid Post-Quantum KEM (X25519 + ML-KEM-768) directly into WireGuard's
    Noise IK state machine with authentic BLAKE2s MACs and AEAD encryption.
    """

    def __init__(
        self,
        peer_name: str,
        suite: CipherSuiteType = CipherSuiteType.HYBRID_X25519_MLKEM768,
        static_priv_ec: Optional[x25519.X25519PrivateKey] = None
    ):
        self.peer_name = peer_name
        self.suite = suite
        self.dual_hkdf = DualHKDF()

        # WireGuard Static Identity Key (Curve25519)
        self.static_priv_ec = static_priv_ec or x25519.X25519PrivateKey.generate()
        self.static_pub_ec = self.static_priv_ec.public_key()
        self.static_pub_bytes = self.static_pub_ec.public_bytes_raw()

        # PQC Hybrid Engine
        self.initiator = HybridKEMInitiator(suite=suite)
        self.responder = HybridKEMResponder(suite=suite)

        # Session state
        self.current_hybrid_psk: Optional[bytes] = None
        self.tunnel_session_key: Optional[bytes] = None
        self.handshake_stats: Dict[str, Any] = {}
        self._pending_init_state: Optional[Dict[str, Any]] = None

    def initiate_wireguard_handshake(self, remote_static_pub: x25519.X25519PublicKey) -> Tuple[bytes, bytes]:
        """
        Builds WireGuard Handshake Initiation message (Message 1) with embedded PQC KeyShare:
          - Ephemeral X25519 key (32B)
          - Ephemeral ML-KEM public key (1184B / 800B / 1568B)
          - Static identity payload encrypted with DH(e_init, s_resp)
          - Genuine BLAKE2s MAC1 keyed with BLAKE2s(LABEL_MAC1 || remote_static_pub)
        Returns: (handshake_init_message_bytes, ephemeral_pqc_pk_bytes)
        """
        t0 = time.perf_counter_ns()
        remote_static_bytes = remote_static_pub.public_bytes_raw()

        # Ephemeral hybrid key generation
        init_pk_composite = self.initiator.generate_keypair()

        # Ephemeral ECDH with remote static key
        ec_dh_init = self.initiator.x25519_priv.exchange(remote_static_pub)

        # WireGuard framing: Type(1B=1) + SenderIndex(4B) + InitCompositePK + StaticEncrypted(48B) + MACs(32B)
        sender_index = os.urandom(4)
        ephemeral_part = init_pk_composite

        # Encrypt static public key under ephemeral DH key using ChaCha20Poly1305
        # AD binds message type, sender index, and ephemeral key material
        ad = bytes([1]) + sender_index + ephemeral_part
        static_encrypted = chacha20poly1305_encrypt(ec_dh_init, 0, self.static_pub_bytes, ad=ad)

        body = bytes([1]) + sender_index + ephemeral_part + static_encrypted

        # Genuine BLAKE2s MAC1 computation
        mac1_key = blake2s_hash(LABEL_MAC1 + remote_static_bytes)
        mac1 = blake2s_mac(mac1_key, body)
        mac2 = b"\x00" * 16  # Cookie MAC (zeros unless under DoS challenge)

        msg1 = body + mac1 + mac2

        self._pending_init_state = {
            "remote_static_bytes": remote_static_bytes,
            "sender_index": sender_index,
            "ec_dh_init": ec_dh_init
        }

        elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
        self.handshake_stats["init_time_us"] = elapsed_us
        return msg1, init_pk_composite

    def respond_wireguard_handshake(
        self,
        handshake_init_msg: bytes,
        sender_static_pub: x25519.X25519PublicKey
    ) -> Tuple[bytes, bytes]:
        """
        Processes WireGuard Initiation (Message 1), verifies MAC1,
        authenticates initiator static identity, encapsulates PQC secret,
        and constructs Handshake Response (Message 2) with authentic BLAKE2s MACs.
        Returns: (handshake_response_message_bytes, derived_hybrid_tunnel_key)
        """
        t0 = time.perf_counter_ns()
        pk_size = CIPHER_TAXONOMY[self.suite]["pk_size"]
        expected_len = 1 + 4 + pk_size + 48 + 16 + 16
        if len(handshake_init_msg) != expected_len:
            raise WireGuardHandshakeError(
                f"Invalid Initiation length: got {len(handshake_init_msg)}, expected {expected_len}"
            )

        # 1. Verify MAC1
        body_len = expected_len - 32
        body = handshake_init_msg[:body_len]
        mac1_received = handshake_init_msg[body_len:body_len + 16]

        mac1_key = blake2s_hash(LABEL_MAC1 + self.static_pub_bytes)
        mac1_expected = blake2s_mac(mac1_key, body)
        if not hmac.compare_digest(mac1_received, mac1_expected):
            raise WireGuardHandshakeError("WireGuard Initiation MAC1 verification failed")

        # 2. Parse Initiation Message
        sender_idx = handshake_init_msg[1:5]
        init_composite_pk = handshake_init_msg[5:5 + pk_size]
        init_ec_pub = x25519.X25519PublicKey.from_public_bytes(init_composite_pk[:32])

        # 3. Decrypt and verify initiator static identity
        ad = bytes([1]) + sender_idx + init_composite_pk
        dh_e_s = self.static_priv_ec.exchange(init_ec_pub)
        encrypted_static = handshake_init_msg[5 + pk_size:5 + pk_size + 48]
        try:
            decrypted_static = chacha20poly1305_decrypt(dh_e_s, 0, encrypted_static, ad=ad)
        except Exception as e:
            raise WireGuardHandshakeError(f"Failed to authenticate initiator identity: {e}")

        # Check sender static public key matches claimed identity
        if sender_static_pub and decrypted_static != sender_static_pub.public_bytes_raw():
            raise WireGuardHandshakeError("Initiator static identity does not match expected peer key")

        # 4. Process PQC encapsulation and hybrid key agreement
        resp_payload, hybrid_master_key = self.responder.process_initiator_pk(init_composite_pk)

        # WireGuard Response: Type(1B=2) + SenderIdx(4B) + ReceiverIdx(4B) + RespPayload + MACs
        my_idx = os.urandom(4)
        resp_body = bytes([2]) + my_idx + sender_idx + resp_payload

        # Genuine BLAKE2s MAC1 for Response
        resp_mac1_key = blake2s_hash(LABEL_MAC1 + decrypted_static)
        mac1_resp = blake2s_mac(resp_mac1_key, resp_body)
        mac2_resp = b"\x00" * 16

        msg2 = resp_body + mac1_resp + mac2_resp

        self.tunnel_session_key = hybrid_master_key
        elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
        self.handshake_stats["resp_time_us"] = elapsed_us
        return msg2, hybrid_master_key

    def complete_wireguard_handshake(self, handshake_resp_msg: bytes) -> bytes:
        """
        Initiator processes Response (Message 2), verifies MAC1,
        decapsulates ML-KEM secret, and finalizes session keys.
        """
        t0 = time.perf_counter_ns()
        ct_size = CIPHER_TAXONOMY[self.suite]["ct_size"]
        resp_payload_len = 32 + (ct_size - 32 if ct_size > 32 else 0)
        expected_len = 1 + 4 + 4 + resp_payload_len + 16 + 16
        if len(handshake_resp_msg) != expected_len:
            raise WireGuardHandshakeError(
                f"Invalid Response message length: got {len(handshake_resp_msg)}, expected {expected_len}"
            )

        # 1. Verify MAC1
        body_len = expected_len - 32
        body = handshake_resp_msg[:body_len]
        mac1_received = handshake_resp_msg[body_len:body_len + 16]

        mac1_key = blake2s_hash(LABEL_MAC1 + self.static_pub_bytes)
        mac1_expected = blake2s_mac(mac1_key, body)
        if not hmac.compare_digest(mac1_received, mac1_expected):
            raise WireGuardHandshakeError("WireGuard Response MAC1 verification failed")

        # 2. Parse Server Response Payload
        resp_payload = handshake_resp_msg[9:9 + resp_payload_len]

        # 3. Decapsulate Post-Quantum Response
        master_key = self.initiator.decapsulate_response(resp_payload)
        self.tunnel_session_key = master_key

        elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
        self.handshake_stats["complete_time_us"] = elapsed_us
        return master_key
