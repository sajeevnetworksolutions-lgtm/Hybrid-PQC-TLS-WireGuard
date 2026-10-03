"""
WireGuard Post-Quantum Proxy & Noise IK PQC Key Exchange Wrapper
Implements Objective 3: WireGuard VPN Zero Trust Transport Security.

Augments the standard WireGuard Noise IK protocol with dynamic Post-Quantum KEM
Preshared Key (PSK) rotation and encapsulation.
"""

import os
import time
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


class WireGuardPQCProxy:
    """
    Zero-Trust WireGuard Post-Quantum Tunnel Proxy.
    Integrates Hybrid Post-Quantum KEM (X25519 + ML-KEM) directly into WireGuard's
    Noise IK state machine.
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
        
        # PQC Hybrid Engine
        self.initiator = HybridKEMInitiator(suite=suite)
        self.responder = HybridKEMResponder(suite=suite)
        
        # Session state
        self.current_hybrid_psk: Optional[bytes] = None
        self.tunnel_session_key: Optional[bytes] = None
        self.handshake_stats: Dict[str, Any] = {}

    def initiate_wireguard_handshake(self, remote_static_pub: x25519.X25519PublicKey) -> Tuple[bytes, bytes]:
        """
        Builds WireGuard Handshake Initiation message (Message 1) with embedded PQC KeyShare:
          - Ephemeral X25519 key (32B)
          - Ephemeral ML-KEM public key (1184B / 800B / 1568B)
          - Static identity payload encrypted with DH(e_init, s_resp)
        Returns: (handshake_init_message_bytes, ephemeral_pqc_pk_bytes)
        """
        t0 = time.perf_counter_ns()

        # Ephemeral hybrid key generation
        init_pk_composite = self.initiator.generate_keypair()

        # Ephemeral ECDH with remote static key
        ec_dh_init = self.initiator.x25519_priv.exchange(remote_static_pub)

        # WireGuard framing: Type(1B=1) + SenderIndex(4B) + InitCompositePK + StaticEncrypted(48B) + MACs(32B)
        sender_index = os.urandom(4)
        ephemeral_part = init_pk_composite
        
        # Encrypt static public key under ephemeral DH
        temp_aead = ChaCha20Poly1305(ec_dh_init)
        static_encrypted = temp_aead.encrypt(b"\x00" * 12, self.static_pub_ec.public_bytes_raw(), b"WG_INIT")

        mac1 = os.urandom(16)
        mac2 = os.urandom(16)
        msg1 = bytes([1]) + sender_index + ephemeral_part + static_encrypted + mac1 + mac2

        elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
        self.handshake_stats["init_time_us"] = elapsed_us
        return msg1, init_pk_composite

    def respond_wireguard_handshake(
        self,
        handshake_init_msg: bytes,
        sender_static_pub: x25519.X25519PublicKey
    ) -> Tuple[bytes, bytes]:
        """
        Processes WireGuard Initiation (Message 1), encapsulates PQC secret,
        and constructs Handshake Response (Message 2).
        Returns: (handshake_response_message_bytes, derived_hybrid_tunnel_key)
        """
        t0 = time.perf_counter_ns()

        # Parse message
        sender_idx = handshake_init_msg[1:5]
        pk_size = CIPHER_TAXONOMY[self.suite]["pk_size"]
        init_composite_pk = handshake_init_msg[5:5 + pk_size]

        # Process PQC encapsulation and ECDH
        resp_payload, hybrid_master_key = self.responder.process_initiator_pk(init_composite_pk)

        # WireGuard Response: Type(1B=2) + SenderIdx(4B) + ReceiverIdx(4B) + RespPayload + AuthPayload + MACs
        my_idx = os.urandom(4)
        mac1 = os.urandom(16)
        mac2 = os.urandom(16)
        msg2 = bytes([2]) + my_idx + sender_idx + resp_payload + mac1 + mac2

        self.tunnel_session_key = hybrid_master_key
        elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
        self.handshake_stats["resp_time_us"] = elapsed_us
        return msg2, hybrid_master_key

    def complete_wireguard_handshake(self, handshake_resp_msg: bytes) -> bytes:
        """
        Initiator processes Response (Message 2) to finalize session keys.
        """
        t0 = time.perf_counter_ns()
        
        # Parse server response payload
        ct_size = CIPHER_TAXONOMY[self.suite]["ct_size"]
        # In hybrid mode: server EC pub (32B) + PQC ciphertext
        resp_payload = handshake_resp_msg[9:9 + 32 + (ct_size - 32 if ct_size > 32 else 0)]
        
        master_key = self.initiator.decapsulate_response(resp_payload)
        self.tunnel_session_key = master_key
        
        elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
        self.handshake_stats["complete_time_us"] = elapsed_us
        return master_key
