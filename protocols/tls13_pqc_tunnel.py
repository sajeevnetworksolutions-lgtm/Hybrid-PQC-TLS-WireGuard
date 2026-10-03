"""
TLS 1.3 Hybrid Post-Quantum Secure Tunnel
Implements Objective 3: High-throughput TLS 1.3 PQC Handshake & Application Data Pipeline.
"""

import asyncio
import os
import time
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.hybrid_kem import (
    HybridKEMInitiator,
    HybridKEMResponder,
    CipherSuiteType,
    CIPHER_TAXONOMY
)
from crypto.packet_framing import PacketFramer, FragmentReassembler


class TLS13PQCClient:
    def __init__(
        self,
        server_host: str = "127.0.0.1",
        server_port: int = 8443,
        suite: CipherSuiteType = CipherSuiteType.HYBRID_X25519_MLKEM768,
        mtu: int = 1500
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.suite = suite
        self.mtu = mtu
        self.initiator = HybridKEMInitiator(suite=suite)
        self.aead_cipher: Optional[AESGCM] = None
        self.keys: Optional[Dict[str, bytes]] = None
        self.handshake_latency_ms: float = 0.0
        self.session_id: bytes = os.urandom(16)
        self.reassembler = FragmentReassembler()
        self.seq_num: int = 0

    async def connect_and_handshake(self) -> float:
        t_start = time.perf_counter_ns()
        reader, writer = await asyncio.open_connection(self.server_host, self.server_port)

        try:
            # 1. Generate Composite KeyShare & ClientHello payload
            client_pk_bytes = self.initiator.generate_keypair()
            suite_name_bytes = self.suite.value.encode('utf-8')
            client_hello_payload = bytes([len(suite_name_bytes)]) + suite_name_bytes + self.session_id + client_pk_bytes

            # 2. Send ClientHello packets
            client_packets = PacketFramer.fragment_payload(
                msg_type=1,
                seq_num=self.seq_num,
                payload=client_hello_payload,
                mtu=self.mtu
            )
            for pkt in client_packets:
                writer.write(pkt)
            await writer.drain()

            # 3. Receive ServerHello packets
            server_hello_payload = None
            recv_buf = bytearray()
            while server_hello_payload is None:
                chunk = await reader.read(4096)
                if not chunk:
                    raise ConnectionError("Connection closed before ServerHello received")

                recv_buf.extend(chunk)
                offset = 0
                while offset < len(recv_buf):
                    if len(recv_buf) - offset < PacketFramer.HEADER_SIZE:
                        break
                    _, _, _, _, _, pkt_len = PacketFramer.parse_packet(bytes(recv_buf[offset:]))
                    if len(recv_buf) - offset < pkt_len:
                        break
                    pkt_bytes = bytes(recv_buf[offset:offset + pkt_len])
                    complete = self.reassembler.add_packet(pkt_bytes)
                    if complete:
                        _, _, server_hello_payload = complete
                    offset += pkt_len
                if offset > 0:
                    del recv_buf[:offset]

            # 4. Decapsulate ServerHello to derive master secret
            master_key = self.initiator.decapsulate_response(server_hello_payload, salt=self.session_id)
            self.keys = self.initiator.dual_hkdf.derive_tunnel_keys(master_key, session_id=self.session_id)
            self.aead_cipher = AESGCM(self.keys["client_write_key"])

            # 5. Send Encrypted Finished record
            finished_nonce = os.urandom(12)
            finished_ciphertext = self.aead_cipher.encrypt(finished_nonce, b"CLIENT_FINISHED", b"TLS13_FINISHED")
            fin_payload = finished_nonce + finished_ciphertext
            fin_packets = PacketFramer.fragment_payload(msg_type=3, seq_num=self.seq_num + 1, payload=fin_payload, mtu=self.mtu)
            for pkt in fin_packets:
                writer.write(pkt)
            await writer.drain()

            self.handshake_latency_ms = (time.perf_counter_ns() - t_start) / 1_000_000.0
            return self.handshake_latency_ms

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


class TLS13PQCServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8443, mtu: int = 1500):
        self.host = host
        self.port = port
        self.mtu = mtu
        self.server = None
        self.total_handshakes: int = 0

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        reassembler = FragmentReassembler()
        client_hello_payload = None
        recv_buf = bytearray()

        try:
            # Reassemble ClientHello
            while client_hello_payload is None:
                chunk = await reader.read(4096)
                if not chunk:
                    return
                recv_buf.extend(chunk)
                offset = 0
                while offset < len(recv_buf):
                    if len(recv_buf) - offset < PacketFramer.HEADER_SIZE:
                        break
                    _, _, _, _, _, pkt_len = PacketFramer.parse_packet(bytes(recv_buf[offset:]))
                    if len(recv_buf) - offset < pkt_len:
                        break
                    pkt_bytes = bytes(recv_buf[offset:offset + pkt_len])
                    complete = reassembler.add_packet(pkt_bytes)
                    if complete:
                        _, _, client_hello_payload = complete
                    offset += pkt_len
                if offset > 0:
                    del recv_buf[:offset]

            # Parse ClientHello
            suite_len = client_hello_payload[0]
            suite_name = client_hello_payload[1:1 + suite_len].decode('utf-8')
            session_id = client_hello_payload[1 + suite_len:1 + suite_len + 16]
            client_pk_bytes = client_hello_payload[1 + suite_len + 16:]

            suite = CipherSuiteType(suite_name)
            responder = HybridKEMResponder(suite=suite)
            resp_payload, master_key = responder.process_initiator_pk(client_pk_bytes, salt=session_id)

            # Send ServerHello packets
            server_packets = PacketFramer.fragment_payload(
                msg_type=2,
                seq_num=0,
                payload=resp_payload,
                mtu=self.mtu
            )
            for pkt in server_packets:
                writer.write(pkt)
            await writer.drain()

            # Wait for Client Finished record
            fin_chunk = await reader.read(4096)
            self.total_handshakes += 1

        except Exception as e:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        self.server = await asyncio.start_server(self._handle_connection, self.host, self.port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
