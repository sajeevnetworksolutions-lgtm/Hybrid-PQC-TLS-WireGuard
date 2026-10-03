"""
Network Packet Framing, MTU Slicing & Transport Fragmentation Module
"""

import math
import struct
from typing import List, Tuple, Dict, Optional


class PacketFramer:
    HEADER_MAGIC = b"PQ"
    HEADER_SIZE = 13  # 2 + 1 + 4 + 2 + 2 + 2 = 13 bytes
    IP_TCP_OVERHEAD = 40  # Standard IPv4 (20B) + TCP (20B) or UDP (8B) + WireGuard/IP (32B)

    @classmethod
    def calculate_fragments(cls, payload_len: int, mtu: int = 1500) -> int:
        mss = max(100, mtu - cls.IP_TCP_OVERHEAD - cls.HEADER_SIZE)
        return math.ceil(payload_len / mss)

    @classmethod
    def fragment_payload(
        cls,
        msg_type: int,
        seq_num: int,
        payload: bytes,
        mtu: int = 1500
    ) -> List[bytes]:
        mss = max(100, mtu - cls.IP_TCP_OVERHEAD - cls.HEADER_SIZE)
        total_len = len(payload)
        total_frags = math.ceil(total_len / mss) if total_len > 0 else 1

        packets = []
        for i in range(total_frags):
            chunk = payload[i * mss:(i + 1) * mss]
            header = struct.pack(
                "!2sBIHHH",
                cls.HEADER_MAGIC,
                msg_type,
                seq_num,
                i,
                total_frags,
                len(chunk)
            )
            packets.append(header + chunk)

        return packets

    @classmethod
    def parse_packet(cls, packet_bytes: bytes) -> Tuple[int, int, int, int, bytes, int]:
        """
        Parses a received network packet.
        Returns: (msg_type, seq_num, frag_index, frag_total, chunk_payload, packet_total_len)
        """
        if len(packet_bytes) < cls.HEADER_SIZE:
            raise ValueError(f"Packet too short: {len(packet_bytes)} bytes")

        magic, msg_type, seq_num, frag_idx, frag_total, chunk_len = struct.unpack(
            "!2sBIHHH",
            packet_bytes[:cls.HEADER_SIZE]
        )

        if magic != cls.HEADER_MAGIC:
            raise ValueError(f"Invalid packet magic header: {magic}")

        chunk_payload = packet_bytes[cls.HEADER_SIZE:cls.HEADER_SIZE + chunk_len]
        total_len = cls.HEADER_SIZE + chunk_len
        return msg_type, seq_num, frag_idx, frag_total, chunk_payload, total_len


class FragmentReassembler:
    def __init__(self):
        self.buffers: Dict[Tuple[int, int], Dict[int, bytes]] = {}
        self.totals: Dict[Tuple[int, int], int] = {}

    def add_packet(self, packet_bytes: bytes) -> Optional[Tuple[int, int, bytes]]:
        msg_type, seq_num, frag_idx, frag_total, chunk, _ = PacketFramer.parse_packet(packet_bytes)
        key = (msg_type, seq_num)

        if key not in self.buffers:
            self.buffers[key] = {}
            self.totals[key] = frag_total

        self.buffers[key][frag_idx] = chunk

        if len(self.buffers[key]) == self.totals[key]:
            ordered_chunks = [self.buffers[key][i] for i in range(self.totals[key])]
            full_payload = b"".join(ordered_chunks)
            del self.buffers[key]
            del self.totals[key]
            return msg_type, seq_num, full_payload

        return None
