"""
Virtual Network Impairment Simulator
Simulates real-world WAN latency, jitter, stochastic packet drops (0% - 5%),
and path MTU limits (576B - 9000B) for empirical protocol evaluation.
"""

import random
import time
from typing import Dict, Any, List, Optional
from crypto.packet_framing import PacketFramer


class VirtualNetworkChannel:
    """
    Simulates physical network transport characteristics:
      - Propagation RTT (ms) + Gaussian Jitter (ms)
      - Independent stochastic packet drop probability (P_loss)
      - MTU fragmentation penalty with TCP Retransmission Timeouts (RTO)
    """

    def __init__(
        self,
        base_rtt_ms: float = 20.0,
        jitter_ms: float = 2.0,
        loss_rate: float = 0.0,
        mtu: int = 1500,
        bandwidth_mbps: float = 100.0,
        rto_base_ms: float = 200.0
    ):
        self.base_rtt_ms = base_rtt_ms
        self.jitter_ms = jitter_ms
        self.loss_rate = loss_rate
        self.mtu = mtu
        self.bandwidth_mbps = bandwidth_mbps
        self.rto_base_ms = rto_base_ms

    def simulate_transmission(self, payload_bytes: bytes) -> Dict[str, Any]:
        """
        Simulates the transmission of a payload through the impaired channel.
        Returns: {
            'transmitted': bool,
            'elapsed_ms': float,
            'fragments_sent': int,
            'retransmissions': int,
            'dropped_fragments': int
        }
        """
        fragments = PacketFramer.fragment_payload(msg_type=1, seq_num=1, payload=payload_bytes, mtu=self.mtu)
        num_frags = len(fragments)
        
        # Transmission serialization delay
        total_bits = len(payload_bytes) * 8
        t_trans_ms = total_bits / (self.bandwidth_mbps * 1000.0)

        # Baseline channel delay with jitter
        sample_rtt = max(0.5, random.gauss(self.base_rtt_ms, self.jitter_ms))

        # Check for packet loss across individual fragments
        retransmissions = 0
        dropped_frags = 0
        all_delivered = False
        rto_penalty_ms = 0.0

        for frag in fragments:
            if random.random() < self.loss_rate:
                dropped_frags += 1
                retransmissions += 1
                # In TCP/WireGuard, dropped fragments incur retransmission timeout
                rto_penalty_ms += self.rto_base_ms

        total_delay_ms = sample_rtt + t_trans_ms + rto_penalty_ms

        return {
            "elapsed_ms": total_delay_ms,
            "num_fragments": num_frags,
            "retransmissions": retransmissions,
            "dropped_fragments": dropped_frags,
            "sample_rtt_ms": sample_rtt
        }
