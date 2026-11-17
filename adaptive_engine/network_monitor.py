"""
Network Monitor and Channel Quality Estimator
Tracks real-time Round-Trip Time (RTT), RTT Variance, Packet Loss Rate (P_loss),
and Path MTU (PMTU).

Supports RFC 6298 EWMA estimation, direct active probing, live protocol handshake
telemetry ingestion, and auditable history tracking.
"""

import time
import math
import socket
from typing import Dict, Any, Optional, List


class NetworkMonitor:
    """
    Exponentially Weighted Moving Average (EWMA) Network Quality Estimator
    compliant with RFC 6298 (TCP RTO calculation).
    """

    def __init__(self, initial_rtt_ms: float = 20.0, initial_mtu: int = 1500, initial_loss_rate: float = 0.0):
        self.alpha = 0.125  # Weight for RTT smoothing
        self.beta = 0.250   # Weight for RTT variance smoothing
        
        self.srtt_ms: float = initial_rtt_ms       # Smoothed RTT
        self.rttvar_ms: float = initial_rtt_ms / 2.0  # RTT Variance
        self.rto_ms: float = self.srtt_ms + 4.0 * self.rttvar_ms  # Retransmission Timeout
        
        self.pmtu: int = initial_mtu
        self.loss_rate: float = initial_loss_rate  # Range [0.0, 1.0]
        self.bandwidth_mbps: float = 100.0         # Link bandwidth
        self.total_probes: int = 0
        self.telemetry_history: List[Dict[str, Any]] = []

    def update_rtt_sample(self, rtt_sample_ms: float):
        """
        Updates SRTT, RTTVAR, and RTO according to RFC 6298 standard.
        """
        if self.total_probes == 0:
            self.srtt_ms = rtt_sample_ms
            self.rttvar_ms = rtt_sample_ms / 2.0
        else:
            self.rttvar_ms = (1.0 - self.beta) * self.rttvar_ms + self.beta * abs(self.srtt_ms - rtt_sample_ms)
            self.srtt_ms = (1.0 - self.alpha) * self.srtt_ms + self.alpha * rtt_sample_ms

        # RTO = max(50ms, SRTT + 4 * RTTVAR)
        self.rto_ms = max(50.0, self.srtt_ms + 4.0 * self.rttvar_ms)
        self.total_probes += 1

    def update_loss_sample(self, dropped: bool):
        """
        Updates packet loss rate using sliding window EWMA.
        """
        sample = 1.0 if dropped else 0.0
        decay = 0.1
        self.loss_rate = (1.0 - decay) * self.loss_rate + decay * sample

    def record_protocol_handshake(self, duration_ms: float, success: bool, payload_bytes: int = 0):
        """
        Ingests actual measured protocol handshake telemetry from live TLS 1.3
        or WireGuard PQC executions.
        """
        self.update_loss_sample(dropped=(not success))
        if success and duration_ms > 0:
            # TLS 1.3 is 1-RTT (handshake takes approx 1 RTT + crypto)
            # We record duration as an empirical RTT indicator
            self.update_rtt_sample(max(0.5, duration_ms))

        event = {
            "timestamp": time.time(),
            "duration_ms": round(duration_ms, 2),
            "success": success,
            "payload_bytes": payload_bytes,
            "resulting_srtt_ms": round(self.srtt_ms, 2),
            "resulting_loss_rate": round(self.loss_rate, 4)
        }
        self.telemetry_history.append(event)
        if len(self.telemetry_history) > 100:
            self.telemetry_history.pop(0)

    def probe_tcp_rtt(self, host: str = "127.0.0.1", port: int = 443, timeout: float = 1.0) -> Optional[float]:
        """
        Performs an active TCP SYN/ACK timing measurement to estimate path RTT.
        Returns measured RTT in ms, or None if probe fails or environment blocks connect.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.perf_counter_ns()
        try:
            s.connect((host, port))
            t1 = time.perf_counter_ns()
            rtt_ms = (t1 - t0) / 1_000_000.0
            self.update_rtt_sample(rtt_ms)
            self.update_loss_sample(dropped=False)
            return rtt_ms
        except Exception:
            self.update_loss_sample(dropped=True)
            return None
        finally:
            try:
                s.close()
            except Exception:
                pass

    def set_channel_state(self, rtt_ms: float, loss_rate: float, mtu: int = 1500, bandwidth_mbps: float = 100.0):
        """
        Directly configures channel parameters (used by impairment / benchmark harness).
        """
        self.srtt_ms = rtt_ms
        self.rttvar_ms = rtt_ms * 0.2
        self.rto_ms = max(50.0, self.srtt_ms + 4.0 * self.rttvar_ms)
        self.loss_rate = max(0.0, min(1.0, loss_rate))
        self.pmtu = mtu
        self.bandwidth_mbps = bandwidth_mbps

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "srtt_ms": round(self.srtt_ms, 2),
            "rttvar_ms": round(self.rttvar_ms, 2),
            "rto_ms": round(self.rto_ms, 2),
            "pmtu": self.pmtu,
            "loss_rate": round(self.loss_rate, 4),
            "bandwidth_mbps": self.bandwidth_mbps,
            "total_probes": self.total_probes,
            "history_count": len(self.telemetry_history)
        }
