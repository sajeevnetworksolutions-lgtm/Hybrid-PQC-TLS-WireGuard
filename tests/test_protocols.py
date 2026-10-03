"""
Unit tests for TLS 1.3 PQC Tunnel and WireGuard PQC Proxy
"""

import unittest
import asyncio
from protocols.tls13_pqc_tunnel import TLS13PQCClient, TLS13PQCServer
from protocols.wireguard_pqc_proxy import WireGuardPQCProxy
from crypto.hybrid_kem import CipherSuiteType


class TestProtocols(unittest.TestCase):

    def test_wireguard_pqc_handshake(self):
        peer_a = WireGuardPQCProxy("PeerA_Client", suite=CipherSuiteType.HYBRID_X25519_MLKEM768)
        peer_b = WireGuardPQCProxy("PeerB_Server", suite=CipherSuiteType.HYBRID_X25519_MLKEM768)

        # 1. Peer A creates Initiation Message
        msg1, _ = peer_a.initiate_wireguard_handshake(peer_b.static_pub_ec)
        self.assertGreater(len(msg1), 1000)

        # 2. Peer B creates Response Message
        msg2, key_b = peer_b.respond_wireguard_handshake(msg1, peer_a.static_pub_ec)
        self.assertGreater(len(msg2), 1000)
        self.assertEqual(len(key_b), 32)

        # 3. Peer A processes Response
        key_a = peer_a.complete_wireguard_handshake(msg2)
        self.assertEqual(key_a, key_b)

    def test_tls13_pqc_async_tunnel(self):
        async def run_tls_test():
            server = TLS13PQCServer(host="127.0.0.1", port=9443)
            await server.start()
            try:
                client = TLS13PQCClient(server_host="127.0.0.1", server_port=9443, suite=CipherSuiteType.HYBRID_X25519_MLKEM768)
                latency = await client.connect_and_handshake()
                self.assertGreater(latency, 0.0)
                self.assertIsNotNone(client.keys)
                self.assertEqual(len(client.keys["client_write_key"]), 32)
            finally:
                await server.stop()

        asyncio.run(run_tls_test())


if __name__ == "__main__":
    unittest.main()
