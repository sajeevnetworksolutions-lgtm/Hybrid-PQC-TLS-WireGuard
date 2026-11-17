"""
Real TLS 1.3 Post-Quantum Key Exchange Protocol Engine (RFC 8446)
Implements genuine TLS 1.3 with X25519 + ML-KEM-768 Hybrid Key Exchange (X25519MLKEM768),
Pure ML-KEM (MLKEM768, MLKEM1024), and Classical Key Exchange using OpenSSL 4.0.0.

Key Standards & Properties:
- RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
- draft-ietf-tls-hybrid-design: Hybrid key exchange in TLS 1.3 (X25519MLKEM768 / 0x11ec)
- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism
- Real Certificate Validation (X.509 chain of trust)
- Genuine Transcript Hashing & Finished Record Verification
- Zero Simulation: Real OpenSSL 4.0.0 TLS 1.3 Record Layer with AES-GCM / ChaCha20-Poly1305
"""

import os
import sys
import socket
import select
from typing import Tuple, Dict, Any, Optional, List
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.bindings.openssl.binding import Binding

_binding = Binding()
_ffi = _binding.ffi
_lib = _binding.lib


class UnsupportedCipherSuiteError(ValueError):
    """Raised when an unsupported cipher suite or key exchange group is requested."""
    pass


class TLSHandshakeError(RuntimeError):
    """Raised when a TLS 1.3 handshake fails (e.g., certificate verification or group mismatch)."""
    pass


# Mapping from project CipherSuiteType string/enum to OpenSSL 4.0.0 named group strings
# OpenSSL 4.0.0 provides native support for:
# - 'X25519MLKEM768' : Hybrid X25519 + ML-KEM-768 (draft-ietf-tls-hybrid-design)
# - 'MLKEM768'        : Pure ML-KEM-768
# - 'MLKEM1024'       : Pure ML-KEM-1024
# - 'SecP256r1MLKEM768': Hybrid NIST P-256 + ML-KEM-768
# - 'X25519'          : Classical Curve25519
# - 'P-256'           : Classical NIST P-256 (prime256v1)
SUPPORTED_GROUPS_MAP = {
    "X25519+ML-KEM-768": b"X25519MLKEM768",
    "X25519MLKEM768": b"X25519MLKEM768",
    "ML-KEM-768": b"MLKEM768",
    "MLKEM768": b"MLKEM768",
    "ML-KEM-1024": b"MLKEM1024",
    "MLKEM1024": b"MLKEM1024",
    "SecP256r1+ML-KEM-768": b"SecP256r1MLKEM768",
    "SecP256r1MLKEM768": b"SecP256r1MLKEM768",
    "X25519": b"X25519",
    "P-256": b"P-256",
    "prime256v1": b"prime256v1"
}


@dataclass
class RealTLS13Config:
    key_exchange_group: str = "X25519MLKEM768"
    ciphersuites: str = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    ca_file: Optional[str] = None
    verify_peer: bool = False
    record_secrets: bool = True


class RealTLS13SocketConnection:
    """
    Connected TLS 1.3 session operating over an actual OS TCP socket.
    Wraps an OpenSSL SSL* handle bound to a socket file descriptor.
    Provides direct access to session-negotiated properties, bidirectional
    encrypted data transfer, and clean session shutdown.
    """

    def __init__(self, ssl_ptr, sock: socket.socket, is_server: bool = False):
        self.ssl = ssl_ptr
        self.sock = sock
        self.is_server = is_server
        self._closed = False

    def write(self, data: bytes, timeout: float = 5.0) -> int:
        """Encrypts and transmits application data over the TLS 1.3 TCP connection."""
        if self._closed or not self.ssl:
            raise RuntimeError("Cannot write to closed TLS socket connection")
        total_sent = 0
        while total_sent < len(data):
            ret = _lib.SSL_write(self.ssl, data[total_sent:], len(data) - total_sent)
            if ret > 0:
                total_sent += ret
            else:
                err = _lib.SSL_get_error(self.ssl, ret)
                if err == 3:  # SSL_ERROR_WANT_WRITE
                    _, w, _ = select.select([], [self.sock], [], timeout)
                    if not w:
                        raise TimeoutError("SSL_write timed out waiting for writable socket")
                elif err == 2:  # SSL_ERROR_WANT_READ
                    r, _, _ = select.select([self.sock], [], [], timeout)
                    if not r:
                        raise TimeoutError("SSL_write timed out waiting for readable socket")
                else:
                    raise RuntimeError(f"SSL_write failed over TCP with OpenSSL error {err}")
        return total_sent

    def read(self, max_len: int = 16384, timeout: float = 5.0) -> bytes:
        """Receives and decrypts application data from the TLS 1.3 TCP connection."""
        if self._closed or not self.ssl:
            raise RuntimeError("Cannot read from closed TLS socket connection")
        buf = _ffi.new("char[]", max_len)
        while True:
            ret = _lib.SSL_read(self.ssl, buf, max_len)
            if ret > 0:
                return _ffi.buffer(buf, ret)[:]
            err = _lib.SSL_get_error(self.ssl, ret)
            if err == 2:  # SSL_ERROR_WANT_READ
                r, _, _ = select.select([self.sock], [], [], timeout)
                if not r:
                    raise TimeoutError("SSL_read timed out waiting for readable socket")
            elif err == 3:  # SSL_ERROR_WANT_WRITE
                _, w, _ = select.select([], [self.sock], [], timeout)
                if not w:
                    raise TimeoutError("SSL_read timed out waiting for writable socket")
            elif err in (5, 6):  # SSL_ERROR_SYSCALL or SSL_ERROR_ZERO_RETURN (clean shutdown)
                return b""
            else:
                raise RuntimeError(f"SSL_read failed over TCP with OpenSSL error {err}")

    def get_negotiated_group(self) -> str:
        """
        Retrieves the actual negotiated key exchange group directly from the
        completed OpenSSL SSL session struct (SSL_get0_group_name).
        Does NOT report configured groups.
        """
        if not self.ssl:
            return "None"
        ptr = _lib.SSL_get0_group_name(self.ssl)
        if ptr == _ffi.NULL:
            return "None"
        name = _ffi.string(ptr).decode("utf-8")
        if name.lower() == "x25519":
            return "X25519"
        return name

    def get_cipher_suite(self) -> str:
        """Retrieves the actual negotiated cipher suite from the active SSL session."""
        if not self.ssl:
            return "None"
        cipher = _lib.SSL_get_current_cipher(self.ssl)
        if cipher == _ffi.NULL:
            return "None"
        return _ffi.string(_lib.SSL_CIPHER_get_name(cipher)).decode("utf-8")

    def get_tls_version(self) -> str:
        """Retrieves the actual negotiated TLS protocol version from the active SSL session."""
        if not self.ssl:
            return "None"
        return _ffi.string(_lib.SSL_get_version(self.ssl)).decode("utf-8")

    def get_verify_result(self) -> int:
        """Retrieves the peer certificate verification status code (0 == X509_V_OK)."""
        if not self.ssl:
            return -1
        return _lib.SSL_get_verify_result(self.ssl)

    def shutdown(self):
        """Cleanly performs bidirectional TLS closure alert and closes the socket."""
        if not self._closed:
            self._closed = True
            if self.ssl and self.ssl != _ffi.NULL:
                _lib.SSL_shutdown(self.ssl)
                _lib.SSL_free(self.ssl)
                self.ssl = None
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass

    def close(self):
        self.shutdown()

    def __del__(self):
        self.shutdown()


class RealTLS13Server:
    """
    Genuine RFC 8446 TLS 1.3 Server backed by OpenSSL 4.0.0.
    Enforces minimum and maximum protocol version to TLS 1.3.
    """

    def __init__(self, config: RealTLS13Config):
        self.config = config
        self.ctx = None
        self.traffic_secrets: List[str] = []
        self._keylog_cb_handle = None

        self._init_ctx()

    def _init_ctx(self):
        self.ctx = _lib.SSL_CTX_new(_lib.TLS_server_method())
        if self.ctx == _ffi.NULL:
            raise RuntimeError("Failed to allocate OpenSSL SSL_CTX for server")

        # 1. Enforce TLS 1.3 exclusively
        _lib.SSL_CTX_set_min_proto_version(self.ctx, _lib.TLS1_3_VERSION)
        _lib.SSL_CTX_set_max_proto_version(self.ctx, _lib.TLS1_3_VERSION)

        # 2. Configure Key Exchange Group
        group_key = self.config.key_exchange_group
        group_bytes = SUPPORTED_GROUPS_MAP.get(group_key)
        if group_bytes is None:
            # Fallback to direct bytes if valid
            group_bytes = group_key.encode("utf-8")

        ret = _lib.SSL_CTX_set1_curves_list(self.ctx, group_bytes)
        if ret != 1:
            raise UnsupportedCipherSuiteError(
                f"Requested key exchange group '{group_key}' is NOT supported by the OpenSSL 4.0.0 TLS 1.3 stack. "
                f"(Note: OpenSSL 4.0.0 deliberately omits ML-KEM-512 per NSA CNSA 2.0 guidance. Supported groups: {list(SUPPORTED_GROUPS_MAP.keys())})"
            )

        # 3. Configure TLS 1.3 Cipher Suites
        if self.config.ciphersuites:
            _lib.SSL_CTX_set_ciphersuites(self.ctx, self.config.ciphersuites.encode("utf-8"))

        # 4. Load Certificate and Private Key
        if self.config.cert_file and self.config.key_file:
            if not os.path.exists(self.config.cert_file):
                raise FileNotFoundError(f"Server certificate file not found: {self.config.cert_file}")
            if not os.path.exists(self.config.key_file):
                raise FileNotFoundError(f"Server private key file not found: {self.config.key_file}")

            if _lib.SSL_CTX_use_certificate_file(self.ctx, self.config.cert_file.encode("utf-8"), 1) != 1:
                raise RuntimeError("Failed to load server certificate into OpenSSL SSL_CTX")
            if _lib.SSL_CTX_use_PrivateKey_file(self.ctx, self.config.key_file.encode("utf-8"), 1) != 1:
                raise RuntimeError("Failed to load server private key into OpenSSL SSL_CTX")
            if _lib.SSL_CTX_check_private_key(self.ctx) != 1:
                raise ValueError("Server private key does not match public certificate")

        # 5. Keylog Callback for Traffic Secret Auditing
        if self.config.record_secrets:
            @_ffi.callback("void(SSL *, char *)")
            def _server_keylog(ssl_ptr, line_ptr):
                line = _ffi.string(line_ptr).decode("utf-8")
                self.traffic_secrets.append(line)

            self._keylog_cb_handle = _server_keylog
            _lib.SSL_CTX_set_keylog_callback(self.ctx, self._keylog_cb_handle)

    def accept_socket(self, client_sock: socket.socket, timeout: float = 5.0) -> RealTLS13SocketConnection:
        """
        Accepts and completes a genuine TLS 1.3 handshake over an established TCP socket.
        Supports both blocking and non-blocking/timeout sockets using select.
        Returns a RealTLS13SocketConnection wrapping the connected SSL* session.
        """
        ssl = _lib.SSL_new(self.ctx)
        if ssl == _ffi.NULL:
            raise RuntimeError("Failed to allocate SSL instance for server TCP session")
        _lib.SSL_set_fd(ssl, client_sock.fileno())
        _lib.SSL_set_accept_state(ssl)

        while True:
            ret = _lib.SSL_do_handshake(ssl)
            if ret == 1:
                break
            err = _lib.SSL_get_error(ssl, ret)
            if err == 2:  # SSL_ERROR_WANT_READ
                r, _, _ = select.select([client_sock], [], [], timeout)
                if not r:
                    _lib.SSL_free(ssl)
                    raise TLSHandshakeError("Server TCP TLS 1.3 handshake timed out waiting for readable socket")
            elif err == 3:  # SSL_ERROR_WANT_WRITE
                _, w, _ = select.select([], [client_sock], [], timeout)
                if not w:
                    _lib.SSL_free(ssl)
                    raise TLSHandshakeError("Server TCP TLS 1.3 handshake timed out waiting for writable socket")
            else:
                _lib.SSL_free(ssl)
                raise TLSHandshakeError(f"Server TCP TLS 1.3 handshake failed with OpenSSL error code {err}")

        return RealTLS13SocketConnection(ssl, client_sock, is_server=True)

    def close(self):
        if self.ctx and self.ctx != _ffi.NULL:
            _lib.SSL_CTX_free(self.ctx)
            self.ctx = None

    def __del__(self):
        self.close()


class RealTLS13Client:
    """
    Genuine RFC 8446 TLS 1.3 Client backed by OpenSSL 4.0.0.
    Enforces minimum and maximum protocol version to TLS 1.3.
    """

    def __init__(self, config: RealTLS13Config):
        self.config = config
        self.ctx = None
        self.traffic_secrets: List[str] = []
        self._keylog_cb_handle = None

        self._init_ctx()

    def _init_ctx(self):
        self.ctx = _lib.SSL_CTX_new(_lib.TLS_client_method())
        if self.ctx == _ffi.NULL:
            raise RuntimeError("Failed to allocate OpenSSL SSL_CTX for client")

        # 1. Enforce TLS 1.3 exclusively
        _lib.SSL_CTX_set_min_proto_version(self.ctx, _lib.TLS1_3_VERSION)
        _lib.SSL_CTX_set_max_proto_version(self.ctx, _lib.TLS1_3_VERSION)

        # 2. Configure Key Exchange Group
        group_key = self.config.key_exchange_group
        group_bytes = SUPPORTED_GROUPS_MAP.get(group_key)
        if group_bytes is None:
            group_bytes = group_key.encode("utf-8")

        ret = _lib.SSL_CTX_set1_curves_list(self.ctx, group_bytes)
        if ret != 1:
            raise UnsupportedCipherSuiteError(
                f"Requested key exchange group '{group_key}' is NOT supported by the OpenSSL 4.0.0 TLS 1.3 stack. "
                f"(Note: OpenSSL 4.0.0 deliberately omits ML-KEM-512 per NSA CNSA 2.0 guidance. Supported groups: {list(SUPPORTED_GROUPS_MAP.keys())})"
            )

        # 3. Configure TLS 1.3 Cipher Suites
        if self.config.ciphersuites:
            _lib.SSL_CTX_set_ciphersuites(self.ctx, self.config.ciphersuites.encode("utf-8"))

        # 4. Configure Certificate Verification
        if self.config.verify_peer:
            _lib.SSL_CTX_set_verify(self.ctx, 1, _ffi.NULL)  # SSL_VERIFY_PEER = 0x01
            if self.config.ca_file:
                if not os.path.exists(self.config.ca_file):
                    raise FileNotFoundError(f"CA bundle file not found: {self.config.ca_file}")
                ret_ca = _lib.SSL_CTX_load_verify_locations(self.ctx, self.config.ca_file.encode("utf-8"), _ffi.NULL)
                if ret_ca != 1:
                    raise RuntimeError("Failed to load CA verify locations in client context")
        else:
            _lib.SSL_CTX_set_verify(self.ctx, 0, _ffi.NULL)  # SSL_VERIFY_NONE

        # 5. Keylog Callback for Traffic Secret Auditing
        if self.config.record_secrets:
            @_ffi.callback("void(SSL *, char *)")
            def _client_keylog(ssl_ptr, line_ptr):
                line = _ffi.string(line_ptr).decode("utf-8")
                self.traffic_secrets.append(line)

            self._keylog_cb_handle = _client_keylog
            _lib.SSL_CTX_set_keylog_callback(self.ctx, self._keylog_cb_handle)

    def connect_socket(self, sock: socket.socket, timeout: float = 5.0) -> RealTLS13SocketConnection:
        """
        Connects and completes a genuine TLS 1.3 handshake over an established TCP socket.
        Supports both blocking and non-blocking/timeout sockets using select.
        Returns a RealTLS13SocketConnection wrapping the connected SSL* session.
        """
        ssl = _lib.SSL_new(self.ctx)
        if ssl == _ffi.NULL:
            raise RuntimeError("Failed to allocate SSL instance for client TCP session")
        _lib.SSL_set_fd(ssl, sock.fileno())
        _lib.SSL_set_connect_state(ssl)

        while True:
            ret = _lib.SSL_do_handshake(ssl)
            if ret == 1:
                break
            err = _lib.SSL_get_error(ssl, ret)
            if err == 2:  # SSL_ERROR_WANT_READ
                r, _, _ = select.select([sock], [], [], timeout)
                if not r:
                    _lib.SSL_free(ssl)
                    raise TLSHandshakeError("Client TCP TLS 1.3 handshake timed out waiting for readable socket")
            elif err == 3:  # SSL_ERROR_WANT_WRITE
                _, w, _ = select.select([], [sock], [], timeout)
                if not w:
                    _lib.SSL_free(ssl)
                    raise TLSHandshakeError("Client TCP TLS 1.3 handshake timed out waiting for writable socket")
            else:
                v_res = _lib.SSL_get_verify_result(ssl)
                if v_res != 0:
                    err_str = _ffi.string(_lib.X509_verify_cert_error_string(v_res)).decode()
                    _lib.SSL_free(ssl)
                    raise TLSHandshakeError(f"Client TCP TLS 1.3 handshake failed: Certificate verification failed ({err_str}, code {v_res})")
                _lib.SSL_free(ssl)
                raise TLSHandshakeError(f"Client TCP TLS 1.3 handshake failed with OpenSSL error code {err}")

        if self.config.verify_peer:
            v_res = _lib.SSL_get_verify_result(ssl)
            if v_res != 0:
                err_str = _ffi.string(_lib.X509_verify_cert_error_string(v_res)).decode()
                _lib.SSL_free(ssl)
                raise TLSHandshakeError(f"Certificate verification failed: {err_str} (error {v_res})")

        return RealTLS13SocketConnection(ssl, sock, is_server=False)

    def close(self):
        if self.ctx and self.ctx != _ffi.NULL:
            _lib.SSL_CTX_free(self.ctx)
            self.ctx = None

    def __del__(self):
        self.close()


class TLS13SessionPair:
    """
    Connected Pair of Real TLS 1.3 Endpoints communicating over OpenSSL Memory BIOs.
    Executes real TLS 1.3 handshakes, record encryption, and application data transfer in memory.
    """

    def __init__(self, server: RealTLS13Server, client: RealTLS13Client):
        self.server = server
        self.client = client

        self.server_ssl = _lib.SSL_new(server.ctx)
        self.client_ssl = _lib.SSL_new(client.ctx)
        if self.server_ssl == _ffi.NULL or self.client_ssl == _ffi.NULL:
            raise RuntimeError("Failed to allocate SSL instance")

        _lib.SSL_set_accept_state(self.server_ssl)
        _lib.SSL_set_connect_state(self.client_ssl)

        # Allocate memory BIOs: rbio (read) and wbio (write) for both endpoints
        self.rbio_c = _lib.BIO_new(_lib.BIO_s_mem())
        self.wbio_c = _lib.BIO_new(_lib.BIO_s_mem())
        _lib.SSL_set_bio(self.client_ssl, self.rbio_c, self.wbio_c)

        self.rbio_s = _lib.BIO_new(_lib.BIO_s_mem())
        self.wbio_s = _lib.BIO_new(_lib.BIO_s_mem())
        _lib.SSL_set_bio(self.server_ssl, self.rbio_s, self.wbio_s)

        self.handshake_completed = False
        self._buf = _ffi.new("char[]", 32768)

    def _pump(self, from_bio, to_bio) -> int:
        total = 0
        while True:
            n = _lib.BIO_read(from_bio, self._buf, 32768)
            if n <= 0:
                break
            _lib.BIO_write(to_bio, self._buf, n)
            total += n
        return total

    def do_handshake(self, max_iterations: int = 25) -> bool:
        """
        Executes the bidirectional TLS 1.3 handshake until completion or fatal alert.
        Validates peer certificate verification results on client.
        """
        client_done = False
        server_done = False

        for _ in range(max_iterations):
            if not client_done:
                rc = _lib.SSL_do_handshake(self.client_ssl)
                if rc == 1:
                    client_done = True
                else:
                    err = _lib.SSL_get_error(self.client_ssl, rc)
                    if err not in (2, 3):  # SSL_ERROR_WANT_READ=2, SSL_ERROR_WANT_WRITE=3
                        v_err = _lib.SSL_get_verify_result(self.client_ssl)
                        if v_err != 0:
                            err_str = _ffi.string(_lib.X509_verify_cert_error_string(v_err)).decode()
                            raise TLSHandshakeError(f"Client TLS 1.3 handshake failed: Certificate verification failed ({err_str}, code {v_err})")
                        raise TLSHandshakeError(f"Client TLS 1.3 handshake failed with OpenSSL error code {err}")

            self._pump(self.wbio_c, self.rbio_s)

            if not server_done:
                rs = _lib.SSL_do_handshake(self.server_ssl)
                if rs == 1:
                    server_done = True
                else:
                    err = _lib.SSL_get_error(self.server_ssl, rs)
                    if err not in (2, 3):
                        raise TLSHandshakeError(f"Server TLS 1.3 handshake failed with OpenSSL error code {err}")

            self._pump(self.wbio_s, self.rbio_c)

            if client_done and server_done:
                # Check verify result on client
                v_res = _lib.SSL_get_verify_result(self.client_ssl)
                if self.client.config.verify_peer and v_res != 0:
                    err_str = _ffi.string(_lib.X509_verify_cert_error_string(v_res)).decode()
                    raise TLSHandshakeError(f"Certificate verification failed: {err_str} (error {v_res})")

                self.handshake_completed = True
                return True

        raise TLSHandshakeError(f"TLS 1.3 handshake did not complete within {max_iterations} steps")

    def client_write(self, data: bytes) -> int:
        if not self.handshake_completed:
            raise RuntimeError("Handshake must be completed before sending application data")
        ret = _lib.SSL_write(self.client_ssl, data, len(data))
        self._pump(self.wbio_c, self.rbio_s)
        return ret

    def server_read(self, max_len: int = 16384) -> bytes:
        if not self.handshake_completed:
            raise RuntimeError("Handshake must be completed before reading application data")
        buf = _ffi.new("char[]", max_len)
        n = _lib.SSL_read(self.server_ssl, buf, max_len)
        if n <= 0:
            return b""
        return _ffi.buffer(buf, n)[:]

    def server_write(self, data: bytes) -> int:
        if not self.handshake_completed:
            raise RuntimeError("Handshake must be completed before sending application data")
        ret = _lib.SSL_write(self.server_ssl, data, len(data))
        self._pump(self.wbio_s, self.rbio_c)
        return ret

    def client_read(self, max_len: int = 16384) -> bytes:
        if not self.handshake_completed:
            raise RuntimeError("Handshake must be completed before reading application data")
        buf = _ffi.new("char[]", max_len)
        n = _lib.SSL_read(self.client_ssl, buf, max_len)
        if n <= 0:
            return b""
        return _ffi.buffer(buf, n)[:]

    def get_negotiated_group(self) -> str:
        ptr = _lib.SSL_get0_group_name(self.client_ssl)
        if ptr == _ffi.NULL:
            return "None"
        name = _ffi.string(ptr).decode("utf-8")
        if name.lower() == "x25519":
            return "X25519"
        return name

    def get_cipher_suite(self) -> str:
        cipher = _lib.SSL_get_current_cipher(self.client_ssl)
        if cipher == _ffi.NULL:
            return "None"
        return _ffi.string(_lib.SSL_CIPHER_get_name(cipher)).decode("utf-8")

    def get_tls_version(self) -> str:
        return _ffi.string(_lib.SSL_get_version(self.client_ssl)).decode("utf-8")

    def verify_traffic_secrets(self) -> Dict[str, Any]:
        """
        Cross-checks derived TLS 1.3 traffic secrets between client and server.
        Asserts bit-for-bit identity across derived traffic secrets.
        """
        c_secrets = self.client.traffic_secrets
        s_secrets = self.server.traffic_secrets

        client_map = {}
        for line in c_secrets:
            parts = line.split()
            if len(parts) >= 3:
                client_map[parts[0]] = parts[-1]

        server_map = {}
        for line in s_secrets:
            parts = line.split()
            if len(parts) >= 3:
                server_map[parts[0]] = parts[-1]

        expected_labels = [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0",
            "SERVER_TRAFFIC_SECRET_0",
            "EXPORTER_SECRET"
        ]

        matches = {}
        all_matched = True
        for lbl in expected_labels:
            c_val = client_map.get(lbl)
            s_val = server_map.get(lbl)
            matched = (c_val is not None) and (c_val == s_val)
            matches[lbl] = {
                "matched": matched,
                "secret_prefix": c_val[:16] + "..." if c_val else None
            }
            if not matched:
                all_matched = False

        return {
            "all_secrets_matched": all_matched,
            "labels_checked": len(expected_labels),
            "details": matches
        }

    def close(self):
        if getattr(self, "client_ssl", None) and self.client_ssl != _ffi.NULL:
            _lib.SSL_free(self.client_ssl)
            self.client_ssl = None
        if getattr(self, "server_ssl", None) and self.server_ssl != _ffi.NULL:
            _lib.SSL_free(self.server_ssl)
            self.server_ssl = None

    def __del__(self):
        self.close()


def run_demo(group: str = "X25519MLKEM768"):
    import time
    from protocols.tls_cert_utils import PKIManager

    print("=" * 75)
    print("REAL TLS 1.3 POST-QUANTUM KEY EXCHANGE DEMONSTRATION (RFC 8446)")
    print("=" * 75)

    with PKIManager() as pki:
        print(f"[*] Initializing Server with Group: {group}")
        s_cfg = RealTLS13Config(
            key_exchange_group=group,
            cert_file=pki.server_cert_path,
            key_file=pki.server_key_path
        )
        print(f"[*] Initializing Client with CA Verification")
        c_cfg = RealTLS13Config(
            key_exchange_group=group,
            ca_file=pki.ca_cert_path,
            verify_peer=True
        )

        server = RealTLS13Server(s_cfg)
        client = RealTLS13Client(c_cfg)
        session = TLS13SessionPair(server, client)

        print("[*] Executing Genuine TLS 1.3 Handshake...")
        t0 = time.perf_counter_ns()
        session.do_handshake()
        lat_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

        print(f"[+] Handshake Succeeded in {lat_ms:.2f} ms!")
        print(f"    Protocol Version : {session.get_tls_version()}")
        print(f"    Negotiated Group : {session.get_negotiated_group()}")
        print(f"    Cipher Suite     : {session.get_cipher_suite()}")

        # Data Transfer
        req = b"GET /pqc-secure-resource HTTP/1.3\r\nHost: localhost\r\n\r\n"
        session.client_write(req)
        resp_data = session.server_read()
        print(f"[+] Client -> Server Encrypted Record: {len(req)} bytes transferred")
        print(f"    Server Decrypted Content: {resp_data.decode().strip()[:40]}...")

        resp = b"HTTP/1.3 200 OK\r\nContent-Type: text/plain\r\n\r\nHello Quantum-Safe World!"
        session.server_write(resp)
        client_data = session.client_read()
        print(f"[+] Server -> Client Encrypted Record: {len(resp)} bytes transferred")
        print(f"    Client Decrypted Content: {client_data.decode().strip()[:40]}...")

        # Traffic Secret Audit
        secrets = session.verify_traffic_secrets()
        print(f"[+] Key Schedule Traffic Secret Agreement:")
        print(f"    All 5 TLS 1.3 Secrets Matched: {secrets['all_secrets_matched']}")
        for k, v in secrets['details'].items():
            print(f"    - {k:<32}: {v['secret_prefix']}")

        session.close()
        server.close()
        client.close()
    print("=" * 75)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Real TLS 1.3 Post-Quantum Key Exchange Engine")
    parser.add_argument("--group", default="X25519MLKEM768", choices=list(SUPPORTED_GROUPS_MAP.keys()), help="TLS 1.3 Named Group")
    args = parser.parse_args()
    run_demo(args.group)
