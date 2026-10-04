"""Transport: the socket + setsockopt layer for TCP/UDP, client and listener.

Keeps platform-specific options behind capability checks so a template written on
Linux (``SO_BINDTODEVICE``, multicast) still loads on Windows - unavailable
options raise a clear error only if actually requested, never on import.
"""

from __future__ import annotations

import socket
import ssl
import struct
from dataclasses import dataclass, field
from typing import Any, Mapping

from .framing import FrameReader, Framing


class TransportError(Exception):
    pass


# Names a template may list in ``socket.options`` -> (level, optname)
_BOOL_OPTS = {
    "SO_REUSEADDR": (socket.SOL_SOCKET, "SO_REUSEADDR"),
    "SO_BROADCAST": (socket.SOL_SOCKET, "SO_BROADCAST"),
    "SO_REUSEPORT": (socket.SOL_SOCKET, "SO_REUSEPORT"),
    "SO_KEEPALIVE": (socket.SOL_SOCKET, "SO_KEEPALIVE"),
    "TCP_NODELAY": (socket.IPPROTO_TCP, "TCP_NODELAY"),
}


def apply_socket_options(sock: socket.socket, options: Any) -> None:
    """Apply a list of socket options. Entries are either a flag name (set to 1)
    or a one-key mapping ``{NAME: value}`` for options that take a value."""
    for opt in options or []:
        if isinstance(opt, Mapping):
            (name, value), = opt.items()
        else:
            name, value = str(opt), 1
        name = str(name).upper()

        if name in ("SO_BINDTODEVICE", "SOCK_BINDTODEVICE"):
            if not hasattr(socket, "SO_BINDTODEVICE"):
                raise TransportError("SO_BINDTODEVICE is not supported on this platform")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, str(value).encode())
            continue
        if name in ("SO_RCVBUF", "SO_SNDBUF"):
            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, name), int(value))
            continue

        spec = _BOOL_OPTS.get(name)
        if spec is None:
            raise TransportError(f"unknown or unsupported socket option: {name}")
        level, attr = spec
        if not hasattr(socket, attr):
            raise TransportError(f"socket option {name} not supported on this platform")
        sock.setsockopt(level, getattr(socket, attr), int(value))


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #
@dataclass
class Connection:
    sock: socket.socket
    transport: str
    peer: tuple[str, int]
    _buf: bytearray = field(default_factory=bytearray)

    def send(self, data: bytes) -> int:
        if self.transport == "tcp":
            self.sock.sendall(data)
        else:
            self.sock.send(data)  # UDP socket is connected to peer
        return len(data)

    def recv(self, framing: Framing) -> bytes:
        if self.transport == "udp":
            # One datagram is one message; framing.size bounds the read.
            bufsize = max(framing.size, 65535) if framing.type == "fixed" else 65535
            try:
                return self.sock.recv(bufsize)
            except socket.timeout as exc:
                raise TransportError("timeout waiting for UDP response") from exc
        reader = FrameReader(self._recv_raw, framing, prebuffer=bytes(self._buf))
        self._buf.clear()
        try:
            frame = reader.read_frame()
        except socket.timeout as exc:
            raise TransportError("timeout waiting for framed TCP response") from exc
        self._buf += reader.buffer
        return frame or b""

    def _recv_raw(self, n: int) -> bytes:
        return self.sock.recv(n)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def open_client(
    transport: str,
    host: str,
    port: int,
    timeout: float,
    options: Any = None,
    tls: Any = None,
) -> Connection:
    family = socket.AF_INET
    if transport == "tcp":
        sock = socket.socket(family, socket.SOCK_STREAM)
        apply_socket_options(sock, options)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except OSError as exc:
            sock.close()
            raise TransportError(f"connect to {host}:{port} failed: {exc}") from exc
        if tls:
            sock = _wrap_tls_client(sock, host, tls)
        return Connection(sock, "tcp", (host, port))

    if transport == "udp":
        sock = socket.socket(family, socket.SOCK_DGRAM)
        apply_socket_options(sock, options)
        sock.settimeout(timeout)
        sock.connect((host, port))  # sets default peer for send/recv
        return Connection(sock, "udp", (host, port))

    raise TransportError(f"unsupported transport for client: {transport!r}")


def _wrap_tls_client(sock: socket.socket, host: str, tls: Any) -> socket.socket:
    cfg = tls if isinstance(tls, Mapping) else {}
    ctx = ssl.create_default_context()
    if not cfg.get("verify", False):
        # Rogue/offensive testing routinely targets self-signed services; default
        # to not verifying, but it is an explicit, visible choice.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    sni = cfg.get("sni") or (host if cfg.get("verify", False) else None)
    return ctx.wrap_socket(sock, server_hostname=sni)


def port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Connect-style open check used by ``preflight`` - plumbing, not a scanner."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------- #
# Listener
# --------------------------------------------------------------------------- #
def open_listener(
    transport: str,
    bind_host: str,
    bind_port: int,
    options: Any = None,
    multicast: Mapping[str, Any] | None = None,
    backlog: int = 16,
) -> socket.socket:
    if transport == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # SO_REUSEADDR by default for listeners so re-binding after a crash works.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        apply_socket_options(sock, options)
        sock.bind((bind_host, bind_port))
        if multicast:
            join_multicast(sock, multicast)
        return sock

    if transport == "tcp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        apply_socket_options(sock, options)
        sock.bind((bind_host, bind_port))
        sock.listen(backlog)
        return sock

    raise TransportError(f"unsupported transport for listener: {transport!r}")


def join_multicast(sock: socket.socket, multicast: Mapping[str, Any]) -> None:
    """IP_ADD_MEMBERSHIP for LLMNR (224.0.0.252) / mDNS (224.0.0.251).

    ``interface`` is taken as an IP address; resolving an interface *name*
    (eth0) to its address is deferred - pass the IP for now, or 0.0.0.0.
    """
    group = multicast.get("group")
    if not group:
        raise TransportError("multicast config needs a 'group'")
    iface = multicast.get("interface") or "0.0.0.0"
    try:
        mreq = struct.pack("=4s4s", socket.inet_aton(group), socket.inet_aton(iface))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError as exc:
        raise TransportError(
            f"multicast join of {group} on {iface} failed: {exc} "
            "(interface must be an IP address, not a device name, in v0)"
        ) from exc
