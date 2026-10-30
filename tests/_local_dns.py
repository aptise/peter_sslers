"""Isolated DNS for Pebble: example.com names resolve only to loopback."""

from contextlib import contextmanager
import socketserver
import struct
import threading
from typing import Iterator
from typing import Mapping
from typing import Optional

import dns.message
import dns.query
import dns.rdatatype
import dns.rrset


def _read_exact(stream: object, size: int) -> bytes:
    # The request socket is always a real socket; this helper is kept separate
    # so partial TCP frames cannot silently turn into malformed DNS requests.
    import socket

    if not isinstance(stream, socket.socket):
        raise TypeError("Expected a DNS socket")
    value = bytearray()
    while len(value) < size:
        chunk = stream.recv(size - len(value))
        if not chunk:
            raise EOFError("Incomplete DNS frame")
        value.extend(chunk)
    return bytes(value)


@contextmanager
def local_http_dns(
    port: int = 18554,
    *,
    aliases: Optional[Mapping[str, str]] = None,
    authoritative_port: int = 18553,
) -> Iterator[None]:
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(2)
            length = struct.unpack("!H", _read_exact(self.request, 2))[0]
            question = dns.message.from_wire(_read_exact(self.request, length))
            answer = dns.message.make_response(question)
            for item in question.question:
                name = item.name.to_text().lower()
                if name.endswith(".example.com.") and item.rdtype == dns.rdatatype.A:
                    address = (
                        "127.0.0.2" if name.startswith("invalid-") else "127.0.0.1"
                    )
                    answer.answer.append(
                        dns.rrset.from_text(item.name, 0, "IN", "A", address)
                    )
                if aliases and name in aliases and item.rdtype == dns.rdatatype.TXT:
                    target = aliases[name].rstrip(".") + "."
                    forwarded = dns.query.tcp(
                        dns.message.make_query(target, dns.rdatatype.TXT),
                        "127.0.0.1",
                        port=authoritative_port,
                        timeout=2,
                    )
                    answer.answer.append(
                        dns.rrset.from_text(item.name, 0, "IN", "CNAME", target)
                    )
                    answer.answer.extend(forwarded.answer)
            wire = answer.to_wire()
            self.request.sendall(struct.pack("!H", len(wire)) + wire)

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with Server(("127.0.0.1", port), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield
        finally:
            server.shutdown()
            thread.join(timeout=3)
            if thread.is_alive():
                raise RuntimeError("Local DNS server failed to stop")
