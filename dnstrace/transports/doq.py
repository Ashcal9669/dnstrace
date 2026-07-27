from __future__ import annotations

import ssl

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.quic
import dns.rcode
from dns.quic._common import UnexpectedEOF

from dnstrace.dns_response import extract_answers
from dnstrace.models import TraceResult
from dnstrace.transports.base import Transport


class DoQTransport(Transport):
    """DNS-over-QUIC transport using RFC 9250 streams."""

    name = "doq"

    def __init__(
        self,
        server: str,
        port: int = 853,
        timeout: float = 3.0,
        *,
        server_hostname: str | None = None,
        verify: bool = True,
    ) -> None:
        super().__init__(server=server, port=port, timeout=timeout)
        self.server_hostname = server_hostname or server
        self.verify = verify

    async def query(self, domain: str, qtype: str) -> TraceResult:
        result = TraceResult(domain=domain, qtype=qtype, transport=self.name, server=self.server)
        result.event("query.build")
        message = dns.message.make_query(domain, qtype, want_dnssec=True)

        try:
            result.event(
                "quic.handshake.start",
                server=self.server,
                port=self.port,
                server_hostname=self.server_hostname,
                verify=self.verify,
            )
            verify_mode = ssl.CERT_REQUIRED if self.verify else ssl.CERT_NONE
            async with dns.quic.AsyncioQuicManager(
                verify_mode=verify_mode,
                server_name=self.server_hostname,
            ) as manager:
                connection = manager.connect(self.server, self.port)
                response = await dns.asyncquery.quic(
                    message,
                    self.server,
                    port=self.port,
                    timeout=self.timeout,
                    connection=connection,
                    server_hostname=self.server_hostname,
                )
                alpn = connection._connection.tls.alpn_negotiated
            result.evidence(alpn=alpn or "none", tls_version="TLSv1.3")
            result.event("quic.handshake.complete")
            result.event("quic.stream.receive", message_id=response.id)
            result.success = True
            result.rcode = dns.rcode.to_text(response.rcode())
            result.flags = dns.flags.to_text(response.flags).split()
            result.answers = extract_answers(response, qtype)
        except (TimeoutError, OSError, dns.exception.DNSException, UnexpectedEOF) as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            result.event("query.error", error=result.error)
        finally:
            result.finish()
        return result
