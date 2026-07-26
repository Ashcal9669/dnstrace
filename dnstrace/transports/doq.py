from __future__ import annotations

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.rcode

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
            response = await dns.asyncquery.quic(
                message,
                self.server,
                port=self.port,
                timeout=self.timeout,
                verify=self.verify,
                server_hostname=self.server_hostname,
            )
            result.event("quic.handshake.complete")
            result.event("quic.stream.receive", message_id=response.id)
            result.success = True
            result.rcode = dns.rcode.to_text(response.rcode())
            result.flags = dns.flags.to_text(response.flags).split()
            result.answers = [item.to_text() for rrset in response.answer for item in rrset]
        except (TimeoutError, OSError, dns.exception.DNSException) as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            result.event("query.error", error=result.error)
        finally:
            result.finish()
        return result
