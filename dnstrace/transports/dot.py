from __future__ import annotations

import asyncio
import ssl

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.rcode

from dnstrace.models import TraceResult
from dnstrace.transports.base import Transport


class DoTTransport(Transport):
    """DNS-over-TLS transport with certificate verification and SNI support."""

    name = "dot"

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

    def _ssl_context(self) -> ssl.SSLContext:
        if self.verify:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    async def query(self, domain: str, qtype: str) -> TraceResult:
        result = TraceResult(domain=domain, qtype=qtype, transport=self.name, server=self.server)
        result.event("query.build")
        message = dns.message.make_query(domain, qtype, want_dnssec=True)
        context = self._ssl_context()

        try:
            result.event("tcp.connect", server=self.server, port=self.port)
            result.event(
                "tls.handshake.start",
                server_hostname=self.server_hostname,
                verify=self.verify,
            )
            response = await dns.asyncquery.tls(
                message,
                self.server,
                port=self.port,
                timeout=self.timeout,
                ssl_context=context,
                server_hostname=self.server_hostname,
            )
            result.event("tls.handshake.complete")
            result.event("dns.receive", message_id=response.id)
            result.success = True
            result.rcode = dns.rcode.to_text(response.rcode())
            result.flags = dns.flags.to_text(response.flags).split()
            result.answers = [item.to_text() for rrset in response.answer for item in rrset]
        except (asyncio.TimeoutError, OSError, ssl.SSLError, dns.exception.DNSException) as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            result.event("query.error", error=result.error)
        finally:
            result.finish()
        return result
