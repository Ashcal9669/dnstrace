from __future__ import annotations

import asyncio

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.rcode

from dnstrace.models import TraceResult
from dnstrace.transports.base import Transport


class DoHTransport(Transport):
    """DNS-over-HTTPS transport using RFC 8484 wire-format requests."""

    name = "doh"

    def __init__(
        self,
        server: str,
        port: int = 443,
        timeout: float = 3.0,
        *,
        url: str | None = None,
        verify: bool = True,
        post: bool = True,
    ) -> None:
        super().__init__(server=server, port=port, timeout=timeout)
        host = server.strip("[]")
        self.url = url or f"https://{host}:{port}/dns-query"
        self.verify = verify
        self.post = post

    async def query(self, domain: str, qtype: str) -> TraceResult:
        result = TraceResult(domain=domain, qtype=qtype, transport=self.name, server=self.server)
        result.event("query.build")
        message = dns.message.make_query(domain, qtype, want_dnssec=True)

        try:
            result.event("https.request.start", url=self.url, method="POST" if self.post else "GET")
            response = await dns.asyncquery.https(
                message,
                self.url,
                timeout=self.timeout,
                verify=self.verify,
                post=self.post,
            )
            result.event("https.response", message_id=response.id)
            result.success = True
            result.rcode = dns.rcode.to_text(response.rcode())
            result.flags = dns.flags.to_text(response.flags).split()
            result.answers = [item.to_text() for rrset in response.answer for item in rrset]
        except (asyncio.TimeoutError, OSError, dns.exception.DNSException) as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            result.event("query.error", error=result.error)
        finally:
            result.finish()
        return result
