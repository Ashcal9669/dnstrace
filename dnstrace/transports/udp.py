from __future__ import annotations

import asyncio

import dns.asyncquery
import dns.flags
import dns.message
import dns.rcode

from dnstrace.models import TraceResult
from dnstrace.transports.base import Transport


class UDPTransport(Transport):
    name = "udp"

    async def query(self, domain: str, qtype: str) -> TraceResult:
        result = TraceResult(domain=domain, qtype=qtype, transport=self.name, server=self.server)
        result.event("query.build")
        message = dns.message.make_query(domain, qtype, want_dnssec=True)
        try:
            result.event("udp.send", server=self.server, port=self.port)
            response = await dns.asyncquery.udp(
                message,
                self.server,
                port=self.port,
                timeout=self.timeout,
                ignore_unexpected=False,
            )
            result.event("udp.receive", message_id=response.id)
            result.success = True
            result.rcode = dns.rcode.to_text(response.rcode())
            result.flags = [name for bit, name in dns.flags._by_value.items() if response.flags & bit]
            result.answers = [item.to_text() for rrset in response.answer for item in rrset]
        except (asyncio.TimeoutError, OSError, dns.exception.DNSException) as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            result.event("query.error", error=result.error)
        finally:
            result.finish()
        return result
