from __future__ import annotations

import ssl
import urllib.parse

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.quic
import dns.rcode
from dns.quic._common import UnexpectedEOF

from dnstrace.dns_response import extract_answers
from dnstrace.models import TraceResult
from dnstrace.transports.base import Transport


class DoH3Transport(Transport):
    """DNS-over-HTTPS over HTTP/3."""

    name = "doh3"

    def __init__(
        self,
        server: str,
        port: int = 443,
        timeout: float = 3.0,
        *,
        url: str | None = None,
        verify: bool = True,
        post: bool = True,
        bootstrap_address: str | None = None,
    ) -> None:
        super().__init__(server=server, port=port, timeout=timeout)
        host = server.strip("[]")
        self.url = url or f"https://{host}:{port}/dns-query"
        self.verify = verify
        self.post = post
        self.bootstrap_address = bootstrap_address

    async def query(self, domain: str, qtype: str) -> TraceResult:
        result = TraceResult(domain=domain, qtype=qtype, transport=self.name, server=self.server)
        result.event("query.build")
        message = dns.message.make_query(domain, qtype, want_dnssec=True)
        target = self.bootstrap_address or self.server
        hostname = urllib.parse.urlparse(self.url).hostname or self.server

        try:
            result.event(
                "http3.request.start",
                url=self.url,
                method="POST" if self.post else "GET",
                bootstrap_address=self.bootstrap_address,
                verify=self.verify,
            )
            verify_mode = ssl.CERT_REQUIRED if self.verify else ssl.CERT_NONE
            async with dns.quic.AsyncioQuicManager(
                verify_mode=verify_mode,
                server_name=hostname,
                h3=True,
            ) as manager:
                connection = manager.connect(target, self.port)
                response = await dns.asyncquery.https(
                    message,
                    self.url,
                    timeout=self.timeout,
                    verify=self.verify,
                    post=self.post,
                    bootstrap_address=self.bootstrap_address,
                    http_version=dns.query.HTTPVersion.H3,
                    client=connection,
                )
                alpn = connection._connection.tls.alpn_negotiated
            result.evidence(alpn=alpn or "none", tls_version="TLSv1.3")
            result.event("http3.response", message_id=response.id)
            result.success = True
            result.rcode = dns.rcode.to_text(response.rcode())
            result.flags = dns.flags.to_text(response.flags).split()
            result.answers = extract_answers(response, qtype)
        except (
            TimeoutError,
            OSError,
            ValueError,
            dns.exception.DNSException,
            UnexpectedEOF,
        ) as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            result.event("query.error", error=result.error)
        finally:
            result.finish()
        return result
