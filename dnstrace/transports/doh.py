from __future__ import annotations

import base64

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import httpx

from dnstrace.dns_response import extract_answers
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
        wire = message.to_wire()
        headers = {"accept": "application/dns-message"}

        try:
            result.event("https.request.start", url=self.url, method="POST" if self.post else "GET")
            async with httpx.AsyncClient(http1=True, http2=True, verify=self.verify) as client:
                if self.post:
                    headers.update(
                        {
                            "content-type": "application/dns-message",
                            "content-length": str(len(wire)),
                        }
                    )
                    response = await client.post(
                        self.url, headers=headers, content=wire, timeout=self.timeout
                    )
                else:
                    encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
                    response = await client.get(
                        self.url,
                        headers=headers,
                        params={"dns": encoded},
                        timeout=self.timeout,
                    )
                if response.status_code < 200 or response.status_code > 299:
                    raise ValueError(
                        f"{self.url} responded with status code {response.status_code}"
                    )
                network_stream = response.extensions.get("network_stream")
                ssl_object = network_stream.get_extra_info("ssl_object") if network_stream else None
                cipher = ssl_object.cipher() if ssl_object else None
                result.evidence(
                    http_version=response.http_version,
                    tls_version=ssl_object.version() if ssl_object else "unknown",
                    cipher=cipher[0] if cipher else "unknown",
                )
                response_wire = response.content
            result.event("https.response")
            try:
                response_message = dns.message.from_wire(response_wire)
            except dns.exception.DNSException as exc:
                raise ValueError(
                    f"{self.url} returned a 2xx status but a non-DNS response body "
                    f"({len(response_wire)} bytes): {response_wire[:100]!r}"
                ) from exc
            result.success = True
            result.rcode = dns.rcode.to_text(response_message.rcode())
            result.flags = dns.flags.to_text(response_message.flags).split()
            result.answers = extract_answers(response_message, qtype)
        except (
            TimeoutError,
            OSError,
            ValueError,
            dns.exception.DNSException,
            httpx.HTTPError,
        ) as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            result.event("query.error", error=result.error)
        finally:
            result.finish()
        return result
