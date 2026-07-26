from __future__ import annotations

import dns.message
import dns.rdatatype


def extract_answers(response: dns.message.Message, qtype: str) -> list[str]:
    """Return only records relevant to the requested type, excluding DNSSEC metadata."""
    requested = dns.rdatatype.from_text(qtype)
    allowed = {requested, dns.rdatatype.CNAME}
    return [
        item.to_text()
        for rrset in response.answer
        if rrset.rdtype in allowed
        for item in rrset
    ]
