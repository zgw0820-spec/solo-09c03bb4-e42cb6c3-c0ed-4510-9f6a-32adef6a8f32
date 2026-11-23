"""Sample upstream DNS server (dnslib) used to exercise the DNS64 service.

It answers from a scripted table so every DNS64 code path can be triggered
with a real UDP query:

======================  ================================================  ==========================================
name                    AAAA query                                        A query
======================  ================================================  ==========================================
native.example.         AAAA 2001:db8::53 (ttl 300)                       NODATA
gone.example.           NXDOMAIN                                          NXDOMAIN
web.example.            NODATA (neg-ttl 30)                               A 192.0.2.10 (ttl 60)
alias.example.          CNAME web.example. (ttl 45) + NODATA (neg 30)     CNAME web.example. (ttl 45) + A 192.0.2.10
noaddr.example.         NODATA (neg-ttl 20)                               NODATA (neg-ttl 20)
slow.example.           NODATA (neg-ttl 1)                                A 192.0.2.20 (ttl 60) after 1.5s delay
flap.example.           CNAME ep-a.example. + NODATA                      CNAME ep-b.example. + A 192.0.2.30
multi.example.          NODATA (neg-ttl 30)                               A 192.0.2.41 (ttl 120) + A 192.0.2.42 (ttl 25)
drop.example.           no response (client times out)                    no response
======================  ================================================  ==========================================
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from dnslib import QTYPE, RCODE, RR, A, AAAA, CNAME, SOA
from dnslib.server import BaseResolver, DNSServer

log = logging.getLogger("mock-upstream")

ZONE = "example."
SOA_SERIAL = 2026112201


def soa(neg_ttl: int) -> RR:
    """SOA whose TTL and MINIMUM both equal the wanted negative TTL."""
    return RR(
        ZONE,
        QTYPE.SOA,
        rdata=SOA(f"ns1.{ZONE}", f"hostmaster.{ZONE}",
                  (SOA_SERIAL, 7200, 3600, 1209600, neg_ttl)),
        ttl=neg_ttl,
    )


@dataclass
class Behaviour:
    """Scripted answer for one name."""

    aaaa_records: list = field(default_factory=list)   # RRs for the answer section
    a_records: list = field(default_factory=list)
    cname_for_aaaa: Optional[str] = None               # CNAME target, AAAA queries
    cname_for_a: Optional[str] = None                  # CNAME target, A queries
    cname_ttl: int = 45
    nxdomain: bool = False
    neg_ttl: int = 30                                  # negative TTL of NODATA replies
    delay: float = 0.0                                 # seconds to wait before answering
    drop: bool = False                                 # never answer (client times out)


ZONE_FILE = {
    "native.example.": Behaviour(
        aaaa_records=[("2001:db8::53", 300)],
    ),
    "gone.example.": Behaviour(nxdomain=True, neg_ttl=60),
    "web.example.": Behaviour(
        a_records=[("192.0.2.10", 60)],
        neg_ttl=30,
    ),
    "alias.example.": Behaviour(
        cname_for_aaaa="web.example.",
        cname_for_a="web.example.",
        cname_ttl=45,
        a_records=[("192.0.2.10", 60)],
        neg_ttl=30,
    ),
    "noaddr.example.": Behaviour(neg_ttl=20),
    "slow.example.": Behaviour(
        a_records=[("192.0.2.20", 60)],
        neg_ttl=1,          # negative cache lifetime of the no-AAAA answer
        delay=1.5,          # ... but the A reply arrives 1.5s later -> expired
    ),
    "flap.example.": Behaviour(
        cname_for_aaaa="ep-a.example.",   # the two queries see different
        cname_for_a="ep-b.example.",      # alias endpoints -> SERVFAIL
        cname_ttl=40,
        a_records=[("192.0.2.30", 60)],
        neg_ttl=30,
    ),
    "multi.example.": Behaviour(
        a_records=[("192.0.2.41", 120), ("192.0.2.42", 25)],
        neg_ttl=30,
    ),
    "drop.example.": Behaviour(drop=True),
}


class ScriptedResolver(BaseResolver):
    def __init__(self, zone: dict):
        self.zone = zone

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".").lower() + "."
        qtype = QTYPE[request.q.qtype]
        behaviour = self.zone.get(qname)

        reply = request.reply()
        if behaviour is None:
            # Unknown name inside our zone: NXDOMAIN.
            reply.header.rcode = RCODE.NXDOMAIN
            reply.add_auth(soa(60))
            return reply
        if behaviour.drop:
            log.info("%s %s: dropping (no response)", qname, qtype)
            time.sleep(10)  # longer than any client timeout
            return reply
        if behaviour.delay and qtype == "A":
            # The A reply arrives late (the AAAA reply is not delayed), so
            # the negative-caching window of the no-AAAA answer can expire
            # before the synthesis basis is complete.
            log.info("%s %s: delaying answer by %.1fs", qname, qtype, behaviour.delay)
            time.sleep(behaviour.delay)
        if behaviour.nxdomain:
            reply.header.rcode = RCODE.NXDOMAIN
            reply.add_auth(soa(behaviour.neg_ttl))
            return reply

        cname_target = behaviour.cname_for_aaaa if qtype == "AAAA" else behaviour.cname_for_a
        if cname_target:
            reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(cname_target),
                                ttl=behaviour.cname_ttl))
            owner = cname_target
        else:
            owner = qname

        records = behaviour.aaaa_records if qtype == "AAAA" else behaviour.a_records
        if qtype == "AAAA":
            for addr, ttl in records:
                reply.add_answer(RR(owner, QTYPE.AAAA, rdata=AAAA(addr), ttl=ttl))
        elif qtype == "A":
            for addr, ttl in records:
                reply.add_answer(RR(owner, QTYPE.A, rdata=A(addr), ttl=ttl))

        if not records:
            # NODATA: name exists, no record of this type -> SOA authority.
            reply.add_auth(soa(behaviour.neg_ttl))
        log.info("%s %s: %d answer(s), rcode=%s", qname, qtype,
                 len(reply.rr), RCODE[reply.header.rcode])
        return reply


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    resolver = ScriptedResolver(ZONE_FILE)
    server = DNSServer(
        resolver,
        address=os.environ.get("LISTEN_HOST", "0.0.0.0"),
        port=int(os.environ.get("LISTEN_PORT", "5353")),
        tcp=False,
    )
    server.start()
    log.info("mock upstream listening on UDP %s",
             os.environ.get("LISTEN_PORT", "5353"))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
