"""DNS64 server built on dnslib.

Receives UDP DNS queries (primarily AAAA) and synthesizes AAAA records from
A records using a configured /96 prefix, RFC 6147 style, with an extra
consistency check: the AAAA (NODATA) reply and the follow-up A reply must
agree on the same endpoint (final name after at most one CNAME hop).

Behaviour summary
-----------------
* Native AAAA answers and NXDOMAIN replies are returned to the client as-is.
* Only when the name exists but has no AAAA (NOERROR/NODATA) *and* the two
  upstream replies (the AAAA reply and the A reply) point to the same
  endpoint do we synthesize AAAA records from the A records + /96 prefix.
* One CNAME hop is supported; the synthesized answer keeps the CNAME (alias)
  record in the answer section.
* If the endpoints match but there is no A record either, the original
  no-data (NODATA) answer is returned unchanged.
* The synthesized TTL is the minimum of:
    - the negative-caching period of the no-AAAA answer
      (min(SOA TTL, SOA MINIMUM), RFC 2308),
    - the remaining TTL of the A record(s),
    - the remaining TTL of the CNAME actually used,
  where each remaining lifetime is counted from the moment its own upstream
  reply arrived.
* Upstream timeout, inconsistent endpoints, or an expired synthesis basis
  all produce SERVFAIL.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import time
from dataclasses import dataclass, field
from typing import Optional

from dnslib import QTYPE, RCODE, RR, AAAA, DNSRecord
from dnslib.server import BaseResolver, DNSServer

log = logging.getLogger("dns64")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _norm(name) -> str:
    """Normalize a DNS name for comparison (lowercase, single trailing dot)."""
    return str(name).rstrip(".").lower() + "."


class UpstreamTimeout(Exception):
    """Raised when the upstream does not answer within the timeout."""


@dataclass
class UpstreamExchange:
    """An upstream reply plus the moment it arrived.

    Remaining TTLs of every record in the reply are counted from ``arrived``.
    """

    reply: DNSRecord
    arrived: float = field(default_factory=time.monotonic)

    def remaining(self, ttl: int, now: Optional[float] = None) -> float:
        now = time.monotonic() if now is None else now
        return ttl - (now - self.arrived)


def query_upstream(name: str, qtype: str, host: str, port: int, timeout: float) -> UpstreamExchange:
    """Send one UDP query to the upstream and return the timed reply."""
    q = DNSRecord.question(name, qtype)
    try:
        reply = q.send(host, port, tcp=False, timeout=timeout)
    except (socket.timeout, TimeoutError) as exc:
        raise UpstreamTimeout(f"upstream {host}:{port} timed out after {timeout}s") from exc
    except OSError as exc:  # e.g. ICMP port unreachable -> ECONNREFUSED on UDP
        raise UpstreamTimeout(f"upstream {host}:{port} unreachable: {exc}") from exc
    return UpstreamExchange(reply=DNSRecord.parse(reply) if isinstance(reply, bytes) else reply)


# ---------------------------------------------------------------------------
# Reply inspection helpers
# ---------------------------------------------------------------------------


def _records(reply: DNSRecord, rtype: int):
    return [rr for rr in reply.rr if rr.rtype == rtype]


def extract_endpoint(reply: DNSRecord, qname: str) -> str:
    """Endpoint of a reply: the first CNAME target for qname, else qname.

    Only one CNAME hop is followed, per the supported feature set.
    """
    wanted = _norm(qname)
    for rr in _records(reply, QTYPE.CNAME):
        if _norm(rr.rname) == wanted:
            return _norm(rr.rdata.label)
    return wanted


def extract_negative_ttl(reply: DNSRecord) -> Optional[int]:
    """Negative-caching period (RFC 2308): min(SOA TTL, SOA MINIMUM).

    dnslib keeps the SOA numeric fields in ``rdata.times`` where index 4 is
    the MINIMUM field.
    """
    for rr in reply.auth:
        if rr.rtype == QTYPE.SOA:
            return min(int(rr.ttl), int(rr.rdata.times[4]))
    return None


def first_cname_for(reply: DNSRecord, qname: str) -> Optional[RR]:
    wanted = _norm(qname)
    for rr in _records(reply, QTYPE.CNAME):
        if _norm(rr.rname) == wanted:
            return rr
    return None


# ---------------------------------------------------------------------------
# The DNS64 resolver
# ---------------------------------------------------------------------------


class DNS64Resolver(BaseResolver):
    def __init__(self, upstream_host: str, upstream_port: int, prefix: str, timeout: float = 2.0):
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        net = ipaddress.IPv6Network(prefix)
        if net.prefixlen != 96:
            raise ValueError("DNS64 prefix must be a /96")
        self.prefix = net
        self.timeout = timeout

    # -- main entry point called by dnslib's DNSServer ----------------------
    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        if qtype != "AAAA":
            # Transparent proxy for anything that is not an AAAA query.
            try:
                up = query_upstream(qname, qtype, self.upstream_host, self.upstream_port, self.timeout)
            except UpstreamTimeout:
                return self._servfail(request)
            return self._passthrough(request, up.reply)
        try:
            return self._resolve_aaaa(request, qname)
        except UpstreamTimeout as exc:
            log.warning("AAAA %s: %s -> SERVFAIL", qname, exc)
            return self._servfail(request)

    # -- AAAA handling -------------------------------------------------------
    def _resolve_aaaa(self, request: DNSRecord, qname: str) -> DNSRecord:
        aaaa_up = query_upstream(qname, "AAAA", self.upstream_host, self.upstream_port, self.timeout)
        reply = aaaa_up.reply
        rcode = RCODE[reply.header.rcode]

        if rcode == "NXDOMAIN":
            log.info("AAAA %s: NXDOMAIN from upstream, passthrough", qname)
            return self._passthrough(request, reply)
        if rcode != "NOERROR":
            log.info("AAAA %s: upstream rcode=%s, passthrough", qname, rcode)
            return self._passthrough(request, reply)
        if _records(reply, QTYPE.AAAA):
            log.info("AAAA %s: native AAAA answer, passthrough", qname)
            return self._passthrough(request, reply)

        # NOERROR + no AAAA in the answer: the name exists but has no AAAA.
        endpoint_aaaa = extract_endpoint(reply, qname)
        neg_ttl = extract_negative_ttl(reply)
        log.info(
            "AAAA %s: NODATA (endpoint=%s, negative-ttl=%s); querying A",
            qname, endpoint_aaaa, neg_ttl,
        )

        a_up = query_upstream(qname, "A", self.upstream_host, self.upstream_port, self.timeout)
        a_reply = a_up.reply
        if RCODE[a_reply.header.rcode] != "NOERROR":
            # e.g. A is NXDOMAIN while AAAA was NODATA: endpoints cannot be
            # shown to be the same -> treat as inconsistent.
            log.warning("AAAA %s: A reply rcode=%s while AAAA was NODATA -> SERVFAIL",
                        qname, RCODE[a_reply.header.rcode])
            return self._servfail(request)

        endpoint_a = extract_endpoint(a_reply, qname)
        if endpoint_a != endpoint_aaaa:
            log.warning(
                "AAAA %s: endpoint mismatch (AAAA reply -> %s, A reply -> %s) -> SERVFAIL",
                qname, endpoint_aaaa, endpoint_a,
            )
            return self._servfail(request)

        a_records = [rr for rr in _records(a_reply, QTYPE.A)
                     if _norm(rr.rname) == endpoint_a]
        if not a_records:
            # Same endpoint but no A either: hand back the original
            # no-data answer untouched.
            log.info("AAAA %s: endpoints match (%s) but no A record; returning NODATA",
                     qname, endpoint_a)
            return self._passthrough(request, reply)

        return self._synthesize(request, qname, endpoint_a, aaaa_up, a_up, a_records, neg_ttl)

    # -- synthesis -----------------------------------------------------------
    def _synthesize(self, request, qname, endpoint, aaaa_up, a_up, a_records, neg_ttl) -> DNSRecord:
        now = time.monotonic()

        # Remaining lifetimes of everything the synthesis is based on.
        basis = {}
        if neg_ttl is not None:
            basis["negative-ttl"] = aaaa_up.remaining(neg_ttl, now)
        else:
            basis["negative-ttl"] = 0.0  # no SOA -> nothing we may cache
        basis["A"] = min(a_up.remaining(int(rr.ttl), now) for rr in a_records)

        cname_rr = first_cname_for(aaaa_up.reply, qname) or first_cname_for(a_up.reply, qname)
        cname_exchange = aaaa_up if first_cname_for(aaaa_up.reply, qname) else a_up
        if cname_rr is not None:
            basis["CNAME"] = cname_exchange.remaining(int(cname_rr.ttl), now)

        synth_ttl = int(min(basis.values()))
        if synth_ttl < 1:
            expired = {k: round(v, 3) for k, v in basis.items()}
            log.warning("AAAA %s: synthesis basis expired %s -> SERVFAIL", qname, expired)
            return self._servfail(request)

        out = request.reply()
        # Keep the alias: copy the CNAME with its remaining TTL.
        if cname_rr is not None:
            out.add_answer(RR(cname_rr.rname, QTYPE.CNAME,
                              rdata=cname_rr.rdata,
                              ttl=max(1, int(cname_exchange.remaining(int(cname_rr.ttl))))))
        for rr in a_records:
            v6 = self._map_address(str(rr.rdata))
            out.add_answer(RR(endpoint, QTYPE.AAAA, rdata=AAAA(v6), ttl=synth_ttl))
        log.info(
            "AAAA %s: synthesized %d record(s) via endpoint %s, ttl=%d (basis: %s)",
            qname, len(a_records), endpoint, synth_ttl,
            {k: round(v, 2) for k, v in basis.items()},
        )
        return out

    def _map_address(self, ipv4: str) -> str:
        v4 = ipaddress.IPv4Address(ipv4)
        return str(ipaddress.IPv6Address(int(self.prefix.network_address) | int(v4)))

    # -- response builders ---------------------------------------------------
    @staticmethod
    def _passthrough(request: DNSRecord, upstream_reply: DNSRecord) -> DNSRecord:
        upstream_reply.header.id = request.header.id
        return upstream_reply

    @staticmethod
    def _servfail(request: DNSRecord) -> DNSRecord:
        out = request.reply()
        out.header.rcode = RCODE.SERVFAIL
        return out


# ---------------------------------------------------------------------------
# Server bootstrap
# ---------------------------------------------------------------------------


def make_server(resolver: DNS64Resolver, host: str, port: int) -> DNSServer:
    # UDP only: the collector-facing service listens for UDP AAAA queries.
    return DNSServer(resolver, address=host, port=port, tcp=False)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    resolver = DNS64Resolver(
        upstream_host=os.environ.get("UPSTREAM_HOST", "127.0.0.1"),
        upstream_port=int(os.environ.get("UPSTREAM_PORT", "5353")),
        prefix=os.environ.get("DNS64_PREFIX", "64:ff9b::/96"),
        timeout=float(os.environ.get("UPSTREAM_TIMEOUT", "2.0")),
    )
    server = make_server(
        resolver,
        host=os.environ.get("LISTEN_HOST", "0.0.0.0"),
        port=int(os.environ.get("LISTEN_PORT", "5354")),
    )
    server.start()
    log.info("DNS64 listening on UDP %s:%s, upstream=%s:%s, prefix=%s",
             os.environ.get("LISTEN_HOST", "0.0.0.0"),
             os.environ.get("LISTEN_PORT", "5354"),
             resolver.upstream_host, resolver.upstream_port, resolver.prefix)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
