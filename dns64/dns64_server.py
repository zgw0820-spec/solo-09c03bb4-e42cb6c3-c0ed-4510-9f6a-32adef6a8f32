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

Speculative A prefetch
----------------------
* ``DNS64_PREFETCH_DOMAINS`` lists names for which the A query is started in
  a background thread *while* the AAAA query is still in flight.
* At most ``DNS64_PREFETCH_CONCURRENCY`` speculative A queries may run at
  once.  When the quota is exhausted (or the name is not listed) the resolver
  uses the normal serial AAAA-then-A flow.
* A reply that makes the A query unnecessary (native AAAA, NXDOMAIN, ...) is
  returned immediately; the speculative query keeps its slot until the
  upstream answer arrives.
* A prefetched A reply is only used when it is NOERROR, points at the same
  endpoint as the AAAA NODATA reply, contains A records, and still satisfies
  the TTL/negative-caching rules above.  TTLs are counted from the moment
  each reply arrived (the prefetched A reply arrived earlier, so its
  remaining TTL is smaller).
* If the prefetched A reply cannot be used, the original NODATA reply is
  kept and the normal A query is sent as a fallback.  Waiting for the
  prefetched reply and the fallback query share one deadline: the normal
  A-query timeout counted from the arrival of the NODATA reply.  If that
  deadline passes, the answer is SERVFAIL.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from dnslib import QTYPE, RCODE, RR, AAAA, DNSRecord
from dnslib.server import BaseResolver, DNSServer

log = logging.getLogger("dns64")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _norm(name) -> str:
    """Normalize a DNS name for comparison (lowercase, single trailing dot)."""
    return str(name).rstrip(".").lower() + "."


def parse_domain_list(raw: str) -> list[str]:
    """Parse a comma/whitespace separated list of domain names."""
    return [part for part in re.split(r"[,;\s]+", raw or "") if part]


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


QueryFunc = Callable[[str, str, str, int, float], UpstreamExchange]


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
# Speculative A prefetch
# ---------------------------------------------------------------------------


class PrefetchJob:
    """Handle for one speculative A query running in a background thread."""

    def __init__(self, name: str):
        self.name = name
        self._done = threading.Event()
        self._exchange: Optional[UpstreamExchange] = None
        self._error: Optional[BaseException] = None

    def finish(self, exchange: Optional[UpstreamExchange] = None,
               error: Optional[BaseException] = None) -> None:
        self._exchange = exchange
        self._error = error
        self._done.set()

    def wait(self, timeout: float) -> bool:
        """Wait for completion; returns False when the timeout expires."""
        return self._done.wait(timeout)

    @property
    def done(self) -> bool:
        return self._done.is_set()

    @property
    def exchange(self) -> Optional[UpstreamExchange]:
        return self._exchange

    @property
    def error(self) -> Optional[BaseException]:
        return self._error


class SpeculativePrefetcher:
    """Start A queries early for listed names, bounded by a concurrency limit.

    A slot is acquired before the background query starts and released only
    when that query finishes, independently of when the client-facing resolve
    call returns.
    """

    def __init__(self, domains: Iterable[str], concurrency: int,
                 upstream_host: str, upstream_port: int, timeout: float,
                 query_func: QueryFunc = query_upstream):
        self.domains = frozenset(_norm(d) for d in domains if d)
        self.concurrency = max(0, int(concurrency))
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.timeout = timeout
        self.query_func = query_func
        self._semaphore = (
            threading.BoundedSemaphore(self.concurrency) if self.concurrency else None
        )
        self._state_lock = threading.Lock()
        self._in_flight = 0

    @property
    def enabled(self) -> bool:
        return self.concurrency > 0 and bool(self.domains)

    @property
    def in_flight(self) -> int:
        with self._state_lock:
            return self._in_flight

    def is_listed(self, name: str) -> bool:
        return _norm(name) in self.domains

    def start(self, name: str) -> Optional[PrefetchJob]:
        """Start a speculative A query, or return None if not applicable.

        None means the caller should use the normal serial flow: either the
        name is not listed, prefetch is disabled, or every slot is busy.
        A slot is reserved before the thread is created, so concurrent
        resolve calls cannot overshoot ``concurrency``.
        """
        if not self.enabled or not self.is_listed(name):
            return None
        if not self._semaphore.acquire(blocking=False):
            log.info(
                "prefetch %s: no free slot (%d in flight) -> serial flow",
                _norm(name), self.in_flight,
            )
            return None

        job = PrefetchJob(_norm(name))
        with self._state_lock:
            self._in_flight += 1
            in_flight = self._in_flight
        thread = threading.Thread(
            target=self._run, args=(name, job), daemon=True,
            name=f"dns64-prefetch-{_norm(name)}",
        )
        try:
            thread.start()
        except BaseException:
            with self._state_lock:
                self._in_flight -= 1
            self._semaphore.release()
            raise
        log.info("prefetch %s: speculative A query started (%d/%d slots)",
                 _norm(name), in_flight, self.concurrency)
        return job

    def _run(self, name: str, job: PrefetchJob) -> None:
        try:
            exchange = self.query_func(
                name, "A", self.upstream_host, self.upstream_port, self.timeout,
            )
        except Exception as exc:  # noqa: BLE001 - reported to the waiter
            log.info("prefetch %s: A query failed: %s", _norm(name), exc)
            job.finish(error=exc)
        else:
            log.info("prefetch %s: A reply received", _norm(name))
            job.finish(exchange=exchange)
        finally:
            with self._state_lock:
                self._in_flight -= 1
            self._semaphore.release()


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


@dataclass
class SynthesisPlan:
    """Everything needed to emit a synthesized answer."""

    ttl: int
    a_records: list
    cname: Optional[RR] = None
    cname_ttl: Optional[int] = None
    basis: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# The DNS64 resolver
# ---------------------------------------------------------------------------


class DNS64Resolver(BaseResolver):
    def __init__(self, upstream_host: str, upstream_port: int, prefix: str,
                 timeout: float = 2.0, prefetch_domains: Optional[Iterable[str]] = None,
                 prefetch_concurrency: int = 0, query_func: QueryFunc = query_upstream):
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        net = ipaddress.IPv6Network(prefix)
        if net.prefixlen != 96:
            raise ValueError("DNS64 prefix must be a /96")
        self.prefix = net
        self.timeout = timeout
        self.query_func = query_func
        self.prefetcher = SpeculativePrefetcher(
            domains=list(prefetch_domains or []),
            concurrency=prefetch_concurrency,
            upstream_host=upstream_host,
            upstream_port=upstream_port,
            timeout=timeout,
            query_func=query_func,
        )

    # -- main entry point called by dnslib's DNSServer ----------------------
    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        if qtype != "AAAA":
            # Transparent proxy for anything that is not an AAAA query.
            try:
                up = self.query_func(qname, qtype, self.upstream_host,
                                     self.upstream_port, self.timeout)
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
        # Start the speculative A query first so that it overlaps with the
        # AAAA query.  The job keeps its slot until its own query finishes,
        # even if this resolve call returns early.
        prefetch_job = self.prefetcher.start(qname)

        aaaa_up = self.query_func(qname, "AAAA", self.upstream_host,
                                  self.upstream_port, self.timeout)
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

        # Waiting for the prefetched reply and the fallback query share this
        # deadline: one normal A-query timeout counted from *this* NODATA
        # reply's arrival.
        deadline = aaaa_up.arrived + self.timeout

        if prefetch_job is not None:
            prefetched = self._reply_from_prefetch(
                request, qname, aaaa_up, endpoint_aaaa, neg_ttl, deadline, prefetch_job,
            )
            if prefetched is not None:
                return prefetched
            # Fallback A query shares the deadline that started at the
            # moment this NODATA reply arrived.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                log.warning("AAAA %s: shared A deadline expired before fallback -> SERVFAIL",
                            qname)
                return self._servfail(request)
            a_up = self.query_func(qname, "A", self.upstream_host,
                                   self.upstream_port, remaining)
        else:
            # Normal serial flow: one A-query timeout of its own.
            a_up = self.query_func(qname, "A", self.upstream_host,
                                   self.upstream_port, self.timeout)
        return self._finish_with_a_reply(request, qname, aaaa_up, endpoint_aaaa, neg_ttl, a_up)

    def _reply_from_prefetch(self, request: DNSRecord, qname: str,
                             aaaa_up: UpstreamExchange, endpoint_aaaa: str,
                             neg_ttl: Optional[int], deadline: float,
                             job: PrefetchJob) -> Optional[DNSRecord]:
        """Return a finished reply from the prefetched A reply, or None.

        None means the prefetched reply cannot be used and the caller must
        keep the NODATA reply and run the normal fallback A query.  A
        SERVFAIL reply means the shared A deadline expired while waiting.
        """
        wait_for = max(0.0, deadline - time.monotonic())
        if not job.wait(wait_for):
            log.warning(
                "AAAA %s: shared A deadline expired while waiting for prefetched A -> SERVFAIL",
                qname,
            )
            return self._servfail(request)

        if job.error is not None:
            log.info("AAAA %s: prefetched A unavailable (%s); falling back to A query",
                     qname, job.error)
            return None

        a_up = job.exchange
        a_reply = a_up.reply if a_up is not None else None
        if a_reply is None:
            log.info("AAAA %s: prefetched A empty; falling back to A query", qname)
            return None

        a_rcode = RCODE[a_reply.header.rcode]
        if a_rcode != "NOERROR":
            log.info("AAAA %s: prefetched A rcode=%s; falling back to A query",
                     qname, a_rcode)
            return None

        endpoint_a = extract_endpoint(a_reply, qname)
        if endpoint_a != endpoint_aaaa:
            log.info(
                "AAAA %s: prefetched A endpoint %s != AAAA endpoint %s; falling back to A query",
                qname, endpoint_a, endpoint_aaaa,
            )
            return None

        a_records = [rr for rr in _records(a_reply, QTYPE.A)
                     if _norm(rr.rname) == endpoint_a]
        if not a_records:
            log.info("AAAA %s: prefetched A has no A record; falling back to A query", qname)
            return None

        plan, basis = self._plan_synthesis(
            aaaa_up, a_up, a_records, neg_ttl, qname,
        )
        if plan is None:
            log.info(
                "AAAA %s: prefetched A fails TTL rules %s; falling back to A query",
                qname, {k: round(v, 3) for k, v in basis.items()},
            )
            return None

        log.info(
            "AAAA %s: using prefetched A via endpoint %s, ttl=%d (basis: %s)",
            qname, endpoint_a, plan.ttl,
            {k: round(v, 2) for k, v in plan.basis.items()},
        )
        return self._build_synthesized(request, qname, endpoint_a, plan)

    def _finish_with_a_reply(self, request: DNSRecord, qname: str,
                             aaaa_up: UpstreamExchange, endpoint_aaaa: str,
                             neg_ttl: Optional[int], a_up: UpstreamExchange) -> DNSRecord:
        """Apply the original endpoint / no-A / synthesis rules to an A reply."""
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
            return self._passthrough(request, aaaa_up.reply)

        return self._synthesize(request, qname, endpoint_a, aaaa_up, a_up,
                                a_records, neg_ttl)

    # -- synthesis -----------------------------------------------------------
    def _plan_synthesis(self, aaaa_up: UpstreamExchange, a_up: UpstreamExchange,
                        a_records: list, neg_ttl: Optional[int], qname: str,
                        now: Optional[float] = None,
                        ) -> tuple[Optional[SynthesisPlan], dict]:
        """Build a synthesis plan, or (None, basis) if the basis expired."""
        now = time.monotonic() if now is None else now

        # Remaining lifetimes of everything the synthesis is based on.  Each
        # is counted from the moment its own upstream reply arrived.
        basis = {}
        if neg_ttl is not None:
            basis["negative-ttl"] = aaaa_up.remaining(neg_ttl, now)
        else:
            basis["negative-ttl"] = 0.0  # no SOA -> nothing we may cache
        basis["A"] = min(a_up.remaining(int(rr.ttl), now) for rr in a_records)

        cname_from_aaaa = first_cname_for(aaaa_up.reply, qname)
        cname_rr = cname_from_aaaa or first_cname_for(a_up.reply, qname)
        cname_exchange = aaaa_up if cname_from_aaaa else a_up
        if cname_rr is not None:
            basis["CNAME"] = cname_exchange.remaining(int(cname_rr.ttl), now)

        synth_ttl = int(min(basis.values()))
        if synth_ttl < 1:
            return None, basis

        cname_ttl = max(1, int(basis["CNAME"])) if cname_rr is not None else None
        return SynthesisPlan(
            ttl=synth_ttl, a_records=list(a_records), cname=cname_rr,
            cname_ttl=cname_ttl, basis=basis,
        ), basis

    def _synthesize(self, request, qname, endpoint, aaaa_up, a_up, a_records, neg_ttl,
                    now: Optional[float] = None) -> DNSRecord:
        plan, basis = self._plan_synthesis(
            aaaa_up, a_up, a_records, neg_ttl, qname, now=now,
        )
        if plan is None:
            log.warning("AAAA %s: synthesis basis expired %s -> SERVFAIL",
                        qname, {k: round(v, 3) for k, v in basis.items()})
            return self._servfail(request)
        return self._build_synthesized(request, qname, endpoint, plan)

    def _build_synthesized(self, request: DNSRecord, qname: str, endpoint: str,
                           plan: SynthesisPlan) -> DNSRecord:
        out = request.reply()
        # Keep the alias: copy the CNAME with its remaining TTL.
        if plan.cname is not None:
            out.add_answer(RR(plan.cname.rname, QTYPE.CNAME,
                              rdata=plan.cname.rdata, ttl=plan.cname_ttl))
        for rr in plan.a_records:
            v6 = self._map_address(str(rr.rdata))
            out.add_answer(RR(endpoint, QTYPE.AAAA, rdata=AAAA(v6), ttl=plan.ttl))
        log.info(
            "AAAA %s: synthesized %d record(s) via endpoint %s, ttl=%d (basis: %s)",
            qname, len(plan.a_records), endpoint, plan.ttl,
            {k: round(v, 2) for k, v in plan.basis.items()},
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
    prefetch_domains = parse_domain_list(os.environ.get("DNS64_PREFETCH_DOMAINS", ""))
    prefetch_concurrency = int(os.environ.get("DNS64_PREFETCH_CONCURRENCY", "0"))
    resolver = DNS64Resolver(
        upstream_host=os.environ.get("UPSTREAM_HOST", "127.0.0.1"),
        upstream_port=int(os.environ.get("UPSTREAM_PORT", "5353")),
        prefix=os.environ.get("DNS64_PREFIX", "64:ff9b::/96"),
        timeout=float(os.environ.get("UPSTREAM_TIMEOUT", "2.0")),
        prefetch_domains=prefetch_domains,
        prefetch_concurrency=prefetch_concurrency,
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
    log.info("DNS64 speculative prefetch: domains=%s, concurrency=%d",
             sorted(resolver.prefetcher.domains) if resolver.prefetcher.enabled else "disabled",
             resolver.prefetcher.concurrency)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
