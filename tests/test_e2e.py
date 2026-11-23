"""End-to-end tests: real UDP queries through the DNS64 server backed by the
scripted sample upstream."""

import socket
import time

import pytest
from dnslib import QTYPE, RCODE, DNSRecord
from dnslib.server import DNSServer

from dns64_server import DNS64Resolver
from mock_upstream import ScriptedResolver, ZONE_FILE

PREFETCH_DOMAINS = [
    "web.example.", "alias.example.", "slowaaaa.example.", "dropa.example.",
    "flap.example.", "prefetchflap.example.", "drop.example.",
]


def start_dns64(upstream_port, **kwargs):
    resolver = DNS64Resolver("127.0.0.1", upstream_port, "64:ff9b::/96", **kwargs)
    dns64 = DNSServer(resolver, address="127.0.0.1", port=0, tcp=False)
    dns64.start_thread()
    return dns64, dns64.server.server_address[1]


@pytest.fixture(scope="module")
def servers():
    upstream = DNSServer(ScriptedResolver(ZONE_FILE), address="127.0.0.1", port=0, tcp=False)
    upstream.start_thread()
    upstream_port = upstream.server.server_address[1]

    dns64, dns64_port = start_dns64(upstream_port, timeout=2.0)

    yield dns64_port

    dns64.stop()
    upstream.stop()


@pytest.fixture(scope="module")
def prefetch_servers():
    """Same upstream, DNS64 with speculative prefetch enabled."""
    upstream = DNSServer(ScriptedResolver(ZONE_FILE), address="127.0.0.1", port=0, tcp=False)
    upstream.start_thread()
    upstream_port = upstream.server.server_address[1]

    dns64, dns64_port = start_dns64(
        upstream_port, timeout=2.0,
        prefetch_domains=PREFETCH_DOMAINS,
        prefetch_concurrency=4,
    )

    yield {"port": dns64_port, "resolver": dns64.server.resolver}

    dns64.stop()
    upstream.stop()


def ask(port, name, qtype="AAAA", timeout=5.0):
    q = DNSRecord.question(name, qtype)
    try:
        raw = q.send("127.0.0.1", port, tcp=False, timeout=timeout)
    except (socket.timeout, TimeoutError):
        return None
    return DNSRecord.parse(raw)


def timed_ask(port, name, qtype="AAAA", timeout=5.0):
    started = time.monotonic()
    reply = ask(port, name, qtype=qtype, timeout=timeout)
    return reply, time.monotonic() - started


def test_native_aaaa_passthrough(servers):
    reply = ask(servers, "native.example.")
    assert RCODE[reply.header.rcode] == "NOERROR"
    aaaa = [rr for rr in reply.rr if rr.rtype == QTYPE.AAAA]
    assert len(aaaa) == 1
    assert str(aaaa[0].rdata) == "2001:db8::53"
    assert aaaa[0].ttl == 300


def test_nxdomain_passthrough(servers):
    reply = ask(servers, "gone.example.")
    assert RCODE[reply.header.rcode] == "NXDOMAIN"


def test_simple_synthesis(servers):
    reply = ask(servers, "web.example.")
    assert RCODE[reply.header.rcode] == "NOERROR"
    aaaa = [rr for rr in reply.rr if rr.rtype == QTYPE.AAAA]
    assert len(aaaa) == 1
    assert str(aaaa[0].rdata) == "64:ff9b::c000:20a"  # 192.0.2.10
    # min(negative 30, A 60) == 30
    assert 28 <= aaaa[0].ttl <= 30


def test_cname_alias_preserved(servers):
    reply = ask(servers, "alias.example.")
    assert RCODE[reply.header.rcode] == "NOERROR"
    cnames = [rr for rr in reply.rr if rr.rtype == QTYPE.CNAME]
    aaaa = [rr for rr in reply.rr if rr.rtype == QTYPE.AAAA]
    assert len(cnames) == 1
    assert str(cnames[0].rname) == "alias.example."
    assert str(cnames[0].rdata.label) == "web.example."
    assert len(aaaa) == 1
    assert str(aaaa[0].rname) == "web.example."
    assert str(aaaa[0].rdata) == "64:ff9b::c000:20a"
    # min(negative 30, A 60, CNAME 45) == 30
    assert 28 <= aaaa[0].ttl <= 30


def test_no_a_record_returns_nodata(servers):
    reply = ask(servers, "noaddr.example.")
    assert RCODE[reply.header.rcode] == "NOERROR"
    assert not reply.rr  # NODATA: empty answer section
    assert any(rr.rtype == QTYPE.SOA for rr in reply.auth)


def test_late_a_reply_expires_basis(servers):
    # slow.example.: negative TTL of the no-AAAA answer is 1s, but the A
    # reply only arrives after 1.5s -> synthesis basis expired -> SERVFAIL.
    reply = ask(servers, "slow.example.")
    assert RCODE[reply.header.rcode] == "SERVFAIL"


def test_inconsistent_alias_endpoints(servers):
    # flap.example.: the AAAA reply aliases to ep-a, the A reply to ep-b.
    reply = ask(servers, "flap.example.")
    assert RCODE[reply.header.rcode] == "SERVFAIL"


def test_multiple_a_records_min_ttl(servers):
    reply = ask(servers, "multi.example.")
    assert RCODE[reply.header.rcode] == "NOERROR"
    aaaa = [rr for rr in reply.rr if rr.rtype == QTYPE.AAAA]
    assert len(aaaa) == 2
    # min(negative 30, A 120, A 25) == 25
    assert all(23 <= rr.ttl <= 25 for rr in aaaa)


def test_upstream_timeout_gives_servfail(servers):
    reply = ask(servers, "drop.example.", timeout=5.0)
    assert RCODE[reply.header.rcode] == "SERVFAIL"


def test_non_aaaa_queries_are_proxied(servers):
    reply = ask(servers, "web.example.", qtype="A")
    assert RCODE[reply.header.rcode] == "NOERROR"
    a_records = [rr for rr in reply.rr if rr.rtype == QTYPE.A]
    assert len(a_records) == 1
    assert str(a_records[0].rdata) == "192.0.2.10"


# ---------------------------------------------------------------------------
# Speculative prefetch: real UDP behaviour
# ---------------------------------------------------------------------------


def test_prefetch_does_not_change_answers(prefetch_servers):
    port = prefetch_servers["port"]
    for name in ("web.example.", "alias.example.", "multi.example.",
                 "noaddr.example.", "native.example.", "gone.example.",
                 "slow.example.", "flap.example."):
        reply = ask(port, name)
        assert reply is not None, name
    # Spot-check the interesting ones against the serial expectation.
    reply = ask(port, "web.example.")
    aaaa = [rr for rr in reply.rr if rr.rtype == QTYPE.AAAA]
    assert str(aaaa[0].rdata) == "64:ff9b::c000:20a"
    assert 28 <= aaaa[0].ttl <= 30

    reply = ask(port, "alias.example.")
    assert [rr for rr in reply.rr if rr.rtype == QTYPE.CNAME]

    assert RCODE[ask(port, "flap.example.").header.rcode] == "SERVFAIL"
    assert RCODE[ask(port, "slow.example.").header.rcode] == "SERVFAIL"


def test_prefetch_hides_slow_aaaa_latency(servers, prefetch_servers):
    # slowaaaa.example. delays both replies by 1.5s.  Serial: AAAA (1.5s)
    # then A (1.5s) = ~3.0s.  Prefetch: the A query runs alongside the AAAA
    # query = ~1.5s.
    serial_reply, serial_elapsed = timed_ask(servers, "slowaaaa.example.", timeout=5.0)
    prefetch_reply, prefetch_elapsed = timed_ask(prefetch_servers["port"],
                                                 "slowaaaa.example.", timeout=5.0)

    assert RCODE[serial_reply.header.rcode] == "NOERROR"
    assert RCODE[prefetch_reply.header.rcode] == "NOERROR"
    assert serial_elapsed > 2.5
    assert prefetch_elapsed < 2.3
    # Answers agree.
    serial_aaaa = [rr for rr in serial_reply.rr if rr.rtype == QTYPE.AAAA]
    prefetch_aaaa = [rr for rr in prefetch_reply.rr if rr.rtype == QTYPE.AAAA]
    assert [str(rr.rdata) for rr in serial_aaaa] == [str(rr.rdata) for rr in prefetch_aaaa]
    assert 28 <= prefetch_aaaa[0].ttl <= 30


def test_prefetch_falls_back_when_a_endpoint_differs(prefetch_servers):
    # prefetchflap.example.: the speculative A aliases to ep-b, the AAAA
    # NODATA reply aliases to ep-a, so the prefetched reply is unusable and
    # the normal fallback A query (also ep-b) ends in SERVFAIL.
    reply = ask(prefetch_servers["port"], "prefetchflap.example.")
    assert RCODE[reply.header.rcode] == "SERVFAIL"


def test_prefetch_shared_deadline_gives_servfail_not_hang(prefetch_servers):
    # dropa.example.: A answer comes after 5s; the shared A deadline is the
    # normal 2s timeout counted from the NODATA arrival -> SERVFAIL quickly.
    reply, elapsed = timed_ask(prefetch_servers["port"], "dropa.example.", timeout=5.0)
    assert RCODE[reply.header.rcode] == "SERVFAIL"
    assert elapsed < 3.0


def test_prefetch_slots_are_bounded_under_load(prefetch_servers):
    """Concurrent queries for listed names still resolve correctly."""
    port = prefetch_servers["port"]
    names = ["web.example.", "alias.example.", "multi.example.", "noaddr.example."] * 3
    results = []

    def run(name):
        results.append(ask(port, name, timeout=5.0))

    import threading
    threads = [threading.Thread(target=run, args=(n,)) for n in names]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == len(names)
    assert all(r is not None for r in results)
    assert all(RCODE[r.header.rcode] == "NOERROR" for r in results)
    # Slots eventually drain back to zero.
    resolver = prefetch_servers["resolver"]
    deadline = time.monotonic() + 2.0
    while resolver.prefetcher.in_flight and time.monotonic() < deadline:
        time.sleep(0.05)
    assert resolver.prefetcher.in_flight == 0
