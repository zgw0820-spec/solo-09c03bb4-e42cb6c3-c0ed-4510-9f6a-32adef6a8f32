"""Unit tests for the DNS64 synthesis logic (no network involved)."""

import threading
import time

import pytest
from dnslib import QTYPE, RCODE, RR, A, AAAA, CNAME, SOA, DNSRecord

from dns64_server import (
    DNS64Resolver,
    PrefetchJob,
    SpeculativePrefetcher,
    UpstreamExchange,
    UpstreamTimeout,
    extract_endpoint,
    extract_negative_ttl,
    parse_domain_list,
)


def query_upstream_stub(name, qtype, host, port, timeout):
    """Default query function: never called by the pure-logic tests."""
    raise AssertionError(f"unexpected upstream query: {qtype} {name}")


def make_resolver(prefetch_domains=None, prefetch_concurrency=0, timeout=0.5,
                  query_func=None):
    return DNS64Resolver("127.0.0.1", 5353, "64:ff9b::/96", timeout=timeout,
                         prefetch_domains=prefetch_domains,
                         prefetch_concurrency=prefetch_concurrency,
                         query_func=query_func or query_upstream_stub)


def nodata_reply(name, neg_ttl=30, cname=None, cname_ttl=45):
    reply = DNSRecord.question(name, "AAAA").reply()
    if cname:
        reply.add_answer(RR(name, QTYPE.CNAME, rdata=CNAME(cname), ttl=cname_ttl))
    reply.add_auth(RR("example.", QTYPE.SOA,
                      rdata=SOA("ns1.example.", "hostmaster.example.",
                                (1, 7200, 3600, 1209600, neg_ttl)),
                      ttl=neg_ttl))
    return reply


def a_reply(name, records, cname=None, cname_ttl=45):
    reply = DNSRecord.question(name, "A").reply()
    owner = name
    if cname:
        reply.add_answer(RR(name, QTYPE.CNAME, rdata=CNAME(cname), ttl=cname_ttl))
        owner = cname
    for addr, ttl in records:
        reply.add_answer(RR(owner, QTYPE.A, rdata=A(addr), ttl=ttl))
    return reply


def test_address_mapping():
    resolver = make_resolver()
    assert resolver._map_address("192.0.2.10") == "64:ff9b::c000:20a"
    assert resolver._map_address("0.0.0.1") == "64:ff9b::1"


def test_prefix_must_be_96():
    import pytest

    with pytest.raises(ValueError):
        DNS64Resolver("127.0.0.1", 5353, "64:ff9b::/64")


def test_extract_endpoint_plain():
    reply = nodata_reply("web.example.")
    assert extract_endpoint(reply, "web.example.") == "web.example."


def test_extract_endpoint_cname_one_hop():
    reply = nodata_reply("alias.example.", cname="web.example.")
    assert extract_endpoint(reply, "alias.example.") == "web.example."


def test_extract_endpoint_normalizes_case_and_dot():
    reply = nodata_reply("alias.example.", cname="Web.Example.")
    assert extract_endpoint(reply, "ALIAS.example") == "web.example."


def test_extract_negative_ttl_min_of_ttl_and_minimum():
    reply = DNSRecord.question("x.example.", "AAAA").reply()
    reply.add_auth(RR("example.", QTYPE.SOA,
                      rdata=SOA("ns1.example.", "h.example.", (1, 1, 1, 1, 10)),
                      ttl=25))
    assert extract_negative_ttl(reply) == 10


def test_extract_negative_ttl_missing_soa():
    reply = DNSRecord.question("x.example.", "AAAA").reply()
    assert extract_negative_ttl(reply) is None


def test_remaining_counts_from_arrival():
    exchange = UpstreamExchange(reply=DNSRecord(), arrived=time.monotonic() - 3.0)
    remaining = exchange.remaining(10)
    assert 6.5 < remaining < 7.5


def test_synthesize_ttl_is_min_of_bases():
    resolver = make_resolver()
    request = DNSRecord.question("alias.example.", "AAAA")
    aaaa_ex = UpstreamExchange(reply=nodata_reply("alias.example.", neg_ttl=30,
                                                  cname="web.example.", cname_ttl=45))
    a_ex = UpstreamExchange(reply=a_reply("alias.example.",
                                          [("192.0.2.10", 60)],
                                          cname="web.example.", cname_ttl=45))
    out = resolver._synthesize(request, "alias.example.", "web.example.",
                               aaaa_ex, a_ex,
                               [rr for rr in a_ex.reply.rr if rr.rtype == QTYPE.A],
                               30)
    assert RCODE[out.header.rcode] == "NOERROR"
    cnames = [rr for rr in out.rr if rr.rtype == QTYPE.CNAME]
    aaaas = [rr for rr in out.rr if rr.rtype == QTYPE.AAAA]
    assert len(cnames) == 1 and str(cnames[0].rdata.label) == "web.example."
    assert len(aaaas) == 1
    assert str(aaaas[0].rname) == "web.example."
    assert str(aaaas[0].rdata) == "64:ff9b::c000:20a"
    # min(negative 30, A 60, CNAME 45) == 30
    assert 28 <= aaaas[0].ttl <= 30


def test_synthesize_expired_basis_gives_servfail():
    resolver = make_resolver()
    request = DNSRecord.question("web.example.", "AAAA")
    # The no-AAAA answer "arrived" 5s ago with a 2s negative TTL: the
    # synthesis basis has already expired.
    aaaa_ex = UpstreamExchange(reply=nodata_reply("web.example.", neg_ttl=2),
                               arrived=time.monotonic() - 5.0)
    a_ex = UpstreamExchange(reply=a_reply("web.example.", [("192.0.2.10", 60)]))
    out = resolver._synthesize(request, "web.example.", "web.example.",
                               aaaa_ex, a_ex,
                               [rr for rr in a_ex.reply.rr if rr.rtype == QTYPE.A],
                               2)
    assert RCODE[out.header.rcode] == "SERVFAIL"
    assert not out.rr


def test_synthesize_multiple_a_records_uses_shortest():
    resolver = make_resolver()
    request = DNSRecord.question("multi.example.", "AAAA")
    aaaa_ex = UpstreamExchange(reply=nodata_reply("multi.example.", neg_ttl=30))
    a_ex = UpstreamExchange(reply=a_reply("multi.example.",
                                          [("192.0.2.41", 120), ("192.0.2.42", 25)]))
    out = resolver._synthesize(request, "multi.example.", "multi.example.",
                               aaaa_ex, a_ex,
                               [rr for rr in a_ex.reply.rr if rr.rtype == QTYPE.A],
                               30)
    aaaas = [rr for rr in out.rr if rr.rtype == QTYPE.AAAA]
    assert len(aaaas) == 2
    # min(negative 30, A 120, A 25) == 25
    assert all(23 <= rr.ttl <= 25 for rr in aaaas)
    assert {str(rr.rdata) for rr in aaaas} == {"64:ff9b::c000:229", "64:ff9b::c000:22a"}


# ---------------------------------------------------------------------------
# Speculative prefetch
# ---------------------------------------------------------------------------


def test_parse_domain_list():
    raw = "web.example., alias.example.;Web.example. multi.example.\n"
    assert parse_domain_list(raw) == [
        "web.example.", "alias.example.", "Web.example.", "multi.example.",
    ]


def test_prefetcher_normalizes_domains_and_respects_list():
    prefetcher = SpeculativePrefetcher(["Web.Example"], 2, "127.0.0.1", 5353, 0.5)
    assert prefetcher.enabled
    assert prefetcher.is_listed("web.example.")
    assert not prefetcher.is_listed("other.example.")


def test_prefetcher_disabled_without_domains_or_concurrency():
    assert not SpeculativePrefetcher([], 2, "127.0.0.1", 5353, 0.5).enabled
    assert not SpeculativePrefetcher(["web.example."], 0, "127.0.0.1", 5353, 0.5).enabled


def test_prefetcher_start_returns_none_for_unlisted_name():
    calls = []

    def fake_query(name, qtype, host, port, timeout):
        calls.append((name, qtype))
        return UpstreamExchange(reply=a_reply(name, []))

    prefetcher = SpeculativePrefetcher(["web.example."], 1, "127.0.0.1", 5353, 1.0,
                                       query_func=fake_query)
    assert prefetcher.start("other.example.") is None
    time.sleep(0.1)
    assert calls == []


def test_prefetcher_limits_concurrency():
    """With one slot, a second speculative query is refused until the first ends."""
    release = threading.Event()
    started = []

    def blocking_query(name, qtype, host, port, timeout):
        started.append(name)
        release.wait(1.0)
        return UpstreamExchange(reply=a_reply(name, [("192.0.2.10", 60)]))

    prefetcher = SpeculativePrefetcher(["a.example.", "b.example."], 1,
                                       "127.0.0.1", 5353, 1.0, query_func=blocking_query)
    first = prefetcher.start("a.example.")
    assert first is not None
    # While the first query runs, the only slot is busy -> serial flow.
    assert prefetcher.start("b.example.") is None
    assert prefetcher.in_flight == 1
    release.set()
    assert first.wait(1.0)
    assert first.exchange is not None
    # Slot released only after the background query finished.
    assert prefetcher.in_flight == 0
    second = prefetcher.start("b.example.")
    assert second is not None
    assert second.wait(1.0)
    assert prefetcher.in_flight == 0


def test_prefetcher_slot_held_until_query_finishes():
    """The slot stays busy even if nobody waits for the early result."""
    release = threading.Event()

    def blocking_query(name, qtype, host, port, timeout):
        release.wait(2.0)
        return UpstreamExchange(reply=a_reply(name, []))

    prefetcher = SpeculativePrefetcher(["a.example."], 1, "127.0.0.1", 5353, 2.0,
                                       query_func=blocking_query)
    job = prefetcher.start("a.example.")
    assert job is not None
    time.sleep(0.2)
    # Nobody waited; the job is still running and still occupies the slot.
    assert not job.done
    assert prefetcher.in_flight == 1
    assert prefetcher.start("a.example.") is None
    release.set()
    assert job.wait(2.0)
    assert prefetcher.in_flight == 0


def test_prefetcher_reports_query_error_as_finished_job():
    def failing_query(name, qtype, host, port, timeout):
        raise UpstreamTimeout("boom")

    prefetcher = SpeculativePrefetcher(["a.example."], 1, "127.0.0.1", 5353, 1.0,
                                       query_func=failing_query)
    job = prefetcher.start("a.example.")
    assert job is not None
    assert job.wait(1.0)
    assert job.done
    assert isinstance(job.error, UpstreamTimeout)
    assert prefetcher.in_flight == 0


def test_job_wait_timeout():
    job = PrefetchJob("a.example.")
    assert job.wait(0.05) is False
    job.finish(UpstreamExchange(reply=a_reply("a.example.", [("192.0.2.10", 60)])))
    assert job.wait(0.1) is True


# -- resolve-level behaviour with a fake upstream ---------------------------


class FakeUpstream:
    """Deterministic query function for resolve-level prefetch tests."""

    def __init__(self, aaaa_reply, a_reply_obj, aaaa_delay=0.0, a_delay=0.0):
        self.aaaa_reply = aaaa_reply
        self.a_reply_obj = a_reply_obj
        self.aaaa_delay = aaaa_delay
        self.a_delay = a_delay
        self.calls = []
        self.completed = []
        self.lock = threading.Lock()

    def __call__(self, name, qtype, host, port, timeout):
        with self.lock:
            self.calls.append((qtype, time.monotonic()))
        delay = self.aaaa_delay if qtype == "AAAA" else self.a_delay
        if delay:
            time.sleep(delay)
        with self.lock:
            self.completed.append((qtype, time.monotonic()))
        reply = self.aaaa_reply if qtype == "AAAA" else self.a_reply_obj
        return UpstreamExchange(reply=reply)

    def count(self, qtype=None):
        with self.lock:
            return sum(1 for t, _ in self.calls if qtype is None or t == qtype)

    def started_at(self, qtype, occurrence=0):
        with self.lock:
            return [ts for qt, ts in self.calls if qt == qtype][occurrence]

    def completed_at(self, qtype, occurrence=0):
        with self.lock:
            return [ts for qt, ts in self.completed if qt == qtype][occurrence]


def _resolve(resolver, name="web.example."):
    request = DNSRecord.question(name, "AAAA")
    return resolver.resolve(request, handler=None)


def test_prefetch_overlap_synthesizes_and_queries_a_early():
    aaaa = nodata_reply("web.example.", neg_ttl=30)
    a = a_reply("web.example.", [("192.0.2.10", 60)])
    fake = FakeUpstream(aaaa, a, aaaa_delay=0.4, a_delay=0.4)
    resolver = make_resolver(["web.example."], 1, query_func=fake)

    started = time.monotonic()
    out = _resolve(resolver)
    elapsed = time.monotonic() - started

    assert RCODE[out.header.rcode] == "NOERROR"
    aaaas = [rr for rr in out.rr if rr.rtype == QTYPE.AAAA]
    assert len(aaaas) == 1
    assert str(aaaas[0].rdata) == "64:ff9b::c000:20a"
    # The A query was sent while the AAAA query was still in flight, so the
    # two 0.4s delays overlap instead of adding up.
    assert fake.count("A") == 1
    assert fake.started_at("A") < fake.completed_at("AAAA")
    assert elapsed < 0.7
    # TTL counted from the moment the A reply arrived (immediately).
    assert 28 <= aaaas[0].ttl <= 30


def test_unlisted_name_is_serial_and_slow():
    aaaa = nodata_reply("other.example.", neg_ttl=30)
    a = a_reply("other.example.", [("192.0.2.10", 60)])
    fake = FakeUpstream(aaaa, a, aaaa_delay=0.4, a_delay=0.4)
    resolver = make_resolver(["web.example."], 1, query_func=fake)

    started = time.monotonic()
    out = _resolve(resolver, "other.example.")
    elapsed = time.monotonic() - started

    assert RCODE[out.header.rcode] == "NOERROR"
    # Serial: 0.4s AAAA then 0.4s A.
    assert fake.count("A") == 1
    assert fake.started_at("A") - fake.started_at("AAAA") > 0.3
    assert elapsed > 0.7


def test_prefetch_not_started_when_slot_busy():
    aaaa = nodata_reply("web.example.", neg_ttl=30)
    a = a_reply("web.example.", [("192.0.2.10", 60)])
    fake = FakeUpstream(aaaa, a, aaaa_delay=0.3, a_delay=0.3)
    resolver = make_resolver(["web.example."], 1, query_func=fake)

    # Occupy the only slot with a similar query first.
    blocker = resolver.prefetcher.start("web.example.")
    assert blocker is not None
    assert not blocker.wait(0.05)  # still running

    started = time.monotonic()
    out = _resolve(resolver)
    elapsed = time.monotonic() - started
    assert RCODE[out.header.rcode] == "NOERROR"
    # Serial flow because no slot was free: AAAA 0.3s then A 0.3s.
    assert elapsed > 0.5
    # AAAA, blocker's A, then our own A.
    assert fake.count("A") == 2
    assert fake.started_at("A", occurrence=1) - fake.started_at("AAAA") > 0.2
    assert blocker.wait(1.0)


def test_native_aaaa_returns_immediately_while_prefetch_runs():
    native = DNSRecord.question("native.example.", "AAAA").reply()
    native.add_answer(RR("native.example.", QTYPE.AAAA, rdata=AAAA("2001:db8::53"), ttl=300))
    a = a_reply("native.example.", [("192.0.2.10", 60)])
    release = threading.Event()

    def fake_query(name, qtype, host, port, timeout):
        if qtype == "A":
            release.wait(1.0)
        return UpstreamExchange(reply=native if qtype == "AAAA" else a)

    resolver = make_resolver(["native.example."], 1, query_func=fake_query)
    started = time.monotonic()
    out = _resolve(resolver, "native.example.")
    elapsed = time.monotonic() - started

    assert elapsed < 0.5
    assert RCODE[out.header.rcode] == "NOERROR"
    aaaas = [rr for rr in out.rr if rr.rtype == QTYPE.AAAA]
    assert str(aaaas[0].rdata) == "2001:db8::53"
    # The speculative A query is still occupying its slot.
    assert resolver.prefetcher.in_flight == 1
    release.set()
    time.sleep(0.1)
    assert resolver.prefetcher.in_flight == 0


def test_prefetched_a_with_expired_basis_falls_back():
    """A prefetched reply that cannot keep the TTL rules is not used."""
    aaaa = nodata_reply("web.example.", neg_ttl=30)
    calls = {"A": 0}

    def fake_query(name, qtype, host, port, timeout):
        if qtype == "A":
            calls["A"] += 1
            if calls["A"] == 1:
                # Speculative reply arrives immediately with a TTL of 1s.
                return UpstreamExchange(reply=a_reply("web.example.", [("192.0.2.10", 1)]))
            # The fallback reply, queried after the NODATA arrived, is fresh.
            return UpstreamExchange(reply=a_reply("web.example.", [("192.0.2.10", 60)]))
        time.sleep(1.5)  # NODATA arrives 1.5s later: the prefetched A expired
        return UpstreamExchange(reply=aaaa)

    resolver = make_resolver(["web.example."], 1, timeout=2.0, query_func=fake_query)
    out = _resolve(resolver)

    assert RCODE[out.header.rcode] == "NOERROR"
    aaaas = [rr for rr in out.rr if rr.rtype == QTYPE.AAAA]
    assert len(aaaas) == 1
    # Prefetched A had expired, so the fresh fallback A was used (TTL 60
    # limited by the 30s negative TTL).
    assert calls["A"] == 2
    assert 28 <= aaaas[0].ttl <= 30


def test_prefetched_result_with_bad_endpoint_falls_back_to_fresh_a_query():
    aaaa = nodata_reply("alias.example.", neg_ttl=30, cname="web.example.")
    wrong = a_reply("alias.example.", [("192.0.2.99", 60)], cname="ep-b.example.")
    right = a_reply("alias.example.", [("192.0.2.10", 60)], cname="web.example.")

    state = {"a_count": 0}

    def fake_query(name, qtype, host, port, timeout):
        if qtype == "AAAA":
            time.sleep(0.2)
            return UpstreamExchange(reply=aaaa)
        state["a_count"] += 1
        return UpstreamExchange(reply=wrong if state["a_count"] == 1 else right)

    resolver = make_resolver(["alias.example."], 1, timeout=2.0, query_func=fake_query)
    out = _resolve(resolver, "alias.example.")

    assert RCODE[out.header.rcode] == "NOERROR"
    aaaas = [rr for rr in out.rr if rr.rtype == QTYPE.AAAA]
    assert len(aaaas) == 1
    assert str(aaaas[0].rdata) == "64:ff9b::c000:20a"  # the fallback A, not .99
    assert state["a_count"] == 2  # speculative + fallback


def test_prefetched_result_honours_negative_ttl_from_aaaa_arrival():
    """TTL basis: A TTL minus the time since *its own* arrival."""
    aaaa = nodata_reply("web.example.", neg_ttl=30)
    release = threading.Event()

    def fake_query(name, qtype, host, port, timeout):
        if qtype == "A":
            return UpstreamExchange(reply=a_reply("web.example.", [("192.0.2.10", 5)]))
        release.wait(2.0)  # AAAA reply comes 0.6s later
        return UpstreamExchange(reply=aaaa)

    resolver = make_resolver(["web.example."], 1, timeout=2.0, query_func=fake_query)
    threading.Timer(0.6, release.set).start()
    out = _resolve(resolver)
    aaaas = [rr for rr in out.rr if rr.rtype == QTYPE.AAAA]
    assert len(aaaas) == 1
    # A TTL 5 minus ~0.6s elapsed since the A reply arrived -> ~4.
    assert 3 <= aaaas[0].ttl <= 4


def test_prefetch_shared_deadline_expiry_gives_servfail():
    """The prefetched A never arrives: waiting + fallback share the deadline."""
    aaaa = nodata_reply("web.example.", neg_ttl=30)
    release = threading.Event()
    calls = {"A": 0}

    def fake_query(name, qtype, host, port, timeout):
        if qtype == "A":
            calls["A"] += 1
            release.wait(3.0)  # never in time for the 0.3s deadline
            return UpstreamExchange(reply=a_reply("web.example.", [("192.0.2.10", 60)]))
        return UpstreamExchange(reply=aaaa)

    resolver = make_resolver(["web.example."], 1, timeout=0.3, query_func=fake_query)
    started = time.monotonic()
    out = _resolve(resolver)
    elapsed = time.monotonic() - started
    release.set()

    assert RCODE[out.header.rcode] == "SERVFAIL"
    assert calls["A"] == 1            # the fallback was not started
    assert elapsed < 1.0


