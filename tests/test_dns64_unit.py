"""Unit tests for the DNS64 synthesis logic (no network involved)."""

import time

from dnslib import QTYPE, RCODE, RR, A, AAAA, CNAME, SOA, DNSRecord

from dns64_server import (
    DNS64Resolver,
    UpstreamExchange,
    extract_endpoint,
    extract_negative_ttl,
)


def make_resolver():
    return DNS64Resolver("127.0.0.1", 5353, "64:ff9b::/96", timeout=0.5)


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
