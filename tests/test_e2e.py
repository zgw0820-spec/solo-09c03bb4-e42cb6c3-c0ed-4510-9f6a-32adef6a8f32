"""End-to-end tests: real UDP queries through the DNS64 server backed by the
scripted sample upstream."""

import socket

import pytest
from dnslib import QTYPE, RCODE, DNSRecord
from dnslib.server import DNSServer

from dns64_server import DNS64Resolver
from mock_upstream import ScriptedResolver, ZONE_FILE


@pytest.fixture(scope="module")
def servers():
    upstream = DNSServer(ScriptedResolver(ZONE_FILE), address="127.0.0.1", port=0, tcp=False)
    upstream.start_thread()
    upstream_port = upstream.server.server_address[1]

    resolver = DNS64Resolver("127.0.0.1", upstream_port, "64:ff9b::/96", timeout=2.0)
    dns64 = DNSServer(resolver, address="127.0.0.1", port=0, tcp=False)
    dns64.start_thread()
    dns64_port = dns64.server.server_address[1]

    yield dns64_port

    dns64.stop()
    upstream.stop()


def ask(port, name, qtype="AAAA", timeout=5.0):
    q = DNSRecord.question(name, qtype)
    try:
        raw = q.send("127.0.0.1", port, tcp=False, timeout=timeout)
    except (socket.timeout, TimeoutError):
        return None
    return DNSRecord.parse(raw)


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
