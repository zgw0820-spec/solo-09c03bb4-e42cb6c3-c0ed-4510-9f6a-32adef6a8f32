"""FastAPI gateway used to fire real DNS queries at the DNS64 service.

Open /docs (Swagger UI) and use GET /query or GET /scenario/{name} to send
live UDP queries through the DNS64 server and inspect the parsed answers.
GET /compare/{name} runs the same query against a second DNS64 instance with
speculative A prefetch enabled and reports both elapsed times.
"""

from __future__ import annotations

import os
import socket
import time

from dnslib import QTYPE, RCODE, DNSRecord
from fastapi import FastAPI, HTTPException, Query

DNS64_HOST = os.environ.get("DNS64_HOST", "127.0.0.1")
DNS64_PORT = int(os.environ.get("DNS64_PORT", "5354"))
# Second DNS64 instance with speculative prefetch enabled, used by /compare.
DNS64_PREFETCH_HOST = os.environ.get("DNS64_PREFETCH_HOST", DNS64_HOST)
DNS64_PREFETCH_PORT = int(os.environ.get("DNS64_PREFETCH_PORT", "5355"))

# One-click demo scenarios against the scripted sample upstream.
SCENARIOS = {
    "native": ("native.example.", "AAAA — native AAAA, returned as-is"),
    "nxdomain": ("gone.example.", "AAAA — NXDOMAIN, returned as-is"),
    "synth": ("web.example.", "AAAA — plain synthesis from A record"),
    "alias": ("alias.example.", "AAAA — one CNAME hop, alias kept in answer"),
    "noaddr": ("noaddr.example.", "AAAA — no AAAA and no A, NODATA returned"),
    "slow": ("slow.example.", "AAAA — A reply arrives after the negative TTL expired -> SERVFAIL"),
    "flap": ("flap.example.", "AAAA — the two upstream replies alias to different endpoints -> SERVFAIL"),
    "multi": ("multi.example.", "AAAA — two A records, TTL = min of all bases"),
    "slowaaaa": ("slowaaaa.example.", "AAAA — slow AAAA reply; prefetched A query overlaps it"),
    "dropa": ("dropa.example.", "AAAA — A reply never arrives before the shared deadline -> SERVFAIL"),
    "prefetchflap": ("prefetchflap.example.", "AAAA — prefetched A aliases elsewhere; fallback A query decides"),
    "timeout": ("drop.example.", "AAAA — upstream never answers -> SERVFAIL"),
}

app = FastAPI(
    title="DNS64 query console",
    description="Trigger real DNS queries through the DNS64 service and inspect the answers.",
    version="1.0.0",
)


def _rr_to_dict(rr) -> dict:
    return {
        "name": str(rr.rname),
        "type": QTYPE[rr.rtype],
        "ttl": rr.ttl,
        "data": str(rr.rdata),
    }


def run_query(name: str, qtype: str, server: str, port: int, timeout: float) -> dict:
    q = DNSRecord.question(name, qtype)
    started = time.monotonic()
    try:
        raw = q.send(server, port, tcp=False, timeout=timeout)
    except (socket.timeout, TimeoutError) as exc:
        raise HTTPException(
            status_code=504,
            detail=f"DNS64 server {server}:{port} did not answer within {timeout}s",
        ) from exc
    reply = DNSRecord.parse(raw)
    elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    return {
        "query": {"name": name, "type": qtype, "server": server, "port": port},
        "rcode": RCODE[reply.header.rcode],
        "elapsed_ms": elapsed_ms,
        "answer": [_rr_to_dict(rr) for rr in reply.rr],
        "authority": [_rr_to_dict(rr) for rr in reply.auth],
        "additional": [_rr_to_dict(rr) for rr in reply.ar],
    }


@app.get("/", summary="Service info")
def index() -> dict:
    return {
        "service": "dns64-query-console",
        "dns64_server": f"{DNS64_HOST}:{DNS64_PORT}",
        "dns64_prefetch_server": f"{DNS64_PREFETCH_HOST}:{DNS64_PREFETCH_PORT}",
        "swagger_ui": "/docs",
        "scenarios": sorted(SCENARIOS),
    }


@app.get("/healthz", summary="Health check")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/query", summary="Send a DNS query through the DNS64 service")
def query(
    name: str = Query("web.example.", description="Name to resolve"),
    qtype: str = Query("AAAA", description="Query type, e.g. AAAA, A, SOA"),
    server: str = Query(DNS64_HOST, description="DNS64 server host"),
    port: int = Query(DNS64_PORT, description="DNS64 server UDP port"),
    timeout: float = Query(5.0, description="Seconds to wait for the answer"),
) -> dict:
    qtype = qtype.upper()
    if qtype not in QTYPE.reverse:
        raise HTTPException(status_code=400, detail=f"unsupported qtype {qtype!r}")
    return run_query(name, qtype, server, port, timeout)


@app.get("/scenario/{scenario}", summary="Run a scripted demo scenario")
def scenario(scenario: str) -> dict:
    if scenario not in SCENARIOS:
        raise HTTPException(status_code=404,
                            detail=f"unknown scenario; try one of {sorted(SCENARIOS)}")
    name, description = SCENARIOS[scenario]
    result = run_query(name, "AAAA", DNS64_HOST, DNS64_PORT, timeout=8.0)
    result["scenario"] = {"name": scenario, "expect": description}
    return result


@app.get("/compare/{scenario}",
         summary="Run the same scenario against the serial and prefetch DNS64")
def compare(scenario: str, repeat: int = Query(3, ge=1, le=10,
                                               description="Queries per server; min is reported")):
    """Compare wall-clock time with and without speculative A prefetch.

    Both servers use the same scripted upstream; only the second one prefetches
    A for names on its list.  ``min_elapsed_ms`` over ``repeat`` runs removes
    most of the scheduling noise.
    """
    if scenario not in SCENARIOS:
        raise HTTPException(status_code=404,
                            detail=f"unknown scenario; try one of {sorted(SCENARIOS)}")
    name, description = SCENARIOS[scenario]

    def one(target_host, target_port):
        runs = []
        result = None
        for _ in range(repeat):
            result = run_query(name, "AAAA", target_host, target_port, timeout=8.0)
            runs.append(result["elapsed_ms"])
        return {
            "server": f"{target_host}:{target_port}",
            "rcode": result["rcode"],
            "answer": result["answer"],
            "authority": result["authority"],
            "elapsed_ms_runs": runs,
            "min_elapsed_ms": min(runs),
        }

    serial = one(DNS64_HOST, DNS64_PORT)
    prefetch = one(DNS64_PREFETCH_HOST, DNS64_PREFETCH_PORT)

    def answer_of(result):
        return {"rcode": result["rcode"],
                "answer": [{k: v for k, v in rr.items() if k != "ttl"}
                           for rr in result["answer"]]}

    return {
        "scenario": {"name": scenario, "name_fqdn": name, "expect": description},
        "serial": serial,
        "prefetch": prefetch,
        "saved_ms": round(serial["min_elapsed_ms"] - prefetch["min_elapsed_ms"], 1),
        # TTLs are expected to differ slightly (the prefetched A reply arrived
        # earlier), so comparison ignores them.
        "same_answer": answer_of(serial) == answer_of(prefetch),
    }


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))


if __name__ == "__main__":
    main()
