# DNS64 服务（dnslib）+ 样例上游 + Swagger 查询控制台

面向 IPv6 单栈网段（已有 NAT64 出口、旧采集器只配 IPv4 地址）的 DNS64 服务。
收到 UDP AAAA 查询时，按 RFC 6147 思路用 A 记录和配置的 /96 前缀合成 AAAA，
并额外做"两次上游答复终点一致性"校验。

## 组件

| 目录 | 说明 | 容器端口 |
|---|---|---|
| `dns64/` | DNS64 服务（dnslib，仅 UDP） | 5354/udp |
| `dns64-prefetch` | 同镜像的第二实例，开启 A 提前查询 | 5355/udp |
| `upstream/` | 样例上游 DNS（剧本化应答，覆盖全部场景） | 5353/udp |
| `api/` | FastAPI 查询控制台，Swagger UI 在 `/docs` | 8080/tcp |

## 行为规则（`dns64/dns64_server.py`）

1. 原生 AAAA 答复、NXDOMAIN 直接透传（仅改写报文 id）。
2. 名称存在但无 AAAA（NOERROR/NODATA）时，再向上游发 A 查询；
   **两次上游答复指向同一终点**（qname 或其一跳 CNAME 目标）才合成。
3. 支持一跳 CNAME，合成答复中保留该 CNAME（别名）记录。
4. 终点一致但也无 A 记录时，原样返回无记录（NODATA）答复。
5. 合成 TTL = min（无 AAAA 答复的负缓存期 min(SOA TTL, SOA MINIMUM)、
   A 记录剩余 TTL、所用 CNAME 剩余 TTL），各项均从**各自答复到达时刻**起算；
   CNAME 记录本身按剩余 TTL 输出。
6. 以下情况返回 SERVFAIL：
   - 上游超时（`UPSTREAM_TIMEOUT`，默认 2.0s）；
   - 两次答复终点不一致；
   - 合成依据过期（任一依据的剩余有效期 < 1s，例如 A 回包太晚，
     负缓存窗口已关闭）。
7. 非 AAAA 查询透传上游答复。

## A 提前查询（speculative prefetch）

给旧采集器的域名提前并行查 A，避免"先等 AAAA、再等 A"的串行等待。

- 名单：`DNS64_PREFETCH_DOMAINS`（逗号/空白分隔，大小写与结尾点会自动归一化）。
- 名额：`DNS64_PREFETCH_CONCURRENCY`，同时最多这么多条提前 A 查询在跑；
  为 0 或名单为空即完全关闭（等价于原串行行为）。
- 命中的域名：发 AAAA 的同时在后台线程发 A。
- 无需 A 的答复（原生 AAAA、NXDOMAIN、其它 rcode、非 AAAA 查询）立即按原结果返回；
  后台那条提前查询**继续占名额，直到自己的上游回包到达**才释放。
- AAAA 收到 NODATA 后：
  - 提前 A 回包只在 **NOERROR + 与 AAAA 答复终点一致 + 有 A 记录 +
    仍满足原有 TTL 规则**时才用于合成；
    TTL 仍从各自回包到达时刻起算（提前 A 到得早，剩余 TTL 更小）。
  - 不可用时保留这份 NODATA 作为回退结果，按原流程补查一次 A。
  - 从收到 NODATA 起，**等提前结果和补查共用同一个 A 查询时限**
    （`UPSTREAM_TIMEOUT`）；到期返回 SERVFAIL。
- 名额用完（或域名不在名单里）：照常串行，先 AAAA 再 A。

## 启动

```bash
docker compose up --build
```

然后打开 http://localhost:8080/docs ：

- `GET /query`、`GET /scenario/{name}`：对 `dns64`（串行）发起真实查询。
- `GET /compare/{scenario}`：同一场景分别打 `dns64`（5354）和
  `dns64-prefetch`（5355），返回各自 `elapsed_ms`、最小值与 `saved_ms`。

无 Docker 时也可以本地直接跑（四个终端）：

```bash
python3 upstream/mock_upstream.py                 # 127.0.0.1:5353/udp
UPSTREAM_HOST=127.0.0.1 python3 dns64/dns64_server.py   # 0.0.0.0:5354/udp
UPSTREAM_HOST=127.0.0.1 LISTEN_PORT=5355 \
  DNS64_PREFETCH_DOMAINS=web.example.,alias.example.,multi.example.,slowaaaa.example.,dropa.example.,flap.example.,prefetchflap.example.,noaddr.example.,drop.example. \
  DNS64_PREFETCH_CONCURRENCY=8 python3 dns64/dns64_server.py  # 0.0.0.0:5355/udp
DNS64_PREFETCH_PORT=5355 python3 api/main.py      # http://127.0.0.1:8080/docs
```

## 样例上游剧本（`upstream/mock_upstream.py`）

| 场景 / 名字 | AAAA 查询 | A 查询 | 预期结果 |
|---|---|---|---|
| `native` / native.example. | AAAA 2001:db8::53 (ttl 300) | NODATA | 原生透传 |
| `nxdomain` / gone.example. | NXDOMAIN | NXDOMAIN | 透传 |
| `synth` / web.example. | NODATA (neg 30s) | A 192.0.2.10 (ttl 60) | 合成 64:ff9b::c000:20a，ttl≈30 |
| `alias` / alias.example. | CNAME web.example. + NODATA | CNAME + A | 保留别名并合成，ttl≈min(30,60,45) |
| `noaddr` / noaddr.example. | NODATA (neg 20s) | NODATA | 沿用无记录答复 |
| `multi` / multi.example. | NODATA (neg 30s) | A×2 (ttl 120/25) | 合成两条，ttl≈25 |
| `slowaaaa` / slowaaaa.example. | NODATA (neg 30s)，延迟 1.5s | A 同样延迟 1.5s | 串行≈3s；提前查询≈1.5s |
| `dropa` / dropa.example. | NODATA (neg 30s) | A 5s 后才到 | 共用时限到期 → SERVFAIL |
| `prefetchflap` / prefetchflap.example. | CNAME ep-a + NODATA | CNAME ep-b + A | 提前结果不可用 → 补查仍不一致 → SERVFAIL |
| `slow` / slow.example. | NODATA (neg 1s) | A 延迟 1.5s 才到 | 依据过期 → SERVFAIL |
| `flap` / flap.example. | CNAME ep-a + NODATA | CNAME ep-b + A | 终点不一致 → SERVFAIL |
| `timeout` / drop.example. | 不应答 | 不应答 | 上游超时 → SERVFAIL |

注：`dropa.example.` 在串行实例上同样是在 2s A 时限内拿不到 A → SERVFAIL；
在提前实例上则是共用时限到期 → SERVFAIL。

## 配置（环境变量）

DNS64 服务：`UPSTREAM_HOST` `UPSTREAM_PORT` `DNS64_PREFIX`（默认 64:ff9b::/96）
`UPSTREAM_TIMEOUT` `LISTEN_HOST` `LISTEN_PORT` `LOG_LEVEL`
`DNS64_PREFETCH_DOMAINS` `DNS64_PREFETCH_CONCURRENCY`。

API：`DNS64_HOST` `DNS64_PORT` `DNS64_PREFETCH_HOST` `DNS64_PREFETCH_PORT` `PORT`。

## 测试

```bash
python3 -m pytest tests/ -v
```

`tests/test_dns64_unit.py`：地址映射、终点提取、负缓存期、TTL 最小值、
过期判定等纯逻辑，以及提前查询的名单/名额/并发/回退/共用时限；
`tests/test_e2e.py`：真实 UDP 起服打满全部场景，并对比开/关提前查询的耗时。

## 已知限制 / TODO

- 仅 UDP；上游截断（TC）时不回退 TCP，也无多上游/重试。
- 无缓存层：每个客户端查询都会真实发起两次上游查询（TTL 只用于当次合成）。
- 提前查询只针对名单内的确切 qname（不做后缀/通配匹配），也不区分客户端。
- 提前查询的 A 回包若不可用，会多打一次 A 上游查询（这是有意的回退路径）。
- 只支持一跳 CNAME；更长的链按"无 A"处理。
- 无 AAAA 答复缺 SOA 时负缓存期按 0 处理，合成会判过期（从严）。
- A 查询发向原始 qname，由上游完成链式解析。
