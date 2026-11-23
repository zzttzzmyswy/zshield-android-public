# JNI 契约

Rust core（`core/`，crate `zshield-core`，产物 `libzshield.so`）与 Kotlin 控制面之间只有一个入口类：
`top.zztweb.zshield.core.Native`（`docs/DESIGN.md` 固定决策 2）。本文件是两侧共同遵守的契约：
Rust 侧字段定义在 `core/src/config.rs`，Kotlin 侧定义在
`app/src/main/java/top/zztweb/zshield/core/NativeConfig.kt`，两边都是「只定义一次」。

## 1. 方法

```kotlin
package top.zztweb.zshield.core

object Native {
    external fun version(): String?
    external fun init(context: Context)
    external fun start(tunFd: Int, configJson: String): Long
    external fun stop(handle: Long)
    external fun trimMemory()
    external fun statsJson(handle: Long): String?
    external fun compile(requestJson: String): String?
    external fun reload(handle: Long, compiledDir: String): Boolean
    external fun recentRequestsJson(handle: Long, sinceId: Long): String?
    external fun generateCa(): String?
    external fun loadCa(certPem: String, keyPkcs8: ByteArray): Boolean
    external fun httpsBypassJson(handle: Long): String?
    external fun clearHttpsBypass(handle: Long): Boolean
    external fun updateHttpsPolicy(handle: Long, policyJson: String): Boolean
    external fun lastError(): String?
    external fun releaseAll()
}
```

### 返回值：每个 `String` 都是可空的

所有返回 JSON 的方法都声明为 `String?`，调用方必须处理 `null`。

- **Rust 侧保证「值是合法 JSON」**：统计没有引擎时是 `{}`，列表为空时是 `[]`，编译失败时是
  `{"error": "..."}`。任何我们能控制的错误路径都不会返回半截文档或空字符串。
- **Rust 侧不能保证「一定有一个 `jstring`」**：`NewStringUTF` 在 JVM 有挂起异常或内存不足时失败，
  这时唯一诚实的返回值就是 `null`（同时写 `lastError()`）。把所有 `String` 返回统一走
  `core/src/jni_api.rs::to_jstring` 后，这条路径只剩这一种语义。
- **Kotlin 侧按 `null` 处理**：解析器（`NativeStats.fromJson`、`CompileStats.fromJson`、
  `BypassEntry.listFromJson`、`HttpRequestLogEntry.listFromJson`）都接受 `String?` 并把 `null`
  当作「本次没有文档」。这条契约是 MYS-2716 §2 的修复：之前声明为非空，于是唯一无法预防的那种
  返回（JVM 分配失败）变成整个进程的 `NullPointerException`（`ZShieldVpnController.kt:254`）。
  统计数据读不到就跳过这一次刷新，永远不该让 App 崩溃。

| 方法 | 说明 |
|---|---|
| `version()` | core 版本号。构建时由 Gradle 通过 `ZSHIELD_VERSION` 环境变量从 `version.properties` 注入；`cargo build` 直接编译时回退到 `0.0.1`。 |
| `init(context)` | 把 `Context` 交给 `rustls-platform-verifier`，使 DoH 的上游证书校验走 Android 系统信任库。首次 DoH 查询前必须调用（`ZShieldApp.onCreate` 与 `ZShieldVpnService.onCreate` 都会调用；重复调用是 no-op）。 |
| `start(tunFd, configJson)` | 在已建立的 TUN fd 上启动引擎（DNS + 明文 HTTP 过滤），返回非 0 句柄；失败返回 `0`，原因由 `lastError()` 给出。**fd 所有权转移给 core**：Kotlin 侧必须先 `ParcelFileDescriptor.detachFd()`，之后不得再 close。`compiledDir` 里的 `engine.bin` 缺失或损坏**不致命**：隧道照常起来，按域名过滤，原因写 `lastError()`（与 `dns.bin` 的处理一致）。 |
| `stop(handle)` | 停止引擎并关闭 TUN fd。未知句柄写入 `lastError()`，不抛异常。 |
| `trimMemory()` | 应用最后一个界面停止显示时，归还分配器中已释放的页；仍有已启动界面或正在配置重建时不触发。不卸载规则、不清空连接或缓存、不改变规则代次。VPN 前台服务可能使系统 `UI_HIDDEN` 通知一直待发，所以使用 Activity 生命周期。Android 14+ 使用 `M_PURGE_ALL`，不支持时回退 `M_PURGE`；没有定时或每请求调用。 |
| `statsJson(handle)` | 返回计数器 JSON（见第 3 节）。未知句柄返回 `{}` 并写 `lastError()`。 |
| `compile(requestJson)` | 把启用的列表编译成 `dns.bin`、`engine.bin` 和 `extras.txt`（见第 5 节）。**同步执行**，Kotlin 必须在后台线程调用。返回 `CompileStats` JSON；失败返回 `{"error": "..."}`（同时写 `lastError()`）。 |
| `reload(handle, compiledDir)` | 更新运行中引擎的 DNS、网络规则和额外修饰规则（`dns.bin`、`engine.bin`、`extras.txt`）。三类制品未变时返回 `true` 并保留规则对象与代次；实际替换 DNS 时清空其缓存，已有请求可继续持有旧快照。替换不是跨组件事务：DNS 成功而 engine/extras 失败时返回 `false` 并写 `lastError()`，失败组件保留旧规则，identity 如实记录混合状态，generation 不递增且不记录成功 fingerprint，后续调用会重试。合法缺失 extras 表示清空；有效空文件仍有内容 identity；损坏或读取失败不能当作清空。详见 `I2_EXTRAS_RELOAD.md`。 |
| `recentRequestsJson(handle, sinceId)` | 环形请求日志（最近 2000 条，DNS / 连接级 / HTTP 三类共用），只返回 `id > sinceId` 的条目，`sinceId = 0` 表示全部。**只在调用时序列化**，没有推送（固定决策 10：熄屏无唤醒）。未知句柄返回 `[]` 并写 `lastError()`。见第 6 节。 |
| `lastError()` | 最近一次失败原因；成功调用不会清空它。调用方仅在本次调用失败时读取，包括 `start` 返回 0、`compile` 返回错误、`reload` 返回 `false`。 |
| `releaseAll()` | 停止全部引擎，进程收尾兜底。 |

**错误策略**：所有 JNI 调用都不向 Java 抛异常，失败一律「返回 0/空 + 写 lastError」。这样 Kotlin 控制面
无需 try/catch 包住每次 JNI 调用，也不会因为一次 Rust panic 而让整个 App 进程崩溃（`resolve` 路径会
捕获 panic 并转成默认返回值）。

## 2. configJson

字段名即 Rust 结构体字段名（`serde(rename_all = "camelCase")`）。省略的字段取默认值。

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `upstreams` | 数组 | DoH 双上游（见下） | 上游列表，按顺序尝试。空数组等价于默认值。 |
| `blockResponse` | `"zero_ip"` \| `"nxdomain"` \| `"refused"` | `"zero_ip"` | 命中规则时的应答方式。 |
| `ruleFiles` | 字符串数组 | `[]` | 规则文件的**绝对路径**，按顺序加载（后加载的 `@@` 例外会覆盖先加载的同名规则判定）。**调试回退**：有可用 `compiledDir` 时不会被解析。 |
| `compiledDir` | 字符串 | `""` | 预编译产物目录（`dns.bin`、`engine.bin`）。设置且文件可用时，`start` 直接反序列化，不再解析任何规则文本（固定决策 6）。文件缺失/版本不符/损坏时**不致命**：写 `lastError()` 说明原因并回退到 `ruleFiles`，因为一个起不来的 VPN 等于完全没有防护。 |
| `dnsV4` / `dnsV6` | 字符串 | `10.111.222.2` / `fd00:7a73::2` | 虚拟 DNS 地址；必须与 `VpnService.Builder` 里 `addDnsServer` 的值一致。 |
| `cacheMaxEntries` | 整数 | `4096` | 缓存条目上限，超出时淘汰最接近过期的条目。 |
| `cacheMaxTtlSecs` | 整数 | `3600` | 缓存条目 TTL 上限（1 h）。 |
| `queryTimeoutMs` | 整数 | `5000` | 单次上游查询超时。 |
| `workers` | 整数 | `2` | tokio worker 线程数（`docs/DESIGN.md` 固定决策 10：线程数受控）。 |
| `mode` | `"full"` \| `"dns_only"` | `"full"` | 隧道模式，必须与 Kotlin 侧安装的路由一致（见下）。 |
| `mtu` | 整数 | `1500` | TUN MTU，1280–9216；必须与 `VpnService.Builder.setMtu` 相同。 |
| `blockQuic` | 布尔 | `true` | 丢弃 UDP/443，迫使浏览器回退到 TCP/TLS。 |
| `blockEncryptedDnsBypass` | 布尔 | `true` | 拒绝 TCP/853，以及 SNI 命中内置 DoH/DoT 名单的 TLS 连接。 |
| `encryptedDnsHostsFile` | 字符串 | `""` | 加密 DNS 主机名单的绝对路径，一行一个主机名，`#` 注释。空或读不到 = 没有固定名单（不致命，写 `lastError()`）。 |
| `tcpIdleTimeoutSecs` | 整数 | `7200` | 转发 TCP 连接空闲超时（2 h）。 |
| `udpIdleTimeoutSecs` | 整数 | `60` | UDP 流空闲超时。 |
| `maxUdpFlows` | 整数 | `1024` | UDP NAT 表条目上限。 |
| `sniffBytes` | 整数 | `4096` | 首包缓冲上限，用于解析 SNI / `Host`；≥ 512。 |
| `sniffTimeoutMs` | 整数 | `3000` | 等待首包的最长时间；超时即直通。 |
| `httpHeadBytes` | 整数 | `8192` | 单个明文 HTTP 请求头的缓冲上限，1024–65536。超过即**直通不拦**（不是断开），保证恶意/异常的头流不会让隧道无界增长。 |
| `ipv6` | 布尔 | `true` | 底层网络是否能承载 IPv6（见下）。为 `false` 时 DNS 层不出 IPv6 结果：AAAA 查询直接答 NODATA，HTTPS/SVCB 应答去掉 `ipv6hint`（key 6）。 |

### `ipv6`：隧道与 DNS 必须一致

`ipv6` 描述的是**隧道下方那条真实链路**有没有 IPv6，由 Kotlin 侧
`top.zztweb.zshield.vpn.Ipv6Availability` 判断：底层默认网络（非 VPN）同时具备「全局单播 IPv6 地址」
和「IPv6 默认路由（`::/0`）」才算可用。ULA（`fc00::/7`，含隧道自己用的 `fd00::/8`）、链路本地、
站点本地、组播、回环一律不算全局地址。

两侧必须同时遵守这个值，否则会出现「握手成功、随后连接被重置」：

| `ipv6` | `VpnService.Builder`（Kotlin） | core |
|---|---|---|
| `true` | 加 `fd00:7a73::1/126`、`addDnsServer(fd00:7a73::2)`；full 模式加 `::/0`，dns_only 加 `fd00:7a73::2/128` | 正常转发 AAAA，保留 `ipv6hint` |
| `false` | 上述四项都不加 | AAAA 本地答 NODATA（NOERROR、答案数 0、question 原样回显）；HTTPS/SVCB 应答去掉 `ipv6hint`，其余 SvcParam 保留 |

理由：客户端（curl、浏览器）拿到 AAAA 后先连 IPv6，隧道内 TCP 握手在本地完成，出站才
`Network is unreachable`；此时客户端**不会**自动回退到 IPv4，页面直接打不开（MYS-2710）。
NODATA 才是解析器表达「这个名字存在，但没有该地址族的记录」的标准方式，客户端据此改走 A。

底层可用性变化时（如 Wi-Fi 切到有 IPv6 的移动数据），Kotlin 侧防抖 ≥ 2 s 后经
`ACTION_RESTART` 重建隧道；可用性不变时（只换了 DNS 服务器、MTU 变化）不重建。
`VpnService.Builder` 在 `establish` 时就固定了地址与路由，运行中无法增删，所以只能重建。

### mode 与路由

| `mode` | Kotlin 侧路由 | 行为 |
|---|---|---|
| `full`（默认） | `0.0.0.0/0`，以及 `ipv6=true` 时的 `::/0` | 全部 IPv4/IPv6 流量进用户态栈：SNI/Host 拦截、QUIC 丢弃、任意地址 DNS 劫持、按连接策略。 |
| `dns_only` | `10.111.222.2/32`，以及 `ipv6=true` 时的 `fd00:7a73::2/128` | 只有虚拟 DNS 地址进隧道（M0/M1 行为），其余流量走系统路径。 |

两种模式共用同一套用户态栈（M2a 起不再有手写 UDP 解析的旁路），因此只有一条数据面要维护。
除 `upstreams` / `ruleFiles` / `encryptedDnsHostsFile` 这类路径外，其余字段都会在 `start` 时校验；
不合法（例如 `mtu: 1000`、`sniffBytes: 10`）直接让 `start` 返回 0 并写 `lastError()`，不做静默钳制。

### upstreams 元素

DoH（默认，推荐）：

```json
{"type": "doh", "url": "https://dns.alidns.com/dns-query", "bootstrap": ["223.5.5.5"]}
```

- `url` 必须是 `https://`，否则配置校验失败；
- `bootstrap` 是**必填**的一个或多个 IP：DoH 主机名不能走系统解析器（那正是本 App 要替换的东西），
  连接直接建到 bootstrap IP，TLS 的 SNI 与 HTTP `:authority` 仍用 URL 里的主机名；
- 证书校验走 `rustls-platform-verifier`（Android 系统信任库），**没有**任何放宽校验的开关。

明文 UDP（仅调试）：

```json
{"type": "udp", "address": "1.1.1.1:53"}
```

### 示例

```json
{
  "upstreams": [
    {"type": "doh", "url": "https://dns.alidns.com/dns-query", "bootstrap": ["223.5.5.5"]},
    {"type": "doh", "url": "https://doh.pub/dns-query", "bootstrap": ["1.12.12.12"]}
  ],
  "blockResponse": "zero_ip",
  "ruleFiles": ["/data/user/0/top.zztweb.zshield/files/builtin-test.txt"],
  "compiledDir": "/data/user/0/top.zztweb.zshield/files/filters/compiled",
  "dnsV4": "10.111.222.2",
  "dnsV6": "fd00:7a73::2",
  "cacheMaxEntries": 4096,
  "cacheMaxTtlSecs": 3600,
  "queryTimeoutMs": 5000,
  "workers": 2,
  "mode": "full",
  "mtu": 1500,
  "blockQuic": true,
  "blockEncryptedDnsBypass": true,
  "encryptedDnsHostsFile": "/data/user/0/top.zztweb.zshield/files/encrypted-dns-hosts.txt",
  "tcpIdleTimeoutSecs": 7200,
  "udpIdleTimeoutSecs": 60,
  "maxUdpFlows": 1024,
  "sniffBytes": 4096,
  "sniffTimeoutMs": 3000,
  "ipv6": true,
  "httpHeadBytes": 8192
}
```

## 3. statsJson

```json
{
  "version": "0.0.1",
  "dnsQueries": 12,
  "dnsBlocked": 3,
  "dnsErrors": 0,
  "dnsCached": 4,
  "dnsUpstreamQueries": 7,
  "upstreamLatencyMsP50": 23,
  "cacheEntries": 5,
  "rulesBlock": 9,
  "rulesException": 1,
  "rulesUnsupported": 107,
  "rulesNetworkOnly": 422362,
  "upstreams": ["doh:https://dns.alidns.com/dns-query", "doh:https://doh.pub/dns-query"],
  "tunPacketsIn": 30,
  "tunPacketsOut": 29,
  "tunDropped": 1,
  "mode": "full",
  "mtu": 1500,
  "echStripped": 2,
  "tcpActive": 3,
  "tcpTotal": 9,
  "udpActive": 1,
  "bytesUp": 1000,
  "bytesDown": 2000,
  "blockedConnections": 4,
  "quicDropped": 5,
  "dnsHijacked": 6,
  "encryptedDnsDropped": 7,
  "ipv6Suppressed": 8,
  "ipv6HintStripped": 9,
  "httpRequests": 24,
  "httpBlocked": 7,
  "httpRedirected": 0,
  "httpDegraded": 0,
  "httpEngineLoaded": true,
  "requestLogSize": 24
}
```

任务卡要求的最小字段 `dnsQueries`、`dnsBlocked`、`dnsErrors`、`upstreamLatencyMsP50` 全部包含。其余：
`dnsCached` 缓存命中数、`dnsUpstreamQueries` 实际发出的上游请求数、`cacheEntries` 当前缓存条目、
`rulesBlock`/`rulesException`/`rulesUnsupported`/`rulesNetworkOnly` 规则统计（不支持的规则必须可见，见固定决策 6）。
`rulesUnsupported` 只统计**解析失败**的行；`rulesNetworkOnly` 是语法有效但只属于 adblock 引擎的规则（路径规则、
`$third-party`、元素隐藏等），两者必须分开，否则真实列表的「不支持」会虚高到几十万条、失去诊断价值、
`tunPacketsIn/Out/Dropped` 隧道读写与丢弃计数、`upstreams` 当前生效的上游。

M2a 新增的隧道计数：

| 字段 | 含义 |
|---|---|
| `mode` / `mtu` | 核心实际运行的隧道模式与 MTU，便于确认配置真的生效。 |
| `tcpActive` | 当前转发的 TCP 连接数。 |
| `tcpTotal` | 本次运行累计建立的 TCP 连接数（含被拦截的）。 |
| `udpActive` | UDP NAT 表中活跃流数。 |
| `bytesUp` / `bytesDown` | 经隧道转发到网络 / 回到应用的字节数（不含 DNS 应答）。 |
| `blockedConnections` | **连接级拦截总数**（MYS-2742 起）：规则拒（SNI/`Host` 命中）、丢弃的 QUIC、被拒的 DoT、加密 DNS 端点。`quicDropped` 与 `encryptedDnsDropped` 是它的明细。首页「已拦截」= `dnsBlocked + blockedConnections + httpBlocked`，因此它的增量必须与日志中 `kind=connection` 的 blocked 条目数一致。 |
| `quicDropped` | 被丢弃的 UDP/443 **目的地址数**（同一 `ip:port` 60 s 内只计一次，见 6.6）——`blockedConnections` 的子集。 |
| `dnsHijacked` | 被引擎接管（而非发往网络）的 DNS 报文数，含发往任意 IP 的 53 端口。 |
| `encryptedDnsDropped` | 被拒的 TCP/853 连接与内置 DoH/DoT 主机名的 TLS 连接数。 |
| `echStripped` | 改写了 `ech` SvcParam 的 HTTPS/SVCB 应答数。 |
| `ipv6Suppressed` | 因为 `ipv6=false` 而在本地答成 NODATA 的 AAAA 查询数（MYS-2710）。 |
| `ipv6HintStripped` | 因为 `ipv6=false` 而去掉 `ipv6hint` 的 HTTPS/SVCB 应答数。 |

M2b 新增（明文 HTTP 过滤）：

| 字段 | 含义 |
|---|---|
| `httpRequests` | 已判定的明文 HTTP 请求数（每个 keep-alive 请求各算一次）。 |
| `httpBlocked` | 其中被拦截、回了合成响应的请求数。 |
| `httpRedirected` | 被拦截且改回 `$redirect` 内置资源的请求数（`httpBlocked` 的子集）。 |
| `httpDegraded` | 中途放弃过滤、退化为逐字节直通的连接数（非 HTTP、`Upgrade`、头过大、chunked 帧损坏）。 |
| `httpEngineLoaded` | `engine.bin` 是否加载成功。`false` 表示只有域名级过滤（UI 必须如实显示）。 |
| `requestLogSize` | 环形请求日志当前条数（上限 2000），用于 UI 判断是否需要拉取。 |

`upstreamLatencyMsP50` 是成功查询耗时的中位数，用 32 个分桶（0–16 ms 每 1 ms 一桶，之后每桶翻倍）
统计，精度约 ±3%，无浮点、无不必要的内存分配。

## 4. compile 请求与结果

### requestJson

字段名即 `core/src/compile.rs::CompileRequest` 的字段名（`serde(rename_all = "camelCase")`）。

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `lists` | 数组 | `[]` | 要编译的列表，按加载顺序。元素见下。 |
| `userRules` | 字符串 | `""` | 用户自定义规则全文，语法与列表相同。既参与 DNS 层，也整体进入 adblock 引擎。 |
| `allowlist` | 字符串数组 | `[]` | 用户放行名单。接受裸域名，也接受 `@@\|\|domain^` 形式。**优先级最高**：压过一切列表规则，包括 `$important`。 |
| `outputDir` | 字符串 | 必填 | 产物目录；不存在时创建。`dns.bin` 与 `engine.bin` 都写在这里。 |
| `debugRules` | 布尔 | `false` | 是否把每条网络规则的原文记进 `engine.bin`。开启后 `FilterDecision.matchedRule` 才有值（请求日志能说明「被哪条规则拦的」），代价是**产物与常驻内存都约翻倍**（39.5 → 74.6 MB，设备 PSS 94 → 184 MB），因此**默认关闭**；数据见 `docs/PERF.md` §11.2/11.3。 |

`lists` 元素：

```json
{"id": "adguard-base", "path": "/data/user/0/top.zztweb.zshield/files/filters/lists/adguard-base.txt"}
```

`id` 必须是稳定标识：每列表的统计以它为键返回，Kotlin 用它把规则数写回对应的列表。

### 结果（`CompileStats`）

成功时返回字段（`serde(rename_all = "camelCase")`）：

```json
{
  "lists": [
    {"id": "adguard-dns", "lines": 190712, "dnsRules": 190019, "networkRules": 684,
     "cosmeticRules": 0, "unsupported": 0, "bytes": 4599606}
  ],
  "totalLines": 841677,
  "dnsRules": 376880,
  "networkRules": 422361,
  "cosmeticRules": 63581,
  "unsupported": 0,
  "networkOnly": 422362,
  "dnsBlockRules": 376628,
  "dnsExceptionRules": 63,
  "allowlist": 0,
  "elapsedMs": 3156,
  "dnsBytes": 4540543,
  "engineBytes": 41406009,
  "outputDir": "/data/user/0/top.zztweb.zshield/files/filters/compiled"
}
```

| 字段 | 含义 |
|---|---|
| `lists[]` | 每个列表一行的计数；用户自定义规则以 `id = "user-rules"` 作为伪列表出现，排在最后。 |
| `totalLines` | 全部行数（含注释）。 |
| `dnsRules` | 进入 DNS 过滤器的行数（hosts 与无修饰域名规则）。 |
| `networkRules` | 语法有效、但只交给 adblock 引擎的行数。 |
| `cosmeticRules` | 其中元素隐藏 / scriptlet 的行数。 |
| `unsupported` | **两层都用不了**的行数（UI 的「不支持」，定义见下）。 |
| `networkOnly` | DNS 层不用、但引擎能用的有效规则数；与 `unsupported` 分开，避免把「不是 DNS 规则」误报成「坏规则」。 |
| `dnsBlockRules` / `dnsExceptionRules` | `$badfilter` 结算后真正生效的 DNS 拦截 / 例外规则数。 |
| `allowlist` | 用户放行条目数。 |
| `elapsedMs` | 整个编译的墙钟耗时。 |
| `dnsBytes` / `engineBytes` | 两个产物的字节数（含版本头）。 |

失败时返回 `{"error": "..."}`，不抛异常。

### 「不支持」的唯一定义

**一行只有在 DNS 层和 adblock 引擎都无法使用时才算「不支持」。** 这个定义写在
`core/src/dns/filter.rs::FilterBuilder::add_text`，并且是编译统计（`CompileStats.unsupported`）、
`dns.bin` 头部（`reload` 读的就是它）、热替换日志（`rules reloaded: … unsupported …`）和 UI
（`stats.unsupported` / 每个列表的 `unsupportedCount`）**唯一**的数字来源。

| 行 | DNS 层 | adblock 引擎 | 计入 |
|---|---|---|---|
| `\|\|a.com^` | 拦截该域名 | 可解析 | `dnsRules` |
| `\|\|a.com^$third-party` | 不是 DNS 规则 | 可解析 | `networkRules` |
| `a.com##.ad` | 不是 DNS 规则 | 可解析 | `networkRules`（并计入 `cosmeticRules`） |
| `\|\|a.com^$unknownmod` | 不是 DNS 规则 | **拒绝** | `unsupported` |
| `\|\|a.com^$`（空修饰列表） | 拒绝 | **拒绝** | `unsupported` |
| `!` 注释 / 空行 / `[Adblock Plus 2.0]` | — | — | 都不计（只出现在 `lines`） |

判定方式：DNS 层拒绝或「不是 DNS 规则」的行，再用 adblock-rust 自己的
`parse_filter(line, …)` 问一次；它接受就是 `networkRules`，拒绝才是 `unsupported`。代价是每行
约 0.4 µs，而且只对被 DNS 层拒绝的行执行（实测 20 万行合成列表里两者都要判的行约占一半，
总耗时增加不到 100 ms，编译本身是 3~4 s）。

MYS-2716 §3 修复前这里有两个不同的口径：编译侧统计的是「DNS 层拒绝的行」，热替换日志打印的是
`dns.bin` 头部里的 `RuleStats::unsupported`，于是同一套规则会同时出现「不支持 0」和
「107 unsupported」；而 `$nonsense` 这种「两层都拒绝、却被记成引擎规则」的行则哪边都不报。
现在两边同源，回归测试见 `dns::filter::tests::unsupported_means_neither_layer_can_use_the_line`
与 `the_unsupported_definition_survives_the_artifact_round_trip`。

`RuleStats::unsupported_by_reason`（`dns.bin` 头部的 `r` 行、`statsJson` 的
`rulesUnsupported`）保留 DNS 层自己的分解原因，**是诊断用途的另一个计数器**：悬空的
`$badfilter`（`dangling_badfilter`）会记在这里，但不会计入 `unsupported` —— 那行语法是合法的，
引擎能用，只是它引用的规则不存在。

### DNS 层规则选择（必须遵守）

| 规则形态 | 去向 |
|---|---|
| `<ip> <domain>` / 裸 `domain`（hosts） | DNS 过滤器 |
| `\|\|domain^`、`\|domain^`、无修饰 | DNS 过滤器 |
| 同上，仅带 `$important` / `$badfilter` | DNS 过滤器 |
| 带 `$third-party`、`$domain=`、`$denyallow`、资源类型等作用域修饰 | **只进引擎** |
| 含路径（`\|\|a.com/path`）、通配、正则 | **只进引擎** |
| `##` / `#@#` / `##+js(...)` 元素隐藏与 scriptlet | **只进引擎** |

理由：`\|\|cdn.example/ads.js` 只禁止该 URL，而 `\|\|cdn.example^` 禁止整个域名。把前者当后者处理会
整站断掉，是过滤列表作者从未意图的行为（任务卡 §4）。

### 产物格式

两个文件共用 20 字节头：magic(8) + 格式版本(2) + 保留(2) + 载荷长度(4) + 载荷 CRC32(4)。
`dns.bin` 载荷是自描述的「section + TAB + domain」文本（含规则统计行），`engine.bin` 载荷是
adblock-rust `Engine::serialize()` 的字节。magic 区分两个产物，版本不符或校验失败一律返回错误，
由 Kotlin 触发重编译——**任何情况下都不崩溃**。

写入一律 `临时文件 + fsync + rename`，读者要么看到旧文件要么看到新文件。

## 5. 线程与生命周期

- `start` 在内部创建 tokio 多线程 runtime（线程名 `zshield-core`），返回后立即返回，不阻塞调用线程。
  隧道循环只等三件事：TUN fd 可读、转发任务的通知、栈自己的下一个 deadline。空闲且无连接时
  `Interface::poll_delay()` 为 `None`，循环永久阻塞在 fd 上，**没有任何周期定时器**（DNS 缓存清理也
  改成了查询路径上的惰性清理）。
- `compile` 同步执行并阻塞调用线程；函数内部用两个线程并行产出 DNS 与引擎产物（互不依赖），
  在 Pixel 5 上把默认启用集的编译从 ~4.3 s 降到 ~3.2 s。Kotlin 必须在 `Dispatchers.IO` 上调用。
- `reload` 只做反序列化 + 指针替换 + 清缓存；反序列化 `dns.bin`（4.5 MB / 37 万条）在 Pixel 5 上约 190 ms。
- 引擎的所有工作都在该 runtime 上；`stop` 置停止标志、等待隧道循环退出、关闭 fd。
- `statsJson` 只读共享计数器，可在任意线程调用。
- 一个进程可有多个句柄（M0 实际只用 1 个），每个句柄独立持有自己的 TUN fd 与引擎。

### 5.1 首编译热替换（MYS-2716 §1）

隧道的两条过滤管线（明文 HTTP 的 `engine.bin`、HTTPS 解密的 `HttpsPipeline`）放在
`core/src/tunnel.rs::PipelineSlots` 里的两个 `RwLock` 槽位，**不是** `start` 时捕获的 `Option`。

这解决的是首次安装的时序问题：全新安装时 `engine.bin` 还不存在，VPN 可能在第一次编译完成前就被
打开。旧实现在 `start` 时把 `engine.bin` 读成 `Option` 存进句柄，编译随后完成时没有任何地方可以
安装它，于是调试页一直显示「引擎 未加载」，必须重启 VPN 才恢复。

现在的时序：

1. `start` 用当时能读到的产物初始化槽位（可能两个都为空）；
2. 第一次编译写完 `dns.bin` + `engine.bin` 后，Kotlin 的 `FilterRepository` 调 `reload`；
3. `reload` 换 DNS 规则，并在槽位为空时**装入**引擎（`engine.bin` 刚反序列化的那一份，不重复读盘）；
4. 引擎到位后，如果配置要求 HTTPS 过滤且 CA 已装，同一步里把 `HttpsPipeline` 也建起来
   （它缺的就是「一个能判定请求的引擎」这一前提）；
5. 之后每条新连接在分派时取一次槽位快照，进行中的连接不受影响。

因此 `statsJson.httpEngineLoaded` 与 `httpsFiltering` 在编译完成后当次就变 `true`，不需要重建隧道。
回归测试：`jni_api::tests::the_engine_is_loaded_into_a_running_tunnel_on_the_first_compile`、
`the_https_pipeline_is_installed_by_the_first_compile_too`。

## 6. 明文 HTTP 过滤（M2b）

管线在 `core/src/http/`，是 M3（HTTPS 解密后过滤）直接复用的基础：M3 只需把解密后的请求交给
`http::decision`，URL / 来源 / 类型模型与合成响应都不变。

### 6.1 接入点与退化

接入点是 M2a 在 `core/src/tun/forward.rs` 首包嗅探之后的位置。嗅探结论决定走哪条路：

| 首包 | 走法 |
|---|---|
| TLS 记录 | SNI 判定 + 逐字节直通（M2a 行为不变） |
| HTTP/1.x 或前缀不足以判断 | `http::relay::run`：**逐个请求**判定，服务器→客户端仍逐字节直通 |
| 其它（服务端先说话、二进制协议、HTTP/2 前言） | 逐字节直通 |

会让一条连接**从某一点起退回逐字节直通**（`httpDegraded` 计数）的情况，而不是断开：

| 情况 | 处理 |
|---|---|
| 请求头超过 `httpHeadBytes` | 直通 |
| `Content-Length` 与 `Transfer-Encoding` 并存、两个不同的长度、`Content-Length` 不是纯十进制（如 `+5`）、无法分帧的 transfer coding | 直通（RFC 9112 §6.2/§6.3 允许的两种处理之一是报错；这里选择直通，绝不猜长度） |
| chunked 帧无法解析 | 已读到的请求体字节**先转发**，其余连接直通（丢弃会让服务器收到截断的请求体） |
| `CONNECT` / `Upgrade`（h2c、WebSocket） | 握手起直通 |
| 第一个 `\n` 之后的请求行版本不是 `HTTP/1.0`/`HTTP/1.1`（memcached 文本协议、HTTP/0.9） | 直通，不等到请求头结束 |
| 管线化：前一个已放行请求的响应还没结束时又来一个**被拦截**请求 | 直通并计数（见下） |

一个连接被放弃过滤是小损失；因为解析器而把连接弄坏不可接受。

### 6.1.1 被拦截请求的连接处理

| 被拦截请求的特征 | 响应与连接 |
|---|---|
| 没有请求体、没有 `Expect`（绝大多数 GET） | 合成响应后**保持连接**，下一个请求照常判定 |
| 有请求体（`Content-Length > 0` 或 chunked）或 `Expect: 100-continue` | 合成响应带 `Connection: close`，随后关闭（RFC 9112 §9.6） |

理由：浏览器把一个页面铺在 6 条 keep-alive 连接上，每拦一个广告就断开一次会让整页变重连风暴；但一个带
请求体的被拦截请求不能读掉请求体继续用——`Expect: 100-continue` 的客户端在收到最终响应后可能永不发送
请求体，那个请求体就会被当成下一个请求头。**被拦截请求的任何字节都不会到达服务器。**

### 6.1.2 管线化请求的顺序

响应必须按请求顺序写给客户端。若前一个已放行请求的响应还没结束，此时又要给一个被拦截请求写合成响应，
就会把我们的状态行插进那个响应体中间。

**取舍：整条连接转为逐字节直通并计入 `httpDegraded`，不等待。** 等待（等服务器把前一个响应发完）是教科书
做法，但它要求在一个不归我们控制的 socket 上无限期等待：服务器接了请求却不回包时会卡住整条连接。
直通是有界的、不会死锁、且在计数里可见。代价是：管线化的连接上，排在一个未响应请求之后的被拦截请求会被
放行。浏览器早已不用 HTTP/1.1 管线化，所以这是一条保护正确性的、实际不可达的兜底路径。

### 6.2 请求模型与判定

- **URL**：`scheme://Host[:port] + origin-form target`。默认端口（`:80`）会从 URL 里去掉，否则
  `||host^` 对 `Host: host:80` 失效。
- **来源**：`Referer`，只接受 `http(s)`。**没有来源时按首方处理**——adblock-rust 自己的
  `Request::new` 把无法解析的来源当作第三方，会让 `$third-party` 规则误伤每一个不带 referer 的请求，
  因此请求用 `Request::preparsed` 构造、显式给出首/三方。
- **类型**：`Sec-Fetch-Dest` 优先；缺失时用 `Accept`；两者都没有给 `other`。
  **不看 URL 后缀**——`ads.js` 说明不了服务器返回什么。完整的推断表在 `core/src/http/resource.rs`。
- **首/三方**：按可注册域名（eTLD+1）比较，`news.example.com → cdn.example.com` 算首方。

### 6.3 拦截动作

| 情况 | 响应 |
|---|---|
| `document` / `subdocument` | `403` + 极简内联页面（纯文本说明 + 被拦 URL，**无任何外链/样式/脚本**） |
| 其它子资源 | `204 No Content`，空体 |
| 规则给了 `$redirect` | `200` + 内置资源（MIME 与字节） |

内置资源（`core/src/http/resources.rs`）：`noopjs`、`noopcss`、`noop.txt`、`noopvmap-1.0`、
`1x1.gif`、`2x2.png`、`3x2.png`、`32x32.png`、`noop-0.1s.mp3`、`noop-1s.mp4`、`noopframe` 及常用别名
（`noop.js`、`1x1-transparent.gif`、`noopmp3-0.1s` …）。名字未注册时 adblock-rust 会**静默丢掉 redirect**、
退化成普通拦截，所以这些资源必须随 core 打包，不能依赖列表自带。

三个响应都带精确 `Content-Length` 且**不关闭连接**：浏览器把一个页面铺在 6 条 keep-alive 连接上，
每个被拦广告都断开一次会让整页变成重连风暴。被拦请求的 body 会被读掉并丢弃，不会被误当成下一个请求头。

### 6.4 recentRequestsJson

返回 JSON 数组（`serde(rename_all = "camelCase")`，对应 `core/src/http/log.rs::RequestLogEntry`、
Kotlin 侧 `RequestLogEntry`；`HttpRequestLogEntry` 是它的 Kotlin 类型别名）：

```json
[{"id":7,"kind":"http","timeMs":1234,"atMs":1234,"host":"ads.example.com",
  "url":"http://ads.example.com/banner.js","truncated":false,"method":"GET",
  "resourceType":"script","outcome":"blocked","rule":"||ads.example.com^$script",
  "thirdParty":true,"cosmetic":false},
 {"id":8,"kind":"dns","timeMs":1240,"host":"ads.example.com","outcome":"blocked","qtype":"A"},
 {"id":9,"kind":"dns","timeMs":1250,"host":"metrics.clean-site.com","outcome":"blocked",
  "qtype":"A","reason":"cname","cname":"tracker.doubleclick.net"},
 {"id":10,"kind":"connection","timeMs":1260,"host":"142.250.74.4:443","outcome":"blocked",
  "reason":"quic"}]
```

MYS-2742 之前日志只记 HTTP 请求，于是关掉 HTTPS 过滤时绝大多数拦截发生在 DNS 层，日志几乎空白而
首页「已拦截」一直在涨。现在三类事件共用一条 id 序列、一个环形缓冲，字段如下：

| 字段 | 适用 `kind` | 含义 |
|---|---|---|
| `id` | 全部 | 单调递增，跨环形回绕仍然递增；下一次调用把它作为 `sinceId` 即可拿到新条目。三类共用，所以一个游标能同时跟上 DNS、连接与 HTTP。 |
| `kind` | 全部 | `dns` / `connection` / `http`。**缺失按 `http` 处理**（旧数据没有这个字段，而它们全都是 HTTP 条目）。 |
| `timeMs` | 全部 | 隧道启动以来的毫秒数。每条都有。 |
| `host` | 全部 | DNS：查询名；连接：SNI/`Host`，拿不到时为 `ip:port`；HTTP：小写主机名（不含端口）。 |
| `outcome` | 全部 | `dns` 为 `blocked` / `allowed` / `cached`；`connection` 恒为 `blocked`；`http` 为 `allowed` / `blocked` / `redirected` / `exception`。 |
| `rule` | HTTP（DNS 命中时） | 命中的规则原文；**只有 `debugRules: true` 编译时才有**，否则字段缺失（不猜）。 |
| `reason` | DNS / 连接 | DNS 的 CNAME 反隐藏命中为 `cname`；连接级为 `rule` / `encrypted_dns` / `dot` / `quic`。 |
| `cname` | DNS | CNAME 反隐藏时命中的那一级（`host` 仍是客户端查询的名字）。 |
| `qtype` | DNS | `A` / `AAAA` / `HTTPS` / … ；未知类型给数字，不硬塞成 `A`。 |
| `atMs` | HTTP | M2b 的旧名字，值与 `timeMs` 相同（保留是为了不破坏既有读取方）。 |
| `url` / `truncated` | HTTP | 参与匹配的完整 URL；超过 512 字节截断并置 `truncated`（按字符边界截，不会切坏 UTF-8）。 |
| `method` / `resourceType` | HTTP | 方法、推断出的资源类型（`document` / `script` / …）。**改名了**：原字段叫 `kind`，而 `kind` 现在表示「哪一层」。 |
| `exceptionRule` | HTTP | 抵消拦截的例外规则。 |
| `thirdParty` | HTTP | 是否三方；无来源按首方。 |
| `cosmetic` | HTTP | 该 document 的响应被改写并注入过（8.2）。 |

某类用不到的字段**不出现**（不是 `null`），所以一条 DNS 记录只有七个键。

容量 2000 条，满了丢最旧的。日志只在这里序列化——没有推送、没有定时器，UI 不拉就没有开销。
**只在内存**：隧道停止即清空（含 QUIC 去重表），不落盘（`docs/DESIGN.md` §11）。

### 6.5 已知边界（刻意不修，记录在此）

| 边界 | 说明 | 为什么不修 |
|---|---|---|
| 服务器在上传过程中提前回 `401`/`413` 并关闭连接时，客户端看到的是 RST | 请求体还没写完，服务器已经走了。转发路径收到 `UnexpectedEof`，连接按不干净结束处理（客户端 RST） | 这个顺序下客户端本来就拿不到完整响应；把它包装成 FIN 只会伪装成一次正常的服务器关闭，让客户端不去重试。真实服务器极少在请求体中途关闭 |
| 上传请求体期间写回客户端时会暂停读客户端 | `write_pumping` 在「写服务器」与「读服务器」之间 `select`，写客户端是其中的 `await` | 这是避免「服务器早答导致双向死锁」的代价：必须同时读服务器。缓冲区 32 KiB、客户端窗口有限，实际只有在服务器先回一大段响应且客户端又停止读取时才会互相等 |
| 排名在被放行请求之后的被拦截请求，在管线化连接上会被放行 | 见 6.1.2 | 见 6.1.2 |

### 6.6 三类拦截与计数的一致性

要让「日志里的拦截条数」和首页「已拦截」回答同一个问题，两侧的口径必须逐条对齐：

| 事件 | 日志 `kind` | 计数 |
|---|---|---|
| DNS 规则命中 | `dns`，`outcome=blocked` | `dnsBlocked` |
| 缓存命中 / 放行 / AAAA 抑制 | `dns`，`allowed` 或 `cached` | 只进 `dnsCached` / `dnsQueries`，不进拦截数 |
| 上游失败 | **不记日志** | 只进 `dnsErrors`（不是过滤决定，混进来会破坏对账） |
| SNI/`Host` 规则拒、DoT 拒、加密 DNS 端点 | `connection`，`reason` 说明哪一种 | `blockedConnections`（`encryptedDnsDropped` 是明细） |
| QUIC 丢弃 | `connection`，`reason=quic` | `blockedConnections` + `quicDropped` |
| HTTP 拦截（明文或解密） | `http`，`blocked` / `redirected` | `httpBlocked` |

**一致性不变量**：环形缓冲未溢出时，
`日志中 outcome=blocked 的条目数（三类相加） == dnsBlocked + blockedConnections + httpBlocked 的增量`。
单元测试 `jni_api::tests::the_request_log_records_every_layer_and_matches_the_blocked_counters`
与 `tun::forward::tests::a_logged_connection_block_counts_exactly_one_entry` 守住这条。

**QUIC 去重**：浏览器对一个站点会持续发 HTTP/3 数据报，逐包记一行会在一秒内冲掉整个环形缓冲，所以
同一个目的 `ip:port` 在 60 s 内只记一次。**计数与日志在同一处决定**（`tun::forward::record_connection_block`）：
被日志去重掉的数据报也不计数，因此 `quicDropped` 报的是「被拦的目的地址数」而不是原始包数——两个数字
始终等于用户看到的那行日志数量。

## 7. HTTPS 过滤（M3a）

管线在 `core/src/https/`：本机根证书、按应用与按域名的解密选择、TLS 双向终结、HTTP/1.1 与
HTTP/2 的逐请求判定、解密后才成立的修饰符（`$removeparam` / `$removeheader` / `$csp`），以及
「不让任何应用断网」的两条兜底（上游证书无效 → 直通；客户端拒绝我们的证书 → 自动放行）。

### 7.1 新增方法

```kotlin
external fun generateCa(): String
external fun loadCa(certPem: String, keyPkcs8: ByteArray): Boolean
external fun httpsBypassJson(handle: Long): String
external fun clearHttpsBypass(handle: Long): Boolean
external fun updateHttpsPolicy(handle: Long, policyJson: String): Boolean
```

| 方法 | 何时调用 | 失败语义 |
|---|---|---|
| `generateCa` | 用户首次生成或「重新生成」 | 返回 `{"error": "..."}`，不抛异常 |
| `loadCa` | **每次 `start` 之前** | 返回 `false` 并写 `lastError`；**之前已加载的 CA 保持有效**（有旧 CA 的隧道仍能过滤，没有 CA 的隧道什么都不能解密，所以保留旧的更安全） |
| `httpsBypassJson` | UI 打开「为什么这个应用没被过滤」时 | 未知 handle 返回 `[]` |
| `clearHttpsBypass` | CA 安装状态变为「已安装」之后 | 未知 handle 返回 `false`；HTTPS 未运行返回 `true`（没有东西要清） |
| `updateHttpsPolicy` | 运行中改变勾选的应用或排除域名 | 未知 handle / 没有 HTTPS 管线 / JSON 非法 → `false` + `lastError` |

### 7.2 `generateCa` 的返回

```json
{"certPem": "-----BEGIN CERTIFICATE-----\n<证书正文，省略>\n-----END CERTIFICATE-----\n",
 "keyPkcs8B64": "<PKCS#8 DER 的 Base64，省略>",
 "fingerprintSha256": "<证书 DER 的 SHA-256，64 位小写十六进制>",
 "notAfterMs": 2109778575000}
```

（上面四个字段只说明形状。早期版本这里印了一段看起来像真实密钥的 Base64 前缀，虽已截断、不含任何
密钥材料，但样式与真密钥难以区分，容易被误抄进代码或当成可复用样本，因此改成显式省略。需要真实样本时
自行调用 `generateCa` 生成；`notAfterMs` 这个数字是本机曾生成过的某个 CA 的到期时间，不是可复用值。）

**私钥只在这里出现一次。** Kotlin 侧立刻用 Android Keystore 里的 AES-GCM 密钥加密后写入
`files/https/ca.key.enc`，明文只在 `CertManager.generate()` 的调用栈里存在；私钥不进 `configJson`、
不进 `statsJson`、不进任何日志（`CaKey` 的 `Debug` 实现固定输出 `[secret elided]`，`GeneratedCa`
根本没有实现 `Debug`）。证书是公开的，存为 `files/https/ca.crt`。

### 7.3 `configJson` 新增字段

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `httpsFiltering` | bool | `false` | 是否解密。**Kotlin 侧把 `CaState.installed` 折进来**：CA 没装就是 `false`，因为用一个没被信任的 CA 解密只会让每条连接握手失败 |
| `httpsUids` | int[] | `[]` | 要解密的应用 uid（浏览器名单 ∪ 用户勾选，Kotlin 换算；未安装的包跳过——uid 会被复用） |
| `httpsExcludedHosts` | string[] | `[]` | 额外排除域名（用户自己加的），与文件合并、去重 |
| `httpsExcludedHostsFile` | string | `""` | `assets/https/excluded-hosts.txt` 的落地路径；文件缺失只告警，不影响启动 |

四个条件全满足才会建 HTTPS 管线，任一不满足都**只是不解密**（隧道照常按明文与域名过滤），原因写入
`lastError`：`httpsFiltering` 开启、`engine.bin` 已加载、`loadCa` 已装入 CA、上游 TLS 配置可建
（Android 上即 platform verifier 可用）。

### 7.4 `statsJson` 新增计数

| 字段 | 含义 |
|---|---|
| `httpsFiltering` | 核心是否真的在解密（不是用户意图） |
| `httpsIntercepted` | 解密并过滤的连接数 |
| `httpsPassthrough` | 443 上**主动不解密**的连接数（见 7.5 的每一条原因） |
| `httpsAutoBypassed` | 进入自动放行表的连接数 |
| `httpsUpstreamInvalid` | 上游证书校验失败的连接数（已按要求直通） |
| `httpsHandshakeFailures` | 客户端侧握手失败数 |
| `httpsDisconnectsIgnored` | 其中**未计入自动放行判定**的断开数（浏览器并行预连接、或证书发出前就断开，见 7.6） |
| `h2Streams` | 解密连接上判定的 HTTP/2 请求数 |
| `h2Blocked` | 其中被本地应答的 |
| `httpsBypassEntries` | 当前自动放行条目数 |
| `httpsRemoveHeaderRules` | 生效的 `$removeheader` 规则数 |

### 7.5 哪些 443 连接会被解密

判定是一个纯函数（`core/src/https/policy.rs::decide`），顺序有讲究——每一条能在 ClientHello 之后
就答完的检查都排在起 Binder 查询之前：

| 顺序 | 条件 | 结果 | 计为 |
|---|---|---|---|
| 1 | `httpsFiltering` 为假 | 直通 | `httpsPassthrough` |
| 2 | 目标端口不是 443 | 直通 | — |
| 3 | 没有 SNI | 直通（没有名字可签叶子） | `httpsPassthrough` |
| 4 | SNI 命中排除名单（含子域） | 直通 | `httpsPassthrough` |
| 5 | 查不到连接所属 uid | 直通（**绝不在猜的 uid 上解密**） | `httpsPassthrough` |
| 6 | (uid, host) 在自动放行表里 | 直通 | `httpsPassthrough` |
| 7 | uid 不在选择集里 | 直通 | `httpsPassthrough` |
| 8 | 以上都不成立 | 解密 | `httpsIntercepted` |

**连接所属应用**通过 JNI 回调 Kotlin 的静态方法获得：

```kotlin
object OwnerResolver {
    @JvmStatic fun ownerUid(protocol: Int, localIp: String, localPort: Int,
                            remoteIp: String, remotePort: Int): Int   // -1 = 未知
}
```

它内部调用 `ConnectivityManager.getConnectionOwnerUid`（API 29+）。API 28 或任何失败返回 `-1`，
而「未知」永不解密。

**这条调用是阻塞的、没有超时的 Binder 调用**，所以 core 侧有两条硬约束：

1. **只在真的需要时才查。** `decide_without_owner` 先用 ClientHello 和策略把能答的答完（未启用、
   非 443、无 SNI、命中排除域名、选择集为空），只有全过才走到查询。银行、支付、排除名单里的连接
   一次 Binder 都不会发。
2. **不占 tokio worker。** 查询放在 `tokio::task::spawn_blocking` 里，外面套 200 ms 超时；超时按
   「未知」处理（即直通）。worker 默认只有几个，一次卡住的 `system_server` 会拖死整条隧道。

**结果不做缓存。** 曾经的实现按 (源端口, 目的地址) 缓存 uid，那不是一个应用的身份：A 应用的连接关闭
后源端口会被复用，B 应用连同一个 `IP:443` 就会拿到 A 的 uid，于是用户没勾选的应用被解密——固定证书
的银行 App 会直接被弄坏。现在每条 443 连接查一次，不做任何复用。

类与 method id 在 `Native.init` 时缓存成 global ref —— 原生线程的 `FindClass` 走系统 ClassLoader，
找不到应用类；同时 `proguard-rules.pro` 里必须 `-keep` 这个类（R8 看不到 Rust 的调用方）。

### 7.6 解密转发的两条兜底

| 情况 | 处理 | 为什么 |
|---|---|---|
| 上游证书校验失败（无效、过期、名字不符、连不上） | 把**缓存的 ClientHello 原样重放**到一条新的 TCP 连接上，双向逐字节转发 | 上游 TLS 已经用我们的 ClientHello 开工了，客户端自己的字节再也发不到那条 socket 上。只有新连接才能让客户端看到并自行判断真实证书——信任固定证书的客户端照常工作，不信任的报出它本来会报的错 |
| 客户端**明确拒绝**我们的叶子证书（`unknown_ca` / `bad_certificate` / `certificate_unknown`） | 立刻把 (uid, host) 记入自动放行表，24 h 内直通 | 重试解密会让那个应用**永久**不可用。这是唯一一次就能定性的情况 |
| 客户端在**握手期断开**（`client_disconnect`） | 只有「该 (uid, host) 最近 10 分钟内**没有**成功握手」且「我们的证书**已经发出**」时，才按「同一 (uid, host) 10 分钟内第二次」放行；否则只计数 `httpsDisconnectsIgnored`，不影响放行判定 | 关标签页、切网络、客户端自己的超时，在线上和「拒绝证书」长得一模一样；更常见的是浏览器**并行预连接**：同一域名同时开多条 TLS，一条成功后立刻掐掉其余的。若不区分，刚解密成功的 CDN 域名会被自己刚掐断的连接打进 24 h 直通 |
| 本地错误（签发失败、内部 TLS 错误） | **不放行**，只计数 | 这是我们的 bug，不是客户端的判决；放行等于让 bug 静默地把该域名关掉一天 |

注意：`httpsUpstreamInvalid` 与「客户端拒绝」是两件不同的事，前者是源站的问题，后者是客户端的选择。

#### 7.6.1 断开的两个前提（MYS-2727）

`client_disconnect` 只有在下面两条**同时**成立时才作为放行证据（`core/src/https/policy.rs::AutoBypass::observe`）：

1. **该 (uid, host) 最近没有成功过。** 每次下游握手成功都会在 `AutoBypass::record_success` 里记一条
   `(uid, host) → 时间戳`（上限 1024 条，写入时就地淘汰过期项与最旧项）。窗口内存在成功记录，说明客户端
   接受我们的证书，随后的断开是连接竞速失败，不是判决。成功记录同时会清掉该 pair 的半截「第一次断开」
   计数——中间成功过，之前那次就不能再算一票。
2. **我们的证书已经发出。** 由 `core/src/https/tls.rs::CertificateSent` 判定：rustls 在构造 Certificate
   消息时恰好、且只调用一次证书解析器（`ResolvesServerCert::resolve`），所以解析器里置位就等于「证书正在
   发给客户端」。ClientHello 之后、证书之前就断开的连接永远没见过叶子证书，不计入。这个判定不依赖 TLS
   版本，也不需要第二个握手解析器。

明确的告警（`unknown_ca` / `bad_certificate` / `certificate_unknown` / `certificate_required`）**不受这两条
限制**，仍然立即放行：那是客户端说出口的判决。

### 7.7 ALPN 与协议选择

- 上游只提供客户端实际提出、且本 core 会说的协议，交集为 `h2`、`http/1.1`，保持客户端偏好顺序。
- 客户端一个 ALPN 都没提 → 两端都按 `http/1.1`。
- **下游只提供上游协商出的那一个协议**（上游没有 ALPN 时只提供 `http/1.1`）。先做完上游握手，再拿
  它的结果去和客户端握手，于是两边必然一致：客户端要 h2 而上游只有 http/1.1 时，客户端自己落到
  `http/1.1`，请求正常完成——这正是它不经过我们时会有的结果。

### 7.8 解密后才成立的修饰符

| 修饰符 | 实现位置 | 行为 |
|---|---|---|
| `$removeparam` | 引擎（`decision_full`），由 `http::relay` / `https::h2` 应用 | 子资源原地改写请求 target；**document 用 `302` 跳转**到改写后的 URL（静默改写会让地址栏与实际 URL 不一致） |
| `$csp` | 引擎（`get_csp_directives`） | 给 document 响应**追加**一条 `Content-Security-Policy`；已有策略与之合并（逗号分隔，浏览器取交集），**不替换**——替换会削弱站点自己的策略 |
| `$removeheader` | `core/src/https/modifiers.rs`（**adblock-rust 不实现**） | 见 7.8.1 |
| `$redirect` | `http::decision`（M2b 已有） | 本地返回替代资源 |

这四个只在**解密连接**上生效：明文连接上 `$removeparam` 会改掉用户在地址栏能看到的 URL，`$csp` 对
非 HTTPS 文档也没有意义，因此 M2b 的逐字节转发行为完全不变。

#### 7.8.1 `$removeheader` 是怎么实现的

adblock-rust 的解析器直接拒绝这个选项（`UnrecognisedOption`），所以它在编译统计里一直落在「不支持」
桶里。这里没有 fork 引擎，而是：把每一行带 `$removeheader=<name>` 的规则**剥掉这个选项**后用引擎自己的
`NetworkFilter::parse` 重新解析（`||a.example^$removeheader=refresh,script` → `||a.example^$script`），
再按 header 名分组各编译一个小 `Engine`。请求来了就问那个 engine「匹配吗」，用引擎自己的
`should_block()`。

这样 `$domain=`、内容类型、`@@` 例外的语义与普通规则完全一致，不会随引擎版本漂移。`$removeheader`
同时作用于**请求头与响应头**：规则文本不区分方向（`set-cookie` 是响应头、`cookie` 是请求头），
AdGuard 也是两边都删。

#### 7.8.2 上游证书校验不在 tokio worker 上跑（MYS-2716 §5）

`rustls-platform-verifier` 的上游校验是一次**同步 JNI 调用**进 `system_server`
（`CertChainValidator`），可能耗时数毫秒且不能 yield。core 的 runtime 只有 2 个 worker
（`core/src/config.rs::workers`），若直接在 worker 上跑，几次并发 443 握手就能把两个 worker 都堵在
证书校验里，DNS、明文 HTTP 与直通转发全部排队。

因此 `core/src/https/tls.rs::client_config` 把平台校验器包进 `BlockingVerifier`，
`verify_server_cert` 通过 `tokio::task::block_in_place` 执行（要求多线程 runtime，`start_engine` 建
的就是多线程 runtime）。**校验逻辑与结论完全不变** —— 包装器只是把内部校验器原样委托并把结果原样
返回；`verify_tls12_signature` / `verify_tls13_signature` / `supported_verify_schemes` /
`root_hint_subjects` 直接委托，因为它们没有跨进程调用。

没有多线程 runtime 时（单测、主机侧工具）自动退化为就地执行，行为与包装前一致，不会 panic。
回归测试 `https::tls::tests::the_blocking_wrapper_keeps_the_runtime_progressing_during_the_check`
用单 worker runtime 证明：包装后同一 worker 上其它任务在校验期间仍在推进（心跳 task 能 yield
十万次量级），去掉 `block_in_place` 则只有 1 次 —— 即 worker 被完全占用。

### 7.9 已知边界（刻意不修，记录在此）

| 边界 | 说明 | 为什么不修 |
|---|---|---|
| HTTP/2 server push 不支持 | 浏览器已移除，源站也不会对我们以客户端身份打开的连接用 | 一个 PUSH_PROMISE 对 `h2` 的 client 是协议错误，会 reset 那条流并保留连接可用 |
| 客户端用 h2、上游只给 http/1.1 时客户端落到 http/1.1 | 见 7.7：下游只提供上游选中的协议 | 不是缺陷，是让它和不经过我们时的行为一致 |
| WebSocket / `Upgrade` 在解密连接上仍走 HTTP/1.1 逐字节直通 | 握手头之后的字节无法逐请求判定 | 与 M2b 一致：`Upgrade` 之后没有「请求」这个概念 |
| 非 Android 构建没有 owner 查询 | 主机侧构建一律返回「未知」，于是永不解密 | 主机构建只是跑单测；HTTPS 端到端测试用自建 CA 直接驱动 `mitm::run`，不经过这条路径 |
| `$removeheader` 不认没有 hostname 锚的模式 | 如 `/ads.js$removeheader=refresh` 解析成功但永不匹配 | 匹配它需要完整 URL 匹配器；宁可少删一个头，也不要多删 |

## 8. 外观过滤（M3b）

对**已放行的 document 响应**做元素隐藏与 scriptlet 注入，实现在 `core/src/cosmetic/`。这一段只描述对
Kotlin 可见的部分；内部状态机见 `core/src/cosmetic/mod.rs` 的模块文档。

### 8.1 `statsJson` 新增计数

| 字段 | 含义 |
|---|---|
| `cosmeticInjected` | 至少插入了一个 `<style>`/`<script>` 的文档数。 |
| `cosmeticSkipped` | 判定为可注入但最终原样交付的文档数（窗口内找不到插入点、编码解不开、内容全被 CSP 拒绝）。**这个数字不是错误**：它正是「过滤器绝不弄坏页面」这条不变量的可见形式。 |
| `scriptletsInjected` | 插入了 scriptlet bundle 的文档数。 |
| `cosmeticCspMeta` | 正文里带 `<meta http-equiv="Content-Security-Policy">` 的文档数（刻意不改，见 8.5）。 |
| `cosmeticScriptlets` | core 内置的可注入 scriptlet 数量（当前 63 个 + 50 个依赖 helper），用于 UI 说明支持范围。 |
| `cosmeticRejectedSelectors` | 因不安全（含 `<`、`{`、`}`）**或浏览器无法解析**被丢弃的选择器数量，见 8.6 与 §9.1。非零说明某个订阅在携带恶意或损坏的规则。 |
| `cosmeticProcedural` | 注入了过程式运行时的文档数（M5b §2）。 |
| `cosmeticProceduralRules` | 过程式运行时收到的规则条数（各文档累加）。 |
| `cosmeticProceduralDropped` | 过程式规则中因选择器无法解析或动作参数越界被丢弃的条数，见 §9.2。 |
| `httpsPopupRules` | 生效的 `$popup` 规则数（M5b §3）。0 表示启用的列表里没有这类规则，不是「不支持」。 |
| `httpsDenyAllowRules` | 生效的 `$denyallow` 规则数（M5b §5）。 |
| `httpsRemoveParamRules` | 由本 core 自行求值的 `$removeparam` 规则数（正则形式与例外形式，M5b §6）。引擎自己能处理的普通形式不计入。 |

### 8.2 `recentRequestsJson` 新增字段

`RequestLogEntry.cosmetic`（布尔）：该 document 的响应被改写并注入过。它在响应体读完之后才置位（判定
发生在转发请求时，是否真的插入了要等 body 读完才知道），所以同一条记录的其它字段不变。

注意 `kind` 现在的含义是「哪一层」（`dns` / `connection` / `http`，见 6.4）；HTTP 的资源类型在
`resourceType`，即 M2b/M3b 时期称为 `kind` 的那个字段（MYS-2742）。

### 8.3 什么时候注入

| 条件 | 判据 |
|---|---|
| 请求类型 | `Sec-Fetch-Dest: document`（无该头时按 M2b 的推断表），且不是 `HEAD` |
| 响应状态 | `200` |
| `Content-Type` | `text/html` 或 `application/xhtml+xml`（参数忽略；大小写不敏感） |
| `Content-Encoding` | 缺失、`identity`、`gzip`、`x-gzip`（`br`/`zstd`/`deflate` 一律不碰） |
| 规则 | 引擎对该 URL 的 `url_cosmetic_resources` 或通用规则查询有结果 |

任一条不满足，响应**逐字节原样转发**，连头部都不动。

### 8.4 请求方向的 `Accept-Encoding`

为了让「解压—注入—以 identity 发出」始终可行，document 请求的 `Accept-Encoding` 被收窄为本地能解的
子集：`gzip, identity`。上游仍然是压缩传输，解压发生在本机回环内，不额外占网络。`br` 没有被选入：
`flate2` 的 `rust_backend` 不带 brotli，为它引入一个 C 依赖会让 NDK 构建与 APK 体积都变差，而 gzip 对
HTML 的压缩率与 br 相差不到 10%。

`core/src/cosmetic/gzip.rs` 自己解析 gzip 头（10 字节固定头 + 可选 FEXTRA/FNAME/FCOMMENT/FHCRC），
把负载交给 `flate2` 的 raw deflate 解码。原因：`rust_backend` 下 `Decompress::new_gzip` 不存在，而
`GzDecoder` 是 `Read` 适配器，无法驱动推送式的流式循环。尾部 CRC 不校验——校验失败只会把一个本来能
渲染的页面变成错误。

### 8.5 CSP

| 情况 | 处理 |
|---|---|
| `script-src`（缺失时回退 `default-src`）不含 `'unsafe-inline'` | 给注入的 `<script>` 加随机 nonce（16 字节，base64url），并在该指令末尾追加 `'nonce-…'` |
| 该指令含 `'unsafe-inline'`（且没有 nonce/hash 源） | **不加 nonce**：CSP2 规定出现了 nonce 后 `'unsafe-inline'` 失效，加了反而会打断页面自己的内联脚本 |
| 该指令已有 `'nonce-…'`/`'sha256-…'` 源 | 可以加：此时 `'unsafe-inline'` 本来就已经被忽略 |
| `style-src` | 同上，独立判定（一个页面可以允许内联脚本却禁止内联样式，反之亦然） |
| 多条 `Content-Security-Policy` | 逐条判定：需要 nonce 的追加，用 `'unsafe-inline'` 的保持原样；浏览器取交集，两者都能放行 |
| `<meta http-equiv="Content-Security-Policy">` | **不改**，计 `cosmeticCspMeta` |
| `$csp` 规则 | 过滤列表自己的策略，**原样追加、永不加 nonce**（放松它是反的）。它拒绝的元素直接不注入 |

改写策略时只按字节偏移插入，不改写指令的其它部分：原始的分隔空格、空指令、行尾 `;` 全部保留。

### 8.6 安全约束（订阅列表是不可信输入）

订阅源可以是任意第三方 URL，它携带的**选择器与 scriptlet 参数都是不可信文本**，而这两者会被拼进本
core 注入到每个页面的标记里。三条硬约束，任何一条被放宽都等于把「订阅列表」变成「任意页面执行任意
脚本」的入口：

| 约束 | 实现 | 为什么 |
|---|---|---|
| 含 `<` 或 `{` `}` 的选择器**一律丢弃**并计数（`cosmetic: … rejected`） | `inject.rs::screen_selector` | `div[title="</style><script>…</script>"]` 是合法 CSS 选择器，会闭合我们的 `<style>`；花括号会逃出规则块、让列表任意写 CSS。合法的元素隐藏选择器不需要字面 `<`。 |
| 脚本文本里所有 `</` 改写为 `<\/`，`<!--` 改写为 `<\!--` | `inject.rs::escape_script_body_into` | scriptlet 参数来自列表。`</script>` 会提前闭合元素，`<!--` 会让 HTML 解析器把余下内容当注释。`\/` 在 JavaScript 里就是 `/`，语义不变。 |
| `$csp` 规则追加的策略**永不加 nonce** | `inject.rs`（`allows_unmodified`） | 放松过滤列表自己要求的策略是反的；它拒绝的元素直接不注入。 |

被丢弃的选择器数量累加到 `CosmeticReport::rejected_selectors`，随文档日志上报——一条持续产出这类
选择器的列表，用户应当看得见。

### 8.7 通用规则的插入位置

通用（按文档 class/id 命中）选择器的 `<style>` 追加在**文档末尾**，不是第一个 `</body` 之前。
`</body` 会出现在内联脚本里（`document.write("<body></body>")`、模板字符串、JSON），插在那里会把带
换行的注入内容塞进 JavaScript 字符串并把页面弄坏；而 HTML 解析器接受 `</html>` 之后的 `<style>`。
流式处理下没有不解析 HTML 就能判断「哪个 `</body` 是真的」的办法，所以选了文档末尾。

### 8.8 分帧与不完整正文

| 情况 | 处理 |
|---|---|
| HTTP/1.1 改写后的正文 | `Transfer-Encoding: chunked` |
| HTTP/1.0 响应 | **不改 chunked**（1.0 没有这个编码）；改写后不声明长度，写完关闭连接标记结束 |
| HTTP/2 | 不带 `content-length`，`END_STREAM` 即结束 |
| 源站分帧未完成（`Content-Length` 不足、chunked 未到终止块） | **不写终止块**，直接关闭连接；h2 发 `RST_STREAM`。残缺页面不能被当成完整页面交付（否则可能被缓存） |
| gzip 成员未到结尾 | 同上——即使 HTTP 分帧「完成」，解码出的也只是文档前缀 |
| gzip 成员之后的残余字节（第二个成员、垃圾） | 丢弃并计数，**绝不**以未分帧形式写出（客户端会当成 chunk 头报分帧错误） |
| `Content-Disposition: attachment` | 不注入（下载文件不是浏览器里阅读的文档） |

### 8.9 内存上限

| 缓冲 | 上限 |
|---|---|
| 找插入点的前缀 | `SCAN_WINDOW` = 64 KiB（解码后） |
| 放弃注入时要原样回放的原始字节 | 仅用于「写出第一个字节之前还可能放弃」的阶段；注入一旦开始就释放 |
| gzip 解压输出 | 每轮 `OUTPUT_CHUNK` = 64 KiB，边解边写（32 KiB 压缩输入最坏膨胀到约 32 MiB，必须分轮） |
| class/id 扫描器的 carry | 272 B |
| 已收集的 class/id 值 | 每类最多 4096 条，每条 ≤ 256 B |

### 8.10 已知边界（刻意不修，记录在此）

| 边界 | 说明 | 为什么不修 |
|---|---|---|
| 通用 `<style>` 在文档末尾而不是 `</body>` 之前 | 见 8.7 | 见 8.7 |
| 脚本动态添加的元素不被通用规则覆盖 | 通用隐藏规则只在文档流里出现过的 `class`/`id` 上求值；页面自己后来加的节点看不到 | 要做就得注入 `MutationObserver` 与整个通用规则集（EasyList 有几万条），与「包小、省电」冲突；这是本里程碑明确写下的边界 |
| `#%#` / `#@%#` AdGuard scriptlet 语法不实现 | 引擎解析器直接拒绝，计入「不支持」 | 与 uBO `##+js()` 语义不同，需要另写一套；条数在 200 以下 |
| `:watch-attr`、`:others`、`:shadow`、`:matches-media`、`:matches-prop` 不实现 | 引擎解析器不产生这些算子，运行时不收录 | 不可达即不必实现；真出现时运行时会**停止该条规则**而不是错配（见 §9.2） |
| 过程式规则不监听 iframe 内部的变化 | 只观察主文档 | 跨文档观察需要每个 frame 各自注入，收益与成本不成比例；元素隐藏本身对子框架是逐响应判定的（8.3） |
| 窗口外找不到插入点的文档不注入 | 首 64 KiB 里没有 `<head>`/`<html>`，且文档还没结束 | 任务卡 §4 的边界：继续缓冲会无上限占内存 |
| 单个 document 只在首 64 KiB 解码范围内找插入点 | 前缀长度上限即 `SCAN_WINDOW` | 同上 |
| 注入后的 body 一律以 identity 发出 | 解压后不再压缩 | 客户端—代理之间是本机回环，重新压缩只多耗 CPU 与电 |
| 只转 ASCII 标签字节，不做字符集转码 | 文档可以是 GBK/Shift-JIS，转码会引入第二种弄坏页面的方式 | 所有查找都是 ASCII 字节比较，非 ASCII 字节原样透传 |

## 9. 规则补齐（M5b）

`docs/coverage.json`（M5a）量出的差距是 25,314 条规则「解析得动但本 core 从不消费」。M5b 修掉其中
按「条数 × 影响」排序的前几类，本节的每个数字都来自同一份 27 列表快照重新生成的 `coverage_probe`。

### 9.1 无效选择器不再连带摧毁整条 CSS（M5b §1）

M5a 在真机上证实：43 条注入选择器里 15 条过程式写法让浏览器丢弃**整条**规则，28 条本来有效的选择器
一起失效（`docs/EFFECTIVENESS.md` §9.3.3）。三层修法：

| 层 | 做什么 | 在哪 |
|---|---|---|
| 1 | `Cargo.toml` 启用 adblock 的 `css-validation`：引擎用浏览器的语法（`cssparser`/`selectors`）校验选择器，把过程式算子从纯 CSS 通道**拆出去**，并丢弃自己语法不接受的选择器 | `core/Cargo.toml` |
| 2 | 注入前每个纯 CSS 选择器再单独过一遍同一个语法（带进程级缓存，命中率接近 100%），不合法的**单独丢弃并计数** | `core/src/cosmetic/validate.rs` |
| 3 | 仍然按块输出（每 200 条一个规则块），作为第二道防线 | `inject.rs::SELECTORS_PER_BLOCK` |

第 2 层的代价实测：每个选择器约 6 µs（host 上 2000 条 12 ms），缓存后是一次哈希查找。体积：
`cssparser` + `selectors` 让 `libzshield.so` 增大 106,648 B（6,610,776 → 6,717,424），release APK
7.79 → 7.96 MB。

`cosmeticRejectedSelectors` 现在同时统计「不安全」与「浏览器解析不了」两种丢弃——两者都是「订阅在携带
这条选择器，而我们发不出去」。

### 9.2 过程式与动作类规则（M5b §2）

| 语法 | 条数 | 通道 |
|---|---:|---|
| `##…:style(…)` | 17,302 | 数据进注入脚本，挂载走 CSSOM `insertRule` |
| `##…:remove()` | 434 | 同上，直接移除节点 |
| `##…:remove-attr()` / `:remove-class()` | 19 | 同上 |
| `:has-text()` / `:upward()` / `:matches-css()` / `:matches-path()` / `:matches-attr()` / `:xpath()` / `:min-text-length()` | 1,223 | 同上，算子按序作用在节点集合上 |

实现见 `core/src/cosmetic/procedural.rs`；安全约束与算子语义见 §9.1 与 `cosmetic/procedural.rs` 的模块文档。运行时以 uBO 1.76 的过程式过滤
设计为蓝本（`docs/THIRD_PARTY.md` 已登记），输入是 adblock 给出的 `procedural_actions` JSON。

### 9.3 `$popup`（M5b §3）

6,222 条。`$popup` 是引擎解析器**整行拒绝**的修饰符，因此整条规则（包括它的 pattern 与其它选项）在
M5b 之前完全不起作用。本 core 自行求值：把 `$popup` 换成 `$document` 后交给引擎匹配，再叠加「这是一次
弹窗」的判定。规则数在 `statsJson.httpsPopupRules`。

#### 9.3.1 判定条件

三条必须同时成立，全部来自 Fetch Metadata 请求头：

| 头 | 要求 | 为什么 |
|---|---|---|
| `Sec-Fetch-Dest` | `document` | 弹窗是顶层导航，不是图片或脚本 |
| `Sec-Fetch-Site` | `cross-site` | 弹窗把用户带到**别的**站点 |
| `Sec-Fetch-User` | 缺失或不是 `?1` | `?1` 表示用户点击了链接/表单；弹窗没有这种激活 |

#### 9.3.2 误伤风险

| 场景 | 是否拦截 | 原因 |
|---|---|---|
| 同一标签页里点广告被带走 | **不拦** | 与点正常链接在隧道里无法区分；拦它等于拦掉普通浏览 |
| 同站弹窗（`Sec-Fetch-Site: same-origin`） | 不拦 | 站点在自己域内开窗是正常行为 |
| 不发送 Fetch Metadata 的客户端（旧浏览器、多数 WebView） | 不拦 | 猜错的代价是所有导航；宁可漏拦 |
| 跨站新窗口 + 无用户激活 | 拦 | 这就是 `$popup` 的定义 |

### 9.4 `*.domain` 归入 DNS 层（M5b §4）

293,686 条（oisd-small + oisd-big 全部）。

#### 9.4.1 归一规则

`*.example.com` 与 `||example.com^` 是同一条指令，所以 `dns::filter::parse_line` 现在把它归到 DNS
层，由一次 DNS 应答回答整域拦截，不再为每个连接判一次 SNI。

| 形式 | 归入 DNS 层 | 说明 |
|---|---|---|
| `*.a.example` | 是 | 通配符占满第一个标签，等价于 `\|\|a.example^` |
| `*.a.example^` | 是 | 同上，`^` 可有可无 |
| `@@*.a.example` | 是（例外） | 与 `@@\|\|a.example^` 等价 |
| `*.a.example^$important` | 是 | 同上 |
| `*ad.example`、`a*.example` | 否 | 通配符只占标签的一部分，后缀匹配表达不了 |
| `*`、`*.` | 否 | 没写域名 |
| `*.a.example^$third-party` | 否 | 带收窄选项，整域拦截会改变规则作者的意图 |

新旧一致性由单测钉住：同一批域名在 `*.same.example` 与 `\|\|same.example^` 下判定完全相同
（`core/src/dns/filter.rs` 的 `a_wildcard_rule_keeping_its_own_form_still_means_the_same_thing`）。归一规则与一致性测试见 §9.4.1。**不改变判定结果**：同一批
域名在两种写法下逐条比对通过。收益是隧道 CPU——这些整域拦截从「每个连接判一次 SNI」变成「一次 DNS
应答」。

### 9.5 `$denyallow`（M5b §5）

118 条。

#### 9.5.1 求值

uBO 的 CDN 豁免语法：`*$script,denyallow=cdn.a|cdn.b,domain=x` 的意思是「x 上的脚本全拦，除了这几个
CDN 的」。引擎同样整行拒绝，所以 M5b 之前这条规则**什么都不拦**（不只是不豁免）。

本 core 去掉 `denyallow=` 后把其余部分交给引擎匹配：

| 引擎匹配（去掉 denyallow 后） | 请求主机在 denyallow 名单内 | 结果 |
|---|---|---|
| 是 | 是 | 放行 |
| 是 | 否 | 拦截 |
| 否 | — | 不干预（交给引擎原本的判定） |

主机匹配按 `\|\|` 语义：`a.example` 命中 `a.example` 与 `x.a.example`，不命中 `nota.example`。
语义见 §9.5.1。注意这些规则在 M5b 之前**什么都不拦**：引擎整行拒绝，连它想拦的其余流量也一起
丢了。

### 9.6 `$removeparam` 正则与例外形式（M5b §6）

152 条（正则 57 + 例外 73 + 其它引擎不接受的 22）。

#### 9.6.1 谁求值

| 形式 | 谁求值 |
|---|---|
| `$removeparam=name`（`[a-zA-Z0-9_-]+`） | 引擎（M3a 已有），本 core **不重复求值** |
| `$removeparam`（无值，拦截规则） | 引擎：清空整个 query |
| `$removeparam`（无值，`@@` 例外规则） | 本 core：「这个范围内不要清理」 |
| `$removeparam=/regex/` | 本 core：对每个 `name=解码后的值` 求值 |
| `$removeparam=/regex/` 在 `@@` 上 | 本 core：取消该范围内的清理 |

正则的约束：编译期设了 64 KiB 的程序体上限（`RegexBuilder::size_limit`/`dfa_size_limit`），`regex`
crate 本身是线性时间匹配，所以订阅列表无法用灾难性回溯拖住隧道。规则总数上限
`MAX_REMOVEPARAM_RULES = 1024`（内置列表实际 205 条）。求值只发生在解密后的连接上。
求值规则与正则上限见 §9.6.1。

### 9.7 未做（任务卡明确排除）

`$urlskip`、`$replace`、`$permissions`、`$ipaddress`、`$cname`、`$elemhide`、`$genericblock`、
`$popunder`、`##^` HTML 过滤、`trusted-` scriptlet —— 每一条都需要一套独立的求值器，单类条数都在 200
以下，收益与成本不成比例（`docs/EFFECTIVENESS.md` §9.5 的排序结论未变）。

### 9.8 `extras.txt` 产物

自行求值的规则（`$popup`、`$denyallow`、`$removeparam` 的非引擎形式）不属于 `engine.bin`，所以随编译
一起写成 `files/compiled/extras.txt`（`Envelope` 包装，`Artifact::Extras`）。存的是**原始规则行**而不是
编译结果：文件是几万条规则里的一千多条，启动时重新解析约 70 ms，而存原始文本意味着升级 core 之后同一
批规则能用上新的求值逻辑，不必重新编译引擎。文件损坏或缺席都不是致命错误——引擎自己的规则照常生效，
原因写进 logcat。

### 9.9 编译统计

`compile` 的日志新增一行 `extra modifiers: N popup, N denyallow, N removeparam, extras.txt N B`，
`CompileStats.extrasBytes` 上报文件大小。它是判断「列表里这类规则是否还在」的唯一入口：引擎的
`unsupported` 计数看不到它们（引擎拒绝了整行）。

## 10. 规则内容身份（MYS-2825）

PSS 就绪判据此前只能用「`engine.bin` 多少字节」「多少条规则」描述「正在跑哪套规则」。两者都不是
内容身份：同长度、同条数、不同规则的两套规则给出同样的数字。缺的不是脚本里的检查，而是 core 从没
观测过自己装了什么，所以观测加在这里——字节所在的地方。

### 10.1 观测什么、什么时候

一次启动或一次**成功**热替换，各打印一行：

```text
rules identity: event=start ok=true handle=1 generation=1 pid=4242 \
  dns=sha256:<hex>:<payloadBytes> engine=sha256:<hex>:<payloadBytes> extras=sha256:<hex>:<payloadBytes>
rules identity: event=swap ok=true handle=1 generation=2 pid=4242 dns=… engine=… extras=…
rules identity: event=swap ok=false handle=1 generation=1 pid=4242 dns=… engine=… extras=… reason=engine:_<原因>
```

| 字段 | 含义 |
|---|---|
| `event` | `start` / `swap` |
| `ok` | 这次安装是否真的成功 |
| `handle` / `generation` | handle 与**单调**代次；`generation` 只在成功安装时前进 |
| `pid` | 写这行日志的进程（与 logcat 的 pid 列必须一致，不一致的行不被采信） |
| `dns` / `engine` / `extras` | 三个制品 payload 的 `sha256:<hex>:<字节数>`；没装上的写 `-` |
| `reason` | 仅 `ok=false`：加载器给出的原因，空白折成 `_` 以保持一 token 一字段 |

口径是 **payload 的 SHA-256**，不是整文件（envelope 还有 20 字节头），也不是大小/mtime。哈希取自
加载器**已经读进内存的那块 buffer**，因此不会出现「哈希的是文件、装进去的是另一版」；失败路径不产出
成功代次，也不会凭空补一个身份。三个分量分开报而不合并成一个 id：三份制品是同一次编译写的，但启动
和替换是逐个读的，读到两份新的、一份旧的时候引擎真的在跑混合规则，合并会把这件事藏起来。

日志只有哈希、计数、handle、generation——没有规则明文、没有 URL、没有密钥。

### 10.2 成本与所有权

| 项 | 实测（release profile，7.4 MB engine + 1.2 MB dns + 0.15 MB extras） |
|---|---|
| 每次启动/成功替换的身份计算 | 约 22 ms（`core/examples/rules_identity_cost.rs`） |
| 每请求 | **0**：请求路径不读、不哈希任何制品 |
| 保留的内存 | 每分量 79 字符 token + 计数（不是规则副本） |
| 依赖 | 无新增：用已有的 `ring::digest`（TLS/熵源已链接 `ring`）。`opt-level="z"`+LTO 下 `sha2` 约 60 MB/s，`ring` 约 300 MB/s |

旧的 `rules: …` / `rules reloaded: …` / `engine loaded in …` 行**保持不变**（工具与人工排障仍在读），
`rules identity:` 是新增的、可解析的观测，不是替换。制品格式与序列化没有改动，旧制品照常可加载。

### 10.3 谁在用

`scripts/effectiveness/pss_idle.sh`（详见 `docs/TESTING.md` §14.8e）：

- **就绪**：本次启动 pid 的**字段完整**的 `rules identity:` 行（logcat pid 列与行内 `pid=` 必须一致），
  最后一条 `ok=true`，其后无失败也无不可解析的身份行；
- **目标**：`--expect-identity` / `--expect-identity-from`（由 `pss_idle.sh --identity <compiledDir>`
  用同一口径从目标制品算出）。正式采样**必须**声明目标，否则 exit 2、不碰设备；
- **采样窗口**：每个样本前后与出中位数前各复核 pid/handle/generation/目标内容，任一变化整批作废、
  不出中位数；meminfo 返回块必须有唯一且匹配的 `MEMINFO in pid N [process]` 头。

因此这三条日志字段的稳定性和完备性是**对外契约**：`event`/`ok`/`handle`/`generation`/`pid`/
`dns`/`engine`/`extras` 任何一个缺失或改格式，都会让正式 PSS 采样无法进行（工具会明确拒绝，
而不是降级通过）。
