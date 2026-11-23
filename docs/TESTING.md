# 测试指南

本文档记录本地测试与 Pixel 5（Android 16）真机验证步骤。M0 内容保留；M1（订阅系统 + 规则预编译/热替换）
新增内容见第 1.1、2.1、6 节。CI 不参与（不使用 GitHub Actions），
结论一律以本地构建 + 真机运行输出为准。

- 设备：Pixel 5（redfin），Android 16 / API 36，`adb -s "$SERIAL"`
- 包名：`top.zztweb.zshield`
- 工具链：JDK 17（`$JAVA_HOME`）、Android SDK（`$ANDROID_SDK_ROOT`，或 `local.properties` 的
  `sdk.dir`）、NDK 版本见 `app/build.gradle.kts` 的 `ndkVersion`
- 设备选择：下文所有 `adb` 命令用 `$SERIAL` 占位；先 `SERIAL=<adb devices 显示的序列号>` 导入环境，
  未设置时 `scripts/` 下工具只在恰好一台设备在线时自动选用。仓库不记录具体设备地址。

> 脱敏说明：本文档记录的实测结果未改动；其中的设备序列号、开发机路径等本机环境值已替换为
> `$SERIAL` / 通用路径占位，测量条件（机型、系统版本、版本号、规则集、日期）保持原样。

## 1. Rust core 单元测试

```bash
cargo test --manifest-path core/Cargo.toml
cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings
```

覆盖内容（都是网络无关的纯逻辑，跑在 host 上）：

| 模块 | 覆盖点 |
|---|---|
| `dns::wire` | 报文解析、压缩指针（含向前指针与环）、CNAME 链展开、A/AAAA 应答构造、NXDOMAIN/REFUSED 应答、名字编码往返 |
| `dns::filter` | hosts 三种格式、`\|\|domain^` 子域命中与父域不误中、`\|domain^` 精确、`@@` 例外、`$important` 压过例外、`$badfilter`、注释空行、不支持规则计数、CNAME 反隐藏、大小写与结尾点 |
| `dns::cache` | TTL 上限、剩余 TTL 递减、过期回收、条目上限淘汰最接近过期项、空应答不缓存 |
| `dns::engine` | 拦截/缓存/上游全流程（用脚本化 resolver）、CNAME 反隐藏拦截、上游失败 → SERVFAIL 计数、垃圾输入不 panic、三种 blockResponse |
| `tun` | IPv4/IPv6 UDP 解析、非 UDP/分片/IP 选项被拒、回包 IPv4 头与 UDP 校验和（含伪首部）验证、地址族不匹配报错 |
| `config` | 默认值、完整字段往返、DoH 缺 bootstrap/https 校验、虚拟 DNS 地址族校验 |
| `jni_api` | 版本号、lastError、坏配置/坏 fd 的失败路径；`compile` 返回统计与错误 JSON；`reload` 换规则成功/失败保留旧规则/无句柄泄漏；`start` 优先用预编译产物、产物过期时回退规则文本、**`ipv6` 经 `start` 传到 DNS 引擎**（缺省为 `true`） |

### 1.1 M1 新增（`core/src/compile.rs`、`core/src/compiled.rs`、`core/src/dns/filter.rs`）

| 覆盖点 | 用例 |
|---|---|
| DNS 层规则选择 | `scope_modifiers_never_become_domain_blocks`（`$third-party` / 路径 / `$domain=` / `$script` 不进 DNS 层，`$important` 与 hosts 进）、`dns_layer_selection_matches_the_task_card` |
| 逐行分类 | `line_classification_is_stable`、`cosmetic_lines_are_recognised` |
| 产物序列化往返 | `dns_artifact_round_trip_preserves_every_verdict`（11 个域名的判定逐个比对）、`dns_payload_round_trip_keeps_every_rule_and_the_statistics`、`engine_artifact_deserializes_and_matches_the_dns_filter`（引擎反序列化后仍拦截） |
| 版本头 / 损坏 | `version_mismatch_is_rejected`、`wrong_magic_is_rejected`、`truncated_and_corrupted_payloads_are_rejected`、`dns_artifact_survives_a_corrupted_body_of_the_right_length`、`load_rejects_a_version_mismatched_artifact` |
| 跨列表 `$badfilter` | `badfilter_crosses_list_boundaries` |
| 放行名单压过列表规则 | `allowlist_beats_list_rules_in_the_compiled_artifact`（含 `$important`）、`user_allowlist_beats_every_list_rule` |
| `CompileStats` 计数 | `compile_stats_counts_every_class`（每类行数与合计逐项比对） |
| 原子写 | `artifacts_are_written_atomically` |
| CRC32 | `crc32_matches_known_vectors` |

## 2. Kotlin 单元测试

```bash
./gradlew :app:testDebugUnitTest
```

覆盖 `NativeConfig` / `NativeStats` 与 Rust 侧的 JSON 契约：字段名、`blockResponse` 的 snake_case
拼写、上游两种形态、往返一致性、stats 解析与畸形输入降级。

### 2.1 M1 新增（`app/src/test/java/top/zztweb/zshield/filters/`）

| 测试类 | 覆盖点 |
|---|---|
| `CatalogTest` | `catalog.json` 解析、字段完整性、**id 唯一**、非法 category/URL 拒绝、随包资产的必含条目与默认启用集、全部 URL 为 https |
| `ListMetadataTest` | `! Title:` / `! Version:` / `! Expires:` / `! Homepage:` 解析；`Expires` 的分钟/小时/天/周/裸数字/`12h`/`2d`/带括号说明等写法；头部扫描上限；非法值拒绝 |
| `ListPreprocessorTest` | `!#include` 同源判定（协议/主机/端口）、就地展开、**跨源拒绝且不发请求**、嵌套跨源也拒绝、失败跳过、深度与条数上限 |
| `ListSanityTest` | HTML 页面（含 BOM/前导空白/Content-Type）拒绝、过短拒绝、无规则行拒绝、规则行占比过低拒绝、二进制拒绝、大列表通过、抽样上限 |
| `ListUpdaterTest` | **304 不改文件、不触发重编译**、校验器回放、HTML 不覆盖旧副本、镜像全失败时逐条报告、失败主地址回退到镜像并记住可用 URL、200 但内容相同视为未变更、`! Expires:` 决定最小更新间隔、`force` 忽略间隔、30 MB 上限 |
| `FilterStateTest` | 状态 JSON 往返、错误字段持久化、间隔夹取、`withList`/`withoutList`、目录与持久状态的合并（默认启用、用户选择优先、已下架的内置条目被移除、用户列表保留）、原子写无残留 `.part`、损坏状态文件降级、列表 id 防路径穿越 |

> 注意：Android 的 `org.json` 桩在本地单测里会抛 `not mocked`，`app/build.gradle.kts` 因此给测试
> classpath 加了 `org.json:json`。

## 3. 构建

```bash
./scripts/build.sh debug      # 产物 dist/zshield-<versionName>-debug.apk
./scripts/build.sh release    # 产物 dist/zshield-<versionName>-release.apk，>10 MB 直接失败
./scripts/build.sh clean
```

脚本第一步就删除 `app/build/outputs/`、`dist/`、`app/src/main/jniLibs/**/*.so`，所以连续跑两次
`dist/` 里只会有一个当前版本的 release APK。

release 签名密钥在 `~/.config/zshield/release.jks`，不存在时脚本调用 `scripts/gen-keystore.sh`
生成（随机密码写入同目录 `keystore.properties`，权限 600，不入库）。

## 4. 真机验证（Pixel 5 / A16）

### 4.0 M1：订阅系统

首次启动（或 `pm clear` 后）App 会自动下载默认启用集并编译一次。观察：

```bash
adb -s "$SERIAL" logcat -c
adb -s "$SERIAL" shell am start -n top.zztweb.zshield/.debug.DebugActivity
adb -s "$SERIAL" logcat -d | grep -E "ZShield :|ZShieldCore"
# I ZShield : list adguard-base: updated from https://filters.adtidy.org/... (6502685 B, AdGuard Base filter + EasyList, expires=120h)
# ...
# I ZShieldCore: compile stage read+classify: 1164 ms
# I ZShieldCore: compile stage engine+serialize: 3189 ms
# I ZShieldCore: compiled 9 lists: 376901 dns rules ..., 4353 ms
```

调试页第三块显示列表数 / 启用数 / 规则数 / 编译耗时 / 两个产物大小。

- **周期更新**：默认 24 h，用平台 `JobScheduler`（`AutoUpdateScheduler.JOB_ID = 4201`，`setPersisted(true)`）。
  检查是否登记：`adb shell dumpsys jobscheduler | grep -A3 zshield`。
  手动触发一次：`adb shell cmd jobscheduler run -f top.zztweb.zshield 4201`。
- **条件请求**：第二次更新时列表若未变，logcat 出现 `list <id>: not modified`，且**不会**出现新的
  `compiled ... lists` 行（304 不触发重编译）。

### 4.0.1 热替换（不重启 VPN）

调试页有两个按钮（「加规则 ||RELOAD-TEST.EXAMPLE^」「清空自定义规则」），也可以用广播驱动（无需点屏幕）：

```bash
# 改用户规则：加一条
adb -s "$SERIAL" shell "am broadcast \
  -a top.zztweb.zshield.action.DEBUG_SET_RULES \
  -n top.zztweb.zshield/.filters.DebugCommandReceiver \
  --es rules '||example.org^'"

# 改放行名单（逗号分隔）
adb -s "$SERIAL" shell "am broadcast \
  -a top.zztweb.zshield.action.DEBUG_SET_ALLOWLIST \
  -n top.zztweb.zshield/.filters.DebugCommandReceiver \
  --es domains 'a.example,b.example'"

# 立即编译一次（跳过防抖）
adb -s "$SERIAL" shell "am broadcast \
  -a top.zztweb.zshield.action.DEBUG_COMPILE \
  -n top.zztweb.zshield/.filters.DebugCommandReceiver"
```

预期日志（实测 4.45 s 端到端）：

```
I ZShield : user rules changed, compile scheduled
I ZShieldCore: compiled 10 lists: ... 3109 ms
I ZShieldCore: rules reloaded: 376629 block, ...; 0 cache entries dropped
I ZShield : hot reload finished: ok=true
```

`ip addr show tun0` 的 MD5 前后一致（接口未重建），没有重新授权弹窗。

> **注意 `ping` 的假阴性**：Android 的 netd 会缓存 DNS 结果（含否定缓存），所以刚加规则后
> `ping <域名>` 可能仍返回旧地址或 `unknown host`。判断规则是否生效要用直接查询虚拟 DNS：
>
> ```bash
> python3 -c "
> def q(name,qid=0x1234):
>     out=bytes([qid>>8,qid&0xff,0x01,0x00,0,1,0,0,0,0,0,0])
>     for l in name.split('.'): out+=bytes([len(l)])+l.encode()
>     return out+b'\x00'+b'\x00\x01\x00\x01'
> import sys; open('/tmp/q.bin','wb').write(q(sys.argv[1]))" example.org
> adb -s "$SERIAL" push /tmp/q.bin /data/local/tmp/q.bin
> adb -s "$SERIAL" shell 'timeout 5 nc -u 10.111.222.2 53 < /data/local/tmp/q.bin | xxd | tail -2'
> # 被拦截：末尾 0004 0000 0000（A 记录 0.0.0.0）
> # 放行：正常应答（多个 A 记录 + OPT 记录）
> ```

### 4.1 安装与预授权

```bash
adb -s "$SERIAL" install -r dist/zshield-0.0.1-release.apk
adb -s "$SERIAL" shell appops set top.zztweb.zshield ACTIVATE_VPN allow
adb -s "$SERIAL" shell pm grant top.zztweb.zshield android.permission.POST_NOTIFICATIONS
adb -s "$SERIAL" logcat -c
adb -s "$SERIAL" shell am start -n top.zztweb.zshield/.debug.DebugActivity
```

### 4.2 开启过滤

调试页只有一个按钮：`开启过滤` / `关闭过滤`。首次开启会弹系统 VPN 授权对话框（`VpnService.prepare`），
点 OK。也可以用坐标点按钮（1080×1920 屏幕上按钮中心约 `540,162`）：

```bash
adb -s "$SERIAL" shell input tap 540 162
```

确认运行状态与规则加载：

```bash
adb -s "$SERIAL" logcat -d | grep ZShieldCore
# I ZShieldCore: rules: 1 files, 7 block, 1 exception, 0 unsupported
# I ZShieldCore: engine started, handle 1
```

确认 TUN 接口（仅 DNS 模式：只有两个虚拟 DNS 地址被路由）：

```bash
adb -s "$SERIAL" shell ip addr show tun0
# inet 10.111.222.1/30 ...  inet6 fd00:7a73::1/126
```

### 4.3 拦截与放行

```bash
# 应被拦截：解析为 0.0.0.0
adb -s "$SERIAL" shell ping -c 1 -W 2 doubleclick.net
adb -s "$SERIAL" shell ping -c 1 -W 2 googleadservices.com
adb -s "$SERIAL" shell ping -c 1 -W 2 zshield-block-test.com

# 应正常解析并可访问
adb -s "$SERIAL" shell ping -c 1 -W 3 www.baidu.com
adb -s "$SERIAL" shell ping -c 1 -W 3 github.com
```

`ping` 把 `0.0.0.0` 显示成 `127.0.0.1`（映射到本机回环），所以被拦截时看到
`PING doubleclick.net (127.0.0.1)` 且 `time=0.0x ms`，这是**预期结果**。

要看原始应答（验证 `0.0.0.0` 与 TTL），直接向虚拟 DNS 发一个原始查询：

```bash
# 生成查询报文（host 上）
python3 - <<'EOF'
def q(name, qtype=1, qid=0x1234):
    out = bytes([qid>>8, qid&0xff, 0x01,0x00, 0,1, 0,0, 0,0, 0,0])
    for l in name.split('.'):
        out += bytes([len(l)]) + l.encode()
    return out + b'\x00' + bytes([qtype>>8, qtype&0xff]) + b'\x00\x01'
open('/tmp/q.bin','wb').write(q('doubleclick.net'))
EOF
adb -s "$SERIAL" push /tmp/q.bin /data/local/tmp/q.bin
adb -s "$SERIAL" shell 'timeout 5 nc -u 10.111.222.2 53 < /data/local/tmp/q.bin | xxd'
# 期望：ANCOUNT=1，RDATA 为 00000000（0.0.0.0），TTL=1
```

### 4.4 计数与缓存

调试页第二第三行是 `statsJson` 的实时快照（有订阅者且屏幕亮时每 ≥1 s 拉一次）。也可以直接看
logcat 里上游是 DoH：

```bash
adb -s "$SERIAL" logcat -d | grep "upstream"
# I ZShieldCore: upstream doh:https://dns.alidns.com/dns-query answered in 42 ms
```

缓存验证：对同一名字连发两次原始查询，第二次的应答 TTL 小于第一次，且 `dnsCached` 增长。

### 4.5 关闭与恢复

```bash
adb -s "$SERIAL" shell input tap 540 162
```

关闭后应满足：调试页显示 `状态：已停止`；`dumpsys notification` 里没有本应用的常驻通知；
`ip addr show tun0` 报 `Device "tun0" does not exist`；之前被拦截的域名走回正常解析路径。

### 4.6 外部规则文件（可选）

app 专属外部目录 `files/rules/*.txt` 会被追加加载，用于推送临时规则。**debug 包**可直接写：
`run-as top.zztweb.zshield` 需要 `android:debuggable`，release 包不可用（这是预期的安全属性）。
release 包上验证外部规则请用 debug APK，或把规则加进 `app/src/main/assets/rules/`。

### 4.7 收尾

```bash
adb -s "$SERIAL" shell input tap 540 162      # 确保 VPN 已关闭
adb -s "$SERIAL" uninstall top.zztweb.zshield # 可选
adb -s "$SERIAL" shell rm -f /data/local/tmp/q*.bin /data/local/tmp/s*.bin
```

## 5. M1 已知限制（记录的边界，不是缺陷）

- **`engine.bin` 目前只编译不使用**：M1 完成了 adblock-rust 引擎的构建与序列化，但网络规则的实际查询要等
  M2 的完整隧道与 M3 的 HTTPS 过滤。默认启用集下它是 39.5 MB，本里程碑按任务卡要求产出并测量。
- **DNS 层只做整域拦截**：带作用域修饰的规则（`$third-party`、`$domain=`、路径、资源类型）一律不进 DNS 层，
  见 `docs/JNI.md` 第 4 节的规则选择表。它们的拦截效果要等引擎接入。
- **`ruleCount` 只统计 DNS 层规则**：UI 上单个列表的「规则数」是进入 DNS 过滤器的条数，不是列表总行数；
  引擎规则数由 `CompileStats.networkOnly` 单独给出。
- **编译一次约 3 s**：默认启用集在 Pixel 5 上 3.0–3.2 s，期间隧道继续用旧规则工作；这段时间内新增/删除的
  规则还没生效。
- **`!#include` 只支持同源**：跨源 include 被跳过并在列表状态里记原因。当前内置目录没有用到 include 的列表。

## 6. M0 已知限制（记录的边界，不是缺陷）

- 只处理发往虚拟 DNS 的 UDP 53；DNS over TCP、DoT 上游不在 M0 范围（M2/M1 补齐）。
- 不解析 IP 选项与分片包，遇到直接丢弃（仅 DNS 模式下不会有正常流量走到这里）。
- 无 EDNS(0)：转发时原样透传客户端的 OPT 记录，但合成应答不带 OPT。
- 负面应答（NXDOMAIN 等空应答）不缓存：负缓存规则容易出错，留到有实测数据后再做。
- 规则语法仅 M0 子集，URL 级规则、`$third-party` 等计数后忽略，M1 交给 adblock-rust。

## 7. M2a：完整隧道（用户态栈）

M2a 把 VPN 从「仅 DNS 模式」升级为完整隧道。新增的验证点都在第 7 节；第 1–6 节（M0/M1）
的内容继续有效。

### 7.1 单元测试新增覆盖

```bash
cargo test --manifest-path core/Cargo.toml        # 170 passed
cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings
./gradlew :app:testDebugUnitTest                  # 119 passed
```

| 模块 | 覆盖点 |
|---|---|
| `tun::packet` | IPv4/IPv6 TCP/UDP 解析与 TCP 标志位、分片/IP 选项/扩展头被拒、UDP/IP 包构造（IPv4 头校验和 + UDP 伪首部校验和逐字节验证，IPv6 同理）、TCP 校验和、地址族不匹配报错 |
| `tun::inspect` | ClientHello SNI 解析：普通、**GREASE 扩展与 GREASE 密码套件**、多扩展、**分片到两个 TCP 段**（`NeedMore` 给出所需字节数）、**无 SNI**、超大 hello 被拒；HTTP/1.x `Host` 解析、大小写、`host:port`、IPv6 字面量、头未收全时 `NeedMore`、`CONNECT` 无 Host、SSH/SMTP/二进制立即判定为 Unknown |
| `tun::policy` | **任意 IP:53 都劫持**（8.8.8.8 / 223.5.5.5 / IPv6 / 虚拟地址）、QUIC 仅在开关打开时丢弃、TCP/853 与 **DoH 主机名（含子域）** 仅在开关打开时拒绝、主机名列表解析（注释、hosts 列、大小写、结尾点、IP 字面量不误判） |
| `tun::nat` | 同一 5 元组复用一条流、空闲超时精确回收、应答刷新活跃时间、条目上限满时先回收再拒绝、`clear` 返回待关闭的 key |
| `tun::stack` | 空栈 `poll_delay()` 为 `None`（**空闲无定时器**，断言而非假设）、每端口只建一个 listener、连接数上限拒绝新 listener、环形缓冲读写往返、未干净结束的流在 Drop 时请求 RST、`StopFlag` 唤醒被 park 的循环且「先置位后等待」不会 park |
| `tun::forward` | QUIC/加密 DNS/域名拦截三类计数分开、SNI 命中 DNS 过滤器、**UDP 流复用同一 socket**、UDP 应答被转成回到隧道客户端的 IP 包、DNS over TCP 的 2 字节长度前缀 |
| `dns::ech` | **ECH 剥离**：移除 key 5 后报文可被重新解析、其他 SvcParam（alpn/port/ipv4hint）按序保留、target name 非根时正确跳过、无 ech 时原样返回、**authority 与 additional（OPT）记录保留**、长度字段越界的畸形 RDATA 不改写、空/垃圾输入不 panic；**`ipv6hint`（key 6）剥离**：只删 key 6、两个 key 可一次删完、无 `ipv6hint` 时逐字节不变、畸形 RDATA 不改写、key 号与 RFC 9460 一致 |
| `dns::engine` | ECH 剥离发生在**缓存之前**（缓存命中也不会复活 ech）、无 ech 的应答逐字节不变、缓存清理是查询路径上的惰性清理（第二次查询不会重复清理）；**`ipv6=false`**：AAAA 本地答 NODATA（rcode 0、答案数 0、question 原样回显、**不打上游**）、A 查询与缓存不受影响、HTTPS 应答去掉 `ipv6hint` 保留其余 SvcParam 且缓存里也是改后版本、`ipv6=true` 时 AAAA 与 `ipv6hint` 照旧、被规则拦截的 AAAA 仍走拦截应答而不是 NODATA |
| `config` | `mode` 往返与非法值拒绝、MTU/sniff/超时字段的范围校验、`ValidatedConfig::policy` 与配置一致、`ipv6` 缺省为 `true` 且能从配置读到 |
| **`tun::e2e_tests`** | **端到端**：用 `socketpair` 假冒 TUN fd，驱动真实的 smoltcp 栈完成三次握手（校验 SYN-ACK 的 ack 号）、双向数据（回环 echo 服务器，回程数据逐字节比对）与 FIN 关闭；另一条用例验证被策略拒绝的端口在握手前就回 RST |

Kotlin 侧新增 `AppSettingsTest`：默认值、原子写（无残留 `.part`）、重启后保留、**单一
`StateFlow`（写者与读者共享，防「UI 写了但服务读不到」）**、字段名契约、未知字段降级、非法包名
被丢弃、列表上限与排序、损坏文件回退并留档。

MYS-2710（仅 IPv4 网络）新增两组：

| 测试类 | 覆盖点 |
|---|---|
| `Ipv6AvailabilityTest` | **只有链路本地 `fe80::`（Pixel 5 的实测状态）→ 不可用**；有全局地址但没有 `::/0` → 不可用；有 `::/0` 但没有全局地址 → 不可用；两者都有 → 可用；**ULA `fd00::/8` / `fc00::/7` 不算全局地址**；`::`/`::1`/`ff00::/8`/`fec0::/10`/IPv4-mapped 不算；`%wlan0` 作用域后缀不影响判断；`prefixLength=1` 的同族路由不算默认路由；`LinkProperties` 为空或没有网络 → 保守判为不可用 |
| `UnderlyingNetworkMonitorTest` | 可用性变化时**防抖期满后重建一次**（2 s 前不重建）；**可用性不变时永不重建**（换 DNS、MTU 变化等链路属性变化）；防抖窗口内反复变化只重建一次；窗口内值又变回原值则取消重建；新隧道建立后取消为旧隧道排的重建；可用性来回翻转时每次变化各重建一次 |

`NativeConfigTest` 增加 `ipv6` 的渲染/解析/缺省值覆盖（键名 `ipv6`，缺省 `true`）。

### 7.2 测试浏览器

Pixel 5 出厂无浏览器。安装官方 Firefox（APK 直链，2026-11-08 校验）：

```bash
curl -sSLo firefox.apk \
  https://ftp.mozilla.org/pub/fenix/releases/138.0.3/android/fenix-138.0.3-android-arm64-v8a/fenix-138.0.3.multi.android-arm64-v8a.apk
sha256sum firefox.apk
# 2a45f9ab655c1c5b270d0f6a2ab653705e42a5e66148052011d6806568da77a3
adb -s "$SERIAL" install -r firefox.apk
```

包名 `org.mozilla.firefox`，测试后可保留。

### 7.3 真机验证（Pixel 5 / A16，full 模式）

```bash
adb -s "$SERIAL" install -r dist/zshield-0.0.3-release.apk
adb -s "$SERIAL" shell appops set top.zztweb.zshield ACTIVATE_VPN allow
adb -s "$SERIAL" shell pm grant top.zztweb.zshield android.permission.POST_NOTIFICATIONS
adb -s "$SERIAL" shell am start -n top.zztweb.zshield/.debug.DebugActivity
# 开启过滤（或走调试广播：见 7.4）
adb -s "$SERIAL" logcat -d | grep ZShieldCore
```

预期启动日志（实测）：

```
I ZShieldCore: encrypted-dns host list: 46 hosts from /data/user/0/top.zztweb.zshield/files/encrypted-dns-hosts.txt
I ZShieldCore: tunnel policy: mode full, mtu 1500, quic true, encrypted-dns true (46 hosts), timeouts tcp 7200s/udp 60s, sniff 4096B/3000ms
I ZShieldCore: tunnel stack up: mode Full, mtu 1500
```

系统侧确认是完整隧道（`0.0.0.0/0`；底层有 IPv6 时才同时有 `::/0`，见 7.5）：

```bash
adb shell dumpsys connectivity | grep -o 'Routes: \[.*\]' | head -1
# 底层有 IPv6：  Routes: [ 0.0.0.0/0 -> 0.0.0.0 tun0 mtu 0,::/0 -> :: tun0 mtu 0 ]
# 底层无 IPv6：  Routes: [ 0.0.0.0/0 -> 0.0.0.0 tun0 mtu 0 ]
```

| 验收项 | 命令 | 预期 |
|---|---|---|
| 百度正常 | Firefox 打开 `www.baidu.com` | 首页完整加载 |
| B 站首页 + 视频 ≥1 min | Firefox 打开 `www.bilibili.com`，点开一个视频播放 1 分钟 | 页面与视频正常，调试页「下行」持续增长 |
| GitHub 正常 | Firefox 打开 `github.com` | 首页完整加载 |
| 广告域名（DNS 过滤器中的 3 个）访问失败 | Firefox 打开 `pagead2.googlesyndication.com` 等 | 连接失败 |
| 硬编码 DNS 也被拦截 | `nc -u -w 4 8.8.8.8 53 < 查询报文` | 返回 A 记录 `0.0.0.0` |
| QUIC 丢弃计数增长且页面正常回退 | 浏览视频；看调试页 `QUIC 丢弃` | 计数 > 0，视频仍能播放（走 TCP/TLS） |
| DoH 主机被拒 | `curl https://dns.google/dns-query?name=example.com` | `Connection reset by peer` |
| DoT 被拒 | `nc -w 5 1.1.1.1 853` | 超时/被拒 |
| ECH 被剥离 | 查询 `crypto.cloudflare.com` 的 HTTPS 记录 | 应答里没有 key 5（`ech`）SvcParam |
| 按应用排除 | 把 Firefox 加入 `excludedApps` 后浏览 | 隧道累计 TCP / DNS 劫持计数**不增长**，页面仍正常 |
| full ↔ dns_only 切换 | 调试页「切换为仅 DNS 模式」 | 路由缩为两个虚拟 DNS 地址；DNS 拦截仍生效，其余流量绕过隧道 |

#### 7.3.1 硬编码 DNS 查询报文

```bash
python3 -c "
import sys
name, qid, qtype = sys.argv[1], int(sys.argv[2],16), int(sys.argv[3])
out=bytes([qid>>8,qid&0xff,0x01,0x00,0,1,0,0,0,0,0,0])
for l in name.split('.'): out+=bytes([len(l)])+l.encode()
open('/tmp/q.bin','wb').write(out+b'\x00'+qtype.to_bytes(2,'big')+b'\x00\x01')
" doubleclick.net 1234 1
adb push /tmp/q.bin /data/local/tmp/q.bin
adb shell 'timeout 6 nc -u -w 4 8.8.8.8 53 < /data/local/tmp/q.bin | xxd | tail -2'
# 被拦截：末尾 0000 0001 0004 0000 0000（TTL 1s + A 记录 0.0.0.0）
```

HTTPS 记录（`qtype=65`）用同一脚本，看应答里 `003a`（RDATA 长度）之后是否还出现 key `0005`。

### 7.4 调试广播（不依赖屏幕坐标）

```bash
# 开/关隧道（脚本化性能对比用）
adb shell am broadcast -a top.zztweb.zshield.action.DEBUG_TOGGLE_VPN \
  -n top.zztweb.zshield/.filters.DebugCommandReceiver
```

调试页另有三个按钮：切换 full/dns_only、把 Firefox 加入/移出 `excludedApps`、以及 M1 的
规则热替换。这个界面在 `debug/**`，正式 UI 由技术负责人实现。

#### 7.4.1 新装的包上广播"不生效"（MYS-2716 §6）

**现象**：全新安装后直接发 `DEBUG_TOGGLE_VPN`，偶发没有任何效果。

**原因**（Pixel 5 / A16 实测，logcat 原文）：

```
E ActivityManager: Background started FGS: Disallowed [callingPackage: top.zztweb.zshield;
    uidState: TRNB; ... intent: Intent { act=top.zztweb.zshield.action.DEBUG_TOGGLE ...}; code:DENIED]
W ActivityManager: startForegroundService() not allowed due to mAllowStartForeground false
E AndroidRuntime: FATAL EXCEPTION: DefaultDispatcher-worker-1
E AndroidRuntime: android.app.ForegroundServiceStartNotAllowedException: startForegroundService() not allowed
```

两件事叠在一起：

1. 后台启动前台服务需要 `ACTIVATE_VPN` app-op —— 也就是**用户至少授权过一次 VPN 同意框**
   （`VpnService.prepare` 返回 `null`）。全新安装、且从未打开过 App 时它还不存在，平台直接拒绝。
   旧实现从广播接收方的协程里直接调 `startForegroundService`，异常逃出协程 → 进程崩溃 →
   隧道当然没起来，而现场只有一条 `result=0`（广播本身确实送达了）。
2. 旧实现绕过了 `VpnService.prepare` 检查，所以即使服务起来了，`establish()` 也会以权限错误失败，
   报错位置离真正的原因很远。

**现在的行为**：广播走 `ZShieldVpnController.start()` / `stop()`，和通知、UI 完全同一条路径：
先查 `VpnService.prepare`，`startForegroundService` 的异常被捕获成 `VpnState.Error`（附
「首次使用需先打开一次应用授予 VPN 权限」提示），不再崩进程，并打印一行
`I ZShield : debug toggle -> <状态>`。

**正确用法**（脚本化测试按这个顺序，5 次连续开关都稳定）：

```bash
# 0. 装包后先打开一次应用并同意 VPN 授权框（或者在测试机上预授权）：
adb shell appops set top.zztweb.zshield ACTIVATE_VPN allow

# 1. 之后广播即可稳定开关；每次连续 5 次
for i in 1 2 3 4 5; do
  adb shell am broadcast -a top.zztweb.zshield.action.DEBUG_TOGGLE_VPN \
    -n top.zztweb.zshield/.filters.DebugCommandReceiver >/dev/null
  sleep 4
  adb shell "ip link show tun0 >/dev/null 2>&1 && echo UP || echo DOWN"
  adb logcat -d | grep "debug toggle ->" | tail -1
done
```

`appops ... ACTIVATE_VPN allow` 就是 `VpnService.prepare` 授权后平台记录的那条 app-op；等价于在界面上
点一次「开启」并同意系统弹窗。注意 `appops set ... default` 会把它撤掉，此时广播只会得到
`VpnState.Error`（不崩溃，但隧道不会起来）——这是**预期**行为，且日志会说清楚原因。

回归测试：`ZShieldVpnControllerTest.the_debug_toggle_treats_a_running_tunnel_as_stop_and_a_stopped_one_as_start`、
`a_failed_start_is_reported_as_an_error_state`。

### 7.5 仅 IPv4 网络下的隧道（MYS-2710）

底层链路没有 IPv6 时（国内常见的只有 IPv4 的 Wi-Fi），隧道不提供 IPv6：没有 `fd00:7a73::1`、
没有 `::/0`、没有 IPv6 DNS，core 也不返回 AAAA（`docs/JNI.md` 的 `ipv6` 一节）。验收步骤：

```bash
# 0. 先确认底层真的没有 IPv6：只有链路本地地址、没有 IPv6 默认路由
adb -s "$SERIAL" shell 'ip -6 addr show wlan0; echo ---; ip -6 route'
# 20: wlan0: ... inet6 fe80::24c2:9cd7:bbf:ce99/64 scope link
# --- （无 ::/0）

# 1. 开启过滤（full 模式），确认日志里的判断结果
adb -s "$SERIAL" logcat -c
adb -s "$SERIAL" shell am broadcast -a top.zztweb.zshield.action.DEBUG_TOGGLE_VPN \
  -n top.zztweb.zshield/.filters.DebugCommandReceiver
adb -s "$SERIAL" logcat -d | grep "underlying network IPv6"
# I ZShield : underlying network IPv6: false (tunnel does not carry IPv6)

# 2. 隧道里没有 IPv6 地址，路由里也没有 ::/0
adb -s "$SERIAL" shell ip -6 addr show tun0     # 没有 inet6 行
adb -s "$SERIAL" shell dumpsys connectivity | grep -o 'Routes: \[.*\]' | head -1
# Routes: [ 0.0.0.0/0 -> 0.0.0.0 tun0 mtu 0 ]   （没有 ::/0）

# 3. 双栈站点不加 -4 也能打开（修复前这里退出码 35）
adb -s "$SERIAL" shell \
  'curl -s -o /dev/null -w "%{http_code}\n" https://www.baidu.com/'
adb -s "$SERIAL" shell \
  'curl -s -o /dev/null -w "%{http_code}\n" https://www.bilibili.com/'
# 200 / 200

# 4. 并发 40 路，连跑 3 轮
for round in 1 2 3; do
  adb -s "$SERIAL" shell \
    'for i in $(seq 40); do curl -s -o /dev/null -w "%{http_code}\n" https://www.baidu.com/ & done; wait' \
    | sort | uniq -c
done
# 每轮 40 个 200

# 5. AAAA 查询在本地就被答成 NODATA（答案数 0）
python3 -c "
out=bytes([0x27,0x10,0x01,0x00,0,1,0,0,0,0,0,0])
for l in 'www.baidu.com'.split('.'): out+=bytes([len(l)])+l.encode()
open('/tmp/q6.bin','wb').write(out+b'\x00'+b'\x00\x1c\x00\x01')"
adb -s "$SERIAL" push /tmp/q6.bin /data/local/tmp/q6.bin
adb -s "$SERIAL" shell 'timeout 5 nc -u 10.111.222.2 53 < /data/local/tmp/q6.bin | xxd | head -2'
# 头部 ancount=0000，后面只有原样回显的 question

# 6. 拦截仍然生效（dns_only 模式同样验证一遍）
adb -s "$SERIAL" shell 'ping -c 1 -W 2 doubleclick.net'
# PING doubleclick.net (127.0.0.1) —— 0.0.0.0 被映射到回环，即被拦截
```

底层网络**有** IPv6 时行为必须与 M2a 一致（隧道有 `fd00:7a73::1` 与 `::/0`，AAAA 正常返回）。
切换网络（Wi-Fi ↔ 移动数据）后 `logcat | grep "underlying network IPv6"` 应出现新的判断行，
且**仅当结果变化时**隧道才重建（`logcat | grep "engine started"` 会再出现一次）。

### 7.6 已知限制（记录，不是缺陷）

- **ICMP（ping）不支持**：`ping 8.8.8.8` 在隧道里 100% 丢包。ICMP 不在用户态栈的转发路径上，
  且任务卡明确允许不支持。需要连通性诊断时用 TCP/UDP（`curl`、`nc`）。
- **分片包被丢弃**：IPv4 分片与 IPv6 扩展头不解析，直接丢。TCP 会重传，UDP 由发送方自行回退。
- **UDP 无端口映射保活**：UDP 流 60 s 无流量即回收，长连接的 UDP 应用需要自己保活。
- **DNS over TCP 已支持**（2 字节长度前缀），但一个连接内串行处理。
- 关闭系统 Wi-Fi（`svc wifi disable`）会同时断开手机上的 adb-over-Wi-Fi；远程测试时不要用这个
  命令，改用飞行模式或直接断开被测应用的网络。

## 8. M2b：HTTP 请求过滤管线

M2b 在 M2a 的首包嗅探之后接入明文 HTTP 过滤：逐个请求判定、命中即回合成响应，服务器方向仍逐字节直通。
第 1–7 节（M0/M1/M2a）保持不变。

### 8.1 单元测试新增覆盖（`core/src/http/`）

```bash
cargo test --manifest-path core/Cargo.toml
cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings
```

| 覆盖点 | 用例 |
|---|---|
| 请求头解析：基本字段、默认端口剥离、absolute-form、`OPTIONS *`、`CONNECT` | `parses_a_minimal_request`、`the_default_port_is_not_part_of_the_matched_url`、`absolute_form_targets_are_used_as_sent`、`options_star_and_lowercase_methods_are_accepted`、`connect_and_upgrade_are_flagged_for_the_relay` |
| **分片请求头**（每个前缀都必须 `Incomplete`） | `a_head_split_across_segments_parses_once_complete`（在 1..len 每个位置切）、`one_byte_at_a_time_still_parses` |
| **超长头拒绝** | `an_oversized_head_is_rejected_instead_of_buffered`（无终止符 / 有终止符两种都拒） |
| 非 HTTP / 上游升级 | `non_http_first_bytes_are_reported_as_such`（h2c 前言、TLS、SSH、二进制） |
| body 分帧与请求走私形态 | `body_framing_is_read_faithfully`（`Content-Length` + `Transfer-Encoding` 并存、长度重复都拒） |
| chunked 扫描器 | `chunked_framing_is_scanned_incrementally`、`chunked_split_across_reads_is_still_tracked`（每个位置切）、`chunk_extensions_and_trailers_are_tolerated`、`broken_chunk_framing_is_reported_not_guessed` |
| **资源类型推断表** | `the_fetch_dest_table_is_complete`（18 个 `Sec-Fetch-Dest` 值）、`the_accept_fallback_table_is_ordered_by_specificity`、`fetch_dest_wins_over_accept`、`no_hint_at_all_is_other_not_a_guess`、`wire_spellings_match_adblock` |
| **`$third-party` / `$script` / `$domain=` 在有/无 Referer 时的判定** | `third_party_rules_need_a_source_and_do_not_fire_without_one`、`a_domain_scoped_rule_needs_a_matching_referer`、`a_script_rule_blocks_a_matching_request`、`request_types_come_from_the_request_not_the_url` |
| `@@` 与 `$important` | `exceptions_cancel_a_block_and_are_reported`、`important_beats_an_exception`、`rule_text_is_reported_only_when_the_engine_carries_it` |
| **redirect 资源返回** | `redirect_resources_are_served_from_the_builtin_set`（noopjs / 1x1.gif 的真实字节）、`an_unknown_redirect_resource_falls_back_to_a_plain_block`、`a_redirect_rule_alone_does_not_block`、`every_builtin_decodes_and_has_the_expected_signature` |
| **日志环形缓冲** | `ids_are_monotonic_and_since_filters_by_them`、`the_ring_wraps_and_keeps_the_newest_entries`、`a_wrapped_buffer_still_answers_since_correctly`、`long_urls_are_truncated_and_flagged`、`truncation_never_splits_a_multibyte_character`、`to_json_is_a_flat_array_with_the_documented_field_names` |
| 引擎加载与热替换 | `a_compiled_engine_is_loaded_and_blocks`、`a_corrupt_artifact_is_an_error_not_a_panic`、`a_payload_that_is_not_an_engine_is_rejected`、`reload_replaces_the_rules_of_a_live_handle`、`a_failed_reload_keeps_the_old_rules` |
| 继电器端到端（`http/e2e_tests.rs`，双 `duplex` 流） | 被拦请求不到服务器、允许请求**逐字节**到达、keep-alive 逐请求判定、分片头、非 HTTP/升级退化、超大头条目直通、chunked body、`$important`/`$third-party` 实链路、热替换、**共享计数器在连接异常断开时仍正确** |
| 被拦 + 有 body / `Expect: 100-continue` → `Connection: close`；无 body 的 GET 保持连接 | `a_blocked_request_with_a_body_closes_instead_of_desyncing_the_connection`、`an_expect_continue_block_closes_the_connection`、`a_blocked_get_without_a_body_keeps_the_connection_open` |
| 被拦请求的 body（含 chunked）一个字节都不到服务器 | `a_blocked_request_with_a_chunked_body_never_leaks_a_byte`、`a_blocked_chunked_upload_closes_instead_of_desyncing_the_connection` |
| 允许的 chunked body 帧损坏时，断点前的字节不被丢弃 | `an_unparseable_allowed_chunked_body_is_forwarded_up_to_the_break` |
| 管线化：前一个响应未结束时，后一个被拦请求不插队 | `a_pipelined_block_after_an_unanswered_request_degrades_instead_of_splicing` |
| `http: Some(..)` 下的服务端先说话 | `a_server_first_greeting_is_not_delayed_when_http_filtering_is_on`（`tun/e2e_tests.rs`） |
| chunk 扩展任意长度合法、死循环 size 行仍被拒 | `a_long_chunk_extension_is_legal`、`an_endless_size_line_is_still_rejected`（`http/body.rs`） |
| `Content-Length` 只接受纯十进制；重复且相同合法、不同则拒 | `content_length_must_be_plain_decimal`、`body_framing_is_read_faithfully` |
| 非 HTTP 版本在第一个换行处就判定 | `a_non_http_version_is_rejected_at_the_first_newline` |
| `Expect` 识别与「何时必须关闭」 | `expect_continue_is_recognised`、`only_requests_with_bodies_or_expect_must_close_when_answered` |

### 8.2 Kotlin 单元测试新增覆盖

| 测试类 | 覆盖点 |
|---|---|
| `RequestLogEntryTest` | `recentRequestsJson` 的字段名、三种 `kind`（`dns`/`connection`/`http`）与「缺失按 http」降级、五种 outcome 拼写、`atMs`→`timeMs` 兼容、未知 kind/outcome 降级、畸形 JSON 返回空列表、容量与 URL 上限与 core 一致、顺序稳定（最新 id 即游标） |
| `FilterRepositoryDownloadTest` | **启用/添加即下载**（MYS-2742）：启用无内容列表后下载并编译出规则数、添加订阅同理会下载、重复添加不重复下载、连续启用 3 个列表只下载一轮、下载失败时列表带错误、已有内容不被重新下载、关闭列表不触发下载 |
| `NativeConfigTest` | `httpHeadBytes` 的 key 与默认值、往返；`statsJson` 的 `httpRequests`/`httpBlocked`/`httpRedirected`/`httpDegraded`/`httpEngineLoaded`/`requestLogSize` 解析；**缺少引擎时必须报 `httpEngineLoaded=false`** |

### 8.3 真机验证（Pixel 5 / A16，full 模式）

前置：设备与构建机同网段，构建机起一个临时 HTTP 服务（`python3 -m http.server <port>`），页面里放
「应放行」与「应拦截」两类资源。规则用调试广播下发，避免依赖屏幕坐标：

```bash
adb -s "$SERIAL" push /tmp/rules.txt /sdcard/rules.txt
adb -s "$SERIAL" shell "am broadcast \
  -a top.zztweb.zshield.action.DEBUG_SET_RULES \
  -n top.zztweb.zshield/.filters.DebugCommandReceiver \
  --es rules \"\$(cat /sdcard/rules.txt)\""
adb -s "$SERIAL" logcat -d | grep -E "rules reloaded|http blocked"
```

实测结果（v0.0.4）：

| 项 | 命令 / 操作 | 结果 |
|---|---|---|
| 引擎运行时加载 | 启动 VPN，看 logcat | `engine loaded in 204–393 ms, 41407497 B (11 redirect resources)` ✅ |
| 热替换同时换两套规则 | 改规则广播 | `rules reloaded: ... engine 41407485 B`，隧道未重建 ✅ |
| 子资源拦截（`$script`） | `curl -H 'Sec-Fetch-Dest: script' .../app.js` | `204`，日志 `http blocked GET .../app.js (script)` ✅ |
| 子资源拦截（`$image`） | `curl -H 'Sec-Fetch-Dest: image' .../logo.gif` | `204` ✅ |
| 类型不匹配不误伤 | 同一 URL 用 `Sec-Fetch-Dest: empty` | `200`，80 B 原样返回 ✅ |
| 导航拦截 | `curl -H 'Sec-Fetch-Dest: document'`，规则带 `$document` | `403` + 内联页面（413 B，无外链），`Cache-Control: no-store` ✅ |
| 完整 URL 规则（DNS 层做不到） | `\|http://host/pathonly-ad.js\|` | `204` ✅ |
| **真实浏览器** | Firefox 打开测试页 | 页面正常渲染，页面内自报 `local=true ad=false`：正常脚本加载、广告脚本被拦 ✅ |
| 计数器与日志 | 调试页 | `HTTP 请求 5 ｜ 拦截 2 ｜ 引擎 已加载 ｜ 日志 5 条`；点「最近请求」列出 ALLOWED/BLOCKED 逐条 ✅ |
| PSS（`debugRules` 关，默认） | `dumpsys meminfo`，浏览器在前台 | **112 MB**，≤ 150 MB ✅（浏览器退到后台时调试页自身占 35 MB 图形内存，读数会到 134 MB，不是本进程的过滤开销） |
| PSS（`debugRules` 开） | 同上 | 184.4 MB，**超预算**——所以默认关，见 `docs/PERF.md` §11.3 |
| `Expect: 100-continue` 的被拦请求 | `curl -H 'Expect: 100-continue' -X POST` | `204` + `Connection: close` ✅ |
| 允许的 chunked 上传 | `curl -X POST --data-binary ... -H 'Transfer-Encoding: chunked'` | 服务器收到（Python `http.server` 对 POST 回 501，说明请求体完整到达）✅ |

收尾：`kill` 临时 HTTP 服务、删除 `/sdcard/rules*.txt`、`svc power stayon false`、关掉调试页。

### 8.4 已知边界（记录，不是缺陷）

- **明文 HTTP 规则默认不作用于顶层导航**（`document`）。这与 uBO / AdGuard 一致：`$document` 必须显式写，
  否则一条路径规则会把整个站点变成 403。实测 `|http://host/x.js|` 对 `Sec-Fetch-Dest: document` 不命中，
  加 `$document` 后命中。
- **`||<IP 字面量>:<端口>/<路径>` 形式不被 adblock-rust 命中**（同一 URL 的 `|<完整 URL>|` 与
  `||<IP>^$script` 都正常）。这是上游解析器对 IP 字面量 + 端口的处理，与本站管线无关；真实列表用的是
  域名，不受影响。用 IP 做测试时请改用完整 URL 形式。
- `Upgrade` / `CONNECT` / h2c 连接从握手起不再过滤（计入 `httpDegraded`）。

## 9. M3a：HTTPS 过滤（根证书 + TLS 解密 H1/H2）

### 9.1 单元测试新增覆盖（`core/src/https/`）

```bash
cargo test --manifest-path core/Cargo.toml
# test result: ok. 400 passed; 0 failed
cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings
```

| 测试 | 覆盖的任务卡条款 |
|---|---|
| `ca::tests::a_generated_ca_has_the_fields_the_task_card_fixes` | ECDSA P-256、`CA:true` + `pathlen:0`、`keyCertSign`+`cRLSign`、`CN = ZShield Personal CA <8 hex>` + `O = ZShield`、10 年、根不带 EKU、指纹 = DER 的 SHA-256 |
| `ca::tests::two_generated_root_cas_are_different` | 「随机根证书」：两次生成不复用密钥/名字 |
| `ca::tests::a_loaded_ca_issues_leaves_under_the_same_root` | 叶子由该根签发、SAN = SNI、非 CA、`serverAuth`、回溯 1 h / 90 天 |
| `ca::tests::leaves_are_cached_per_host_and_reused` + `the_leaf_cache_is_bounded_and_evicts` | LRU 命中与 512 条上限 |
| `ca::tests::loading_a_different_root_drops_every_cached_leaf` | `loadCa` 换根后清空叶子缓存 |
| `ca::tests::a_non_ca_certificate_is_refused` / `unusable_host_names_are_refused` / `the_key_is_never_printed` | 输入校验；私钥不出现在 `Debug` |
| `policy::tests::*` | 8 条解密判定的每一条（关闭、非 443、无 SNI、排除域名含子域、未知归属、自动放行、未选中、正常解密），以及「本地检查排在 Binder 查询之前」「auto-bypass 24 h 过期」「表有上限」「uid 缓存命中/失效/上限」 |
| `modifiers::tests::*` | `$removeheader` 选项剥离与按 header 名分组、`$domain=`/内容类型/`@@` 语义、空值与无模式规则的拒绝、`$csp` 与 `$removeparam` 经引擎 |
| `rewrite::tests::*` | 请求行改写只动目标、头删除不区分大小写、`$csp` 与已有策略**合并而非替换**、302 的 Location 防注入（CR/LF 百分号编码）、跨站改写被识别 |
| `head::tests::the_scheme_decides_the_matched_url` 等 3 个 | 解密连接的 URL 是 `https://`、默认端口随 scheme、绝对形式 target 以传输层为准 |
| `mitm::e2e_tests::*`（12 个） | 见 9.2 |

### 9.2 端到端测试（本机回环，真实 TLS 两端）

`core/src/https/https_e2e.rs`：脚本化源站 + 真实 MITM 中继 + 真实 TLS 客户端，没有设备也没有网络。
唯一非生产代码是**上游信任**的注入：测试源站由测试自己的根签发，所以上游校验器拿到那个根而不是系统
信任库（`tls::client_config_with_roots`，只在 `#[cfg(test)]` 下存在）。生产代码没有任何放宽上游校验
的入口——这是本里程碑的硬性验收条款。

| 用例 | 断言 |
|---|---|
| `a_decrypted_http11_request_is_filtered_on_its_full_url` | 放行请求逐字节到达源站；同一连接上路径匹配的请求被本地回答 `204`；日志里有该条 |
| `a_document_request_gets_the_blocked_page` | `document` 得到 `403` + 内联页面；源站只看到 TLS 腿、没收到请求 |
| `an_h2_connection_is_decided_per_stream` | 一条 h2 连接上 3 个 stream：1 个被拦（204）、2 个转发（各自拿到源站正文）；`h2Streams=3`、`h2Blocked=1` |
| `an_invalid_upstream_certificate_passes_the_client_through` | 上游校验失败 → 重放 ClientHello；**客户端拿到的证书字节等于源站自己的叶子**；`httpsUpstreamInvalid=1`、`httpsIntercepted=0` |
| `a_client_that_rejects_our_leaf_is_auto_bypassed` | 第一次握手被客户端拒绝 → `ClientRejected` + 进放行表；第二次直通，客户端与源站握手成功 |
| `a_client_offering_no_alpn_is_served_http11` | 无 ALPN → 两端都 HTTP/1.1 |
| `the_leaf_is_issued_for_the_sni_it_was_asked_for` | 叶子 SAN = SNI、链 = 叶子 + 根、缓存 1 条 |
| `a_rewritten_url_is_forwarded_in_place_for_a_subresource` | `$removeparam` 改写后的 target 出现在源站收到的请求行里 |
| `a_csp_and_removed_response_header_reach_the_client` | `$csp` 出现在响应头、`$removeheader` 指定的头消失 |
| `a_redirect_substitute_is_served_on_the_decrypted_connection` | `$redirect` 返回 `200` + `application/javascript` |
| `an_origin_that_does_not_speak_h2_is_not_spliced_into_an_h2_client` | 客户端 h2 / 源站 http1.1 → 连接失败而不是畸形数据 |
| `the_alpn_of_a_hello_decides_the_relay` | ALPN 解析与上游交集 |

### 9.3 Kotlin 单元测试

```bash
./gradlew :app:testDebugUnitTest
# 151 tests completed, 0 failed
```

| 测试 | 覆盖 |
|---|---|
| `https/CertManagerTest` | 导出文件名 `ZShield-CA-<指纹前 8>.crt`、指纹 = DER 的 SHA-256（小写 hex）、`CaState` 三字段与 `copy(installed=)`、PEM 解析与垃圾输入、到期日格式 |
| `https/HttpsAppsTest` | 浏览器名单解析（注释、行尾注释、去重、非法包名丢弃）、真实 `assets/https/browsers.txt` 全部合法且含三个主流浏览器、**manifest 声明 `QUERY_ALL_PACKAGES`**（这条是设备测试发现 bug 后补的） |
| `https/BypassEntryTest` | `httpsBypassJson` 数组解析、空/截断/缺字段 |
| `settings/AppSettingsTest` | HTTPS 三项默认关闭、持久化往返、**v1 文档仍可读且 HTTPS 关闭**、包名与域名清洗、500 条上限 |
| `core/NativeConfigTest` | `httpsFiltering`/`httpsUids`/`httpsExcludedHosts`/文件路径的往返与 wire 名、`NativeStats` 的 9 个 HTTPS 计数（含缺字段时全零） |

### 9.4 真机验证（Pixel 5 / A16，full 模式）

前置：设备已装 `Firefox`（不信任用户 CA）与 `Cromite`（Chromium 分支，系统信任库）。

```bash
# 0. 安装用户 CA 需要锁屏口令（Android 11+ 无法静默安装）
#    自己挑一个只用于测试设备的凭据，通过环境变量传入；仓库里没有默认值：
export ZSHIELD_TEST_PIN='<你自己的测试凭据>'
adb shell locksettings set-pin "$ZSHIELD_TEST_PIN"   # 测试后必须按同样方式清除
./scripts/build.sh release
adb install -r dist/zshield-0.0.6-release.apk

# 1. 生成根证书
#    调试页「生成根证书」→ 日志：
#    I ZShieldCore: generated root CA 1b9ed15b2bd8ce204299fb49efff914cf6510bd1095fcdc370d1aba88dbaebfb (valid until 2109778575000)
#    I ZShield : root CA generated: Ready(fingerprintSha256=1b9ed15b…, notAfterMs=…, installed=false)

# 2. 导出到「下载」
#    I ZShield: root CA exported to content://media/external/downloads/…
adb shell ls -l /sdcard/Download/
# -rwxrwx--- 1 u0_a219 media_rw 652 2026-11-09 01:36 ZShield-CA-1b9ed15b.crt

# 3. 通过系统设置安装（不能用 am start 直接装，必须走 UI）
#    设置 → 安全与隐私 → 更多安全与隐私 → 加密与凭据 → 安装证书 → CA 证书
#    → 「仍然安装」→ 输入 PIN → 选择 ZShield-CA-*.crt → Select
#    回到应用，调试页显示：
#    根证书：指纹 1b9ed15b… ｜ 到期 2036-11-09 ｜ 已安装：是
```

> **`am start` 装不了**：直接 `am start -a VIEW -d file:///…crt` 会让 CertInstaller 拿到
> `EACCES`（`/sdcard/Download` 对它是不可读的）或者干脆只显示类型选择页。必须走上面那条 Settings 路径，
> 由 DocumentsUI 把文件作为 `content://` 交给 CertInstaller。

```bash
# 4. 开启 HTTPS 过滤并启动隧道
#    调试页「开启 HTTPS 过滤」→「开启过滤」→ 接受 VPN 授权
#    I ZShieldCore: https filtering on: ca 1b9ed15b…, 2 selected uids, 112 excluded hosts
#    2 uids = Firefox(10244) + Cromite
```

**为什么需要修 `QUERY_ALL_PACKAGES`**：没有它时同样的日志是 `0 selected uids`，而且每一行都是
`https: package org.mozilla.firefox is not installed, skipping` —— Android 11+ 的包可见性让
`getPackageUid` 对任意包直接抛 `NameNotFoundException`。这个 bug 在单测里看不出来（单测只测转换逻辑），
所以现在有一条断言 manifest 的用例守着它。

```bash
# 5. 浏览器访问正常
#    Firefox 打开 https://www.baidu.com / https://www.bilibili.com：页面正常
#    I ZShieldCore: https client for i2.hdslb.com (uid 10244) rejected the certificate (client_unknown_ca): auto-bypassed for 24 h
#    D ZShieldCore: https passthrough i2.hdslb.com (AutoBypassed, uid Some(10244))
#    —— 现代 Firefox 没有「使用第三方 CA」开关，一律拒绝用户 CA；自动放行把它兜住，站点照常打开。
```

```bash
# 6. 解密连接上的路径级规则（DNS 层做不到）
adb shell am broadcast -a top.zztweb.zshield.action.DEBUG_SET_RULES \
  -n top.zztweb.zshield/.filters.DebugCommandReceiver --es rules '||www.baidu.com/img/'
# 把 shell uid 临时加入解密名单，并用导出的 CA 校验
adb shell am broadcast -a top.zztweb.zshield.action.DEBUG_HTTPS_UIDS \
  -n top.zztweb.zshield/.filters.DebugCommandReceiver --es uids '2000,10244'
adb shell am broadcast -a top.zztweb.zshield.action.DEBUG_CLEAR_BYPASS \
  -n top.zztweb.zshield/.filters.DebugCommandReceiver

CA=/sdcard/Download/ZShield-CA-*.crt
adb shell "curl -s -o /dev/null -w '%{http_code}\n' --max-time 25 --cacert $CA \
  'https://www.baidu.com/img/PCtm_d9c8750bed0b3c7d089fa7d55720d6cf.png'"   # 204
adb shell "curl -s -o /dev/null -w '%{http_code}\n' --max-time 25 --cacert $CA \
  https://www.baidu.com"                                                     # 200
# I ZShieldCore: http blocked GET https://www.baidu.com/img/PCtm_….png (other)
# 调试页：HTTPS ｜ 解密 3 ｜ 直通 0 ｜ 自动放行 0 ｜ 上游证书无效 0 ｜ 握手失败 0
```

> 这条路径第一次跑出来是 **200 而不是 204**：解密腿把 URL 拼成了 `http://…`，路径规则全失配。
> 修复见 `docs/JNI.md` §7.8 与提交 `fix(m3a): 解密连接的 URL 用 https`。HTTP/1.1 与 h2 共用同一套
> 判定，所以两种协议此前都会踩到。

```bash
# 7. 非浏览器应用不被解密
adb shell "curl -s -o /dev/null -w '%{http_code}\n' --max-time 20 https://www.baidu.com"   # 200
# D ZShieldCore: https passthrough www.baidu.com (AppNotSelected, uid Some(2000))
# （shell uid 已从名单里去掉时）

# 8. 证书钉扎 / 不信任用户 CA 的应用 → 自动放行，第二次请求成功
adb shell "curl -s -o /dev/null -w '%{http_code}\n' --max-time 20 https://www.baidu.com"
# I ZShieldCore: https client for www.baidu.com (uid 2000) rejected the certificate (client_unknown_ca): auto-bypassed for 24 h
adb shell "curl -s -o /dev/null -w '%{http_code}\n' --max-time 20 https://www.baidu.com"   # 200
# D ZShieldCore: https passthrough www.baidu.com (AutoBypassed, uid Some(2000))

# 9. 性能数据见 docs/PERF.md §12
adb shell "dumpsys meminfo top.zztweb.zshield | grep 'TOTAL PSS'"   # 空闲 137 MB / 20 并发 154 MB
```

### 9.4b HTTP/2 在真机上怎么测（M3a 返工时补）

设备上唯一「接受用户 CA 且会走 h2」的客户端是系统浏览器 **`org.lineageos.jelly`**
（uid 10146）。Cromite 也接受用户 CA，但它的流量在本机只落到 http/1.1；`/system/bin/curl` 编译时没有
http2，`Protocols` 里根本没有 `h2`，所以不能用它测 h2。

```bash
# 1. 只选 jelly，让它的连接被解密
adb shell am broadcast -a top.zztweb.zshield.action.DEBUG_HTTPS_UIDS \
  -n top.zztweb.zshield/.filters.DebugCommandReceiver --es uids 10146
adb shell am broadcast -a top.zztweb.zshield.action.DEBUG_CLEAR_BYPASS \
  -n top.zztweb.zshield/.filters.DebugCommandReceiver

# 2. 看清每个连接协商到哪个协议（0.0.6 起 mitm.rs 会打这一行）
adb logcat -c; adb shell am force-stop org.lineageos.jelly
adb shell am start -a android.intent.action.VIEW -d 'https://www.baidu.com'
adb logcat -d | grep 'https decrypt'
#  D ZShieldCore: https decrypt www.baidu.com (uid 10146) negotiated http/1.1
#  D ZShieldCore: https decrypt t11.baidu.com (uid 10146) negotiated h2      ← 这条才是 h2
#  D ZShieldCore: https decrypt b.bdstatic.com (uid 10146) negotiated h2

# 3. 对**真的协商了 h2 的主机**下规则（注意 `$` 必须在设备 shell 里转义，否则被当变量吃掉）
adb shell "am broadcast -a top.zztweb.zshield.action.DEBUG_SET_RULES \
  -n top.zztweb.zshield/.filters.DebugCommandReceiver \
  --es rules '||b.bdstatic.com^\$image,script,xmlhttprequest,other,subdocument'"
adb logcat -d | grep 'https blocked'
#  I ZShieldCore: https blocked GET https://b.bdstatic.com/.../2547961546.png (image)
```

`https blocked` 是 h2 路径（`h2.rs::send_local`）打的；h1.1 中继打的是 `http blocked`。计数上表现为
`HTTP/2 流 26 ｜ 其中拦截 2`。

### 9.5 收尾（每次真机测试都必须做）

```bash
# 关闭 HTTPS 过滤、停止 VPN
# 删除用户 CA：设置 → 安全与隐私 → 更多安全与隐私 → 加密与凭据 →
#            受信任的凭据 → 点「用户」标签 → 选中 ZShield CA →
#            弹出证书详情后点「卸载」(Uninstall) → 确认「永久删除？」
#            列表清空即完成；本机测试留下过两个 CA，两个都删掉了
# 清除锁屏 PIN（用你设置时用的同一个凭据）
adb shell locksettings clear --old "$ZSHIELD_TEST_PIN"
# 清理临时文件
adb shell rm -f /sdcard/Download/ZShield-CA-*.crt
adb uninstall org.cromite.cromite        # 测试浏览器，如非必需
```

### 9.6 已知边界（记录，不是缺陷）

| 边界 | 说明 |
|---|---|
| 现代 Firefox 没有「使用第三方 CA 证书」开关 | 它一律拒绝用户安装的 CA。这不是我们的 bug，而是「浏览器必须信任用户 CA」这条前提在这个版本不成立；自动放行把它兜住，站点照常打开，`httpsBypassJson` 里能看到 `client_unknown_ca` |
| 设备上没有默认浏览器 | `docs/DESIGN.md` §6 已记录。本次用 Cromite（Chromium 分支）验证解密路径，用 Firefox 验证自动放行路径 |
| shell uid 的 `getConnectionOwnerUid` 有时返回 -1 | shell 的 socket 由 `init`/`netd` 代为持有，归属不可归因。此时一律「未知 → 不解密」，是设计期望的行为 |
| `am start` 不能直接触发证书安装 | Android 的 CertInstaller 需要 DocumentsUI 给 `content://` URI；必须走 Settings UI（见 9.4 第 3 步） |
| 重新安装 APK 会清掉 CA 与 VPN 授权 | `adb install -r` 保留数据，但 `pm uninstall` / 换签名会清；每次重装后要重新走 CA 安装与 VPN 授权 |
| 「受信任的凭据 → 用户」列表里的指纹可能与应用报的不一致 | 应用按 `AndroidCAStore` 里每个 alias 的实际证书算指纹，而系统设置那一屏在本机出现过只刷新出旧条目的情况（列表显示 `5e8f228c` 时应用报的是 `dbcdb807`）。以应用侧「已安装：是/否」为准，它是把整库扫一遍比对的 |
| 清掉锁屏 PIN 后装不了用户 CA | CertInstaller 读得到证书（`CERT: 652`、`got a CA cert`）但立刻退出，只弹一个 toast，日志里没有错误。装 CA 前必须先用 `locksettings set-pin <你自己的测试凭据>` 设一个锁屏凭据 |

## 10. M3b：外观过滤（元素隐藏 + scriptlet 注入）

### 10.1 单元测试新增覆盖（`core/src/cosmetic/`）

```bash
cd core
cargo test --lib                 # test result: ok. 557 passed; 0 failed
cargo clippy --all-targets -- -D warnings
```

| 测试模块 | 覆盖的任务卡条款 |
|---|---|
| `scan::tests::*`（24 个） | 插入位置：`<head>`、`<head lang=…>`、没有 head（用 `<html>`）、没有 html（用文档开头）、BOM + doctype、`<head>` 跨两块、64 KiB 窗口放弃；`</head>`/`<header>` 不被误认为 `<head>`；class/id 扫描（引号/无引号、跨块、逐字节、大小写与等号周围空白、`classname=`/`identifier=`/`data-class=` 不误判、超长值不无限增长、超长文档不累积内存） |
| `head::tests::*`（10 个） | 响应头解析（200 + HTML 的可注入判定、304/404/非 HTML/无 Content-Type 全部不可注入）；编码识别（`gzip`/`x-gzip` 可解，`br`/`zstd`/`deflate` 不可）；多条 CSP 全部保留；chunked 识别；改写后去掉 `Content-Length`/`Content-Encoding`/`Transfer-Encoding` 并加 chunked；h2 走 Unframed 时不加 chunked；已有 CSP 原地替换不重复；无终止符的头不改写 |
| `csp::tests::*`（18 个） | 无 `'unsafe-inline'` 时加 nonce；有 `'unsafe-inline'` 时不加（CSP2 语义）；已有 nonce/hash 源时 `'unsafe-inline'` 已被忽略、可以加；`default-src` 回退且 nonce 追加在 `default-src` 上（不新建 `script-src`）；`script-src` 优先；不涉及该元素的策略不用改；style/script 各自独立判定；多条策略逐条判定；空指令与异常空白原样保留；nonce 唯一且为 base64url |
| `gzip::tests::*`（7 个） | gzip 成员的完整解码；**每一个**切分点都能解码；一字节一喂也能解码；可选头字段（FEXTRA/FNAME/FHCRC）的长度计算；非 gzip 与错误压缩方法被拒绝；损坏的 deflate 负载被拒绝；成员之后的字节不被吞掉 |
| `inject_tests::*`（44 个） | 见 10.2 |
| `scriptlets::tests::*`（7 个） | 资源名与别名唯一；依赖都存在；每个 scriptlet 都是引擎能提取名字的函数声明；常用 scriptlet 齐全；别名解析；一份 `##+js(set-constant,…)` 规则真的产出可执行代码；**没有资源注册时引擎静默不产出**（这条守着本模块存在的理由） |

### 10.2 端到端测试（`core/src/cosmetic/inject_tests.rs` 与两条 relay 路径）

`inject_tests.rs` 直接把 origin 的字节喂给改写器，断言的是**客户端会看到的字节**（含 chunked 分帧）：

| 用例 | 断言 |
|---|---|
| `a_style_goes_right_after_head_and_the_document_is_unchanged_otherwise` | `<style>` 紧跟 `<head>`；头部去掉 `Content-Length`、加 chunked；文档其余字节不变 |
| `a_head_with_attributes_and_a_document_without_a_head_both_work` | `<head lang=…>` 与「没有 head」两种位置 |
| `a_document_without_head_or_html_gets_the_style_after_the_doctype` | doctype 之后 |
| `a_bom_is_preserved_in_front_of_the_injected_markup` | BOM 仍是文档第一个字节 |
| `a_head_split_across_two_body_chunks_is_still_found` | **每一个**切分点都注入成功 |
| `a_document_with_no_insertion_point_within_the_window_is_delivered_unchanged` | 窗口外放弃 → 响应**逐字节**原样 |
| `a_gzip_document_is_decoded_injected_and_sent_as_identity` | gzip 进、identity 出、注入成功 |
| `a_gzip_body_split_across_many_chunks_still_injects` | gzip 流**每一个**切分点 |
| `a_corrupt_gzip_body_is_reported_instead_of_delivered_wrong` | 报 `broke`（调用方关连接），不静默交付错误内容 |
| `generic_rules_are_keyed_on_the_class_and_id_values_the_document_contains` | 通用规则按文档里的 class/id 命中，插在文档末尾（不在 `</body>` 前，见 M3b 返工条目 7） |
| `a_generic_rule_for_a_class_the_document_does_not_have_is_not_injected` | 没有该 class 就不注入 |
| `generichide_suppresses_the_generic_style_but_not_the_specific_one` | `$generichide` 只关通用，不关特定 |
| `a_body_close_tag_split_across_two_chunks_still_gets_the_generic_style` | `</body>` 四个切分点 |
| `a_strict_csp_gets_a_nonce_and_the_element_carries_it` | 头部策略与元素 nonce 一致 |
| `an_unsafe_inline_csp_gets_no_nonce_and_no_element_that_would_need_one` | 不加 nonce，`<style>` 仍注入 |
| `a_default_src_only_policy_is_extended_on_default_src` | 在 `default-src` 上追加 |
| `a_meta_csp_in_the_body_is_counted_and_left_alone` | 计 `cosmeticCspMeta`，meta 标签不动 |
| `a_scriptlet_rule_puts_callable_code_in_the_document` | scriptlet 真的在文档里，且 `<style>` 在前 |
| `a_non_html_response_is_byte_for_byte_unchanged` / `a_non_200_response_is_byte_for_byte_unchanged` / `a_document_with_nothing_to_inject_is_byte_for_byte_unchanged` / `an_undecodable_coding_is_byte_for_byte_unchanged` | 四种不该动的响应**逐字节**不变 |
| `an_unframed_rewrite_sends_the_body_without_a_content_length_or_chunking` | HTTP/2 分帧 |
| `a_document_delivered_one_byte_at_a_time_is_injected_correctly` | 逐字节喂入 |
| `a_large_document_is_streamed_without_buffering_it` | 单次 push 的输出远小于文档（流式成立） |
| `a_selector_with_a_brace_cannot_escape_its_rule_block` | 规则不能靠选择器注入任意 CSS |
| `many_selectors_are_split_into_independent_blocks` | 450 条选择器 → 3 个独立规则块 |
| `the_injection_latency_budget_is_met` | 首字节额外延迟 p50 < 20 ms（见 `docs/PERF.md` §13.1） |

两条 relay 路径各有一条端到端用例（`core/src/http/e2e_tests.rs`、`core/src/https/https_e2e.rs`）：

| 用例 | 断言 |
|---|---|
| `http::e2e_tests::a_document_response_is_injected_through_the_live_relay` | HTTP/1.1 明文 relay：注入 + chunked；源站收到的请求等于浏览器发的那条（外加 `Accept-Encoding` 收窄） |
| `http::e2e_tests::a_gzip_document_is_injected_and_arrives_decoded` | 明文 relay 的 gzip 路径 |
| `http::e2e_tests::an_injected_document_is_marked_in_the_request_log` | `recentRequestsJson` 里该条 `cosmetic: true` |
| `http::e2e_tests::a_non_document_response_is_not_injected_by_the_live_relay` | 子资源逐字节直通 |
| `https::mitm::e2e_tests::an_h2_document_is_injected_without_a_content_length` | HTTP/2 真实 TLS：注入且不带 `content-length` |
| `https::mitm::e2e_tests::an_h2_document_gets_a_generic_rule_for_a_class_it_carries` | h2 上的通用规则 |
| `https::mitm::e2e_tests::an_h2_document_request_offers_only_the_codings_the_core_decodes` | h2 的 `Accept-Encoding` 收窄 |
| `https::mitm::e2e_tests::an_h2_subresource_keeps_the_clients_accept_encoding` | 子资源保留客户端自己的 `Accept-Encoding` |
| `https::mitm::e2e_tests::an_h2_non_html_response_is_not_injected` | h2 上非 HTML 不注入 |
| `https::mitm::e2e_tests::a_large_document_survives_a_slow_http11_client` | 1.2 MB chunked+gzip 文档、16 KiB 客户端管道、每读 2 ms 延迟：**必须收到完整文档**（去掉客户端的 `flush` 后停在约 1.12 MB，见 §10.8） |
| `https::mitm::e2e_tests::a_large_document_survives_a_slow_http11_client_without_cosmetic_rules` | 同上，但引擎里没有规则——证明缺陷在写入路径而非注入逻辑 |
| `https::mitm::e2e_tests::a_large_non_document_survives_a_slow_http11_client` | 纯拷贝路径的对照：非文档大响应同样必须完整 |
| `https::mitm::e2e_tests::a_large_h2_document_survives_a_slow_client` | h2 上同样的大文档 + 慢客户端 |

### 10.3 Kotlin 单元测试

```bash
ANDROID_HOME="$ANDROID_SDK_ROOT" ./gradlew :app:testDebugUnitTest
# 158 tests, 0 failures
```

本卡只新增 Rust 侧能力，Kotlin 未改（统计字段由 core 的 `statsJson` 提供，UI 读取在后续迭代）。

### 10.4 构建与体积

```bash
./scripts/build.sh release
# APK zshield-0.0.6-release.apk  7.70 MB (8071501 bytes)
# so  lib/arm64-v8a/libzshield.so  5.37 MB
# 尺寸检查通过：7.70 MB ≤ 10.00 MB
```

### 10.5 真机验证（Pixel 5 / A16，full 模式）

前置：设备已装 `org.lineageos.jelly`（uid 10146，信任用户 CA、会走 h2）。

```bash
# 0. 装 CA 需要锁屏口令（自己提供，仓库无默认值）
adb shell locksettings set-pin "$ZSHIELD_TEST_PIN"

# 1. 装包并生成根证书（调试页按钮），导出到「下载」
adb install -r dist/zshield-0.0.6-release.apk
# 调试页「生成根证书」→ I ZShieldCore: generated root CA <指纹> (valid until …)
# 调试页「导出证书到「下载」」→ I ZShield: root CA exported to content://media/external/downloads/…
adb shell ls -l /sdcard/Download/            # ZShield-CA-<前8位>.crt

# 2. 走系统设置装 CA（`am start` 装不了，见 9.6）
#    设置 → 安全与隐私 → 更多安全与隐私 → 加密与凭据 → 安装证书 → CA 证书
#    → 仍然安装 → 文件选择器里选 ZShield-CA-*.crt → Select
#    回到应用，调试页显示「已安装：是」

# 3. 排除测试浏览器 + 开 HTTPS 过滤 + 启动隧道
#    调试页「排除测试浏览器（FIREFOX）」/ 手动加 jelly → 「开启 HTTPS 过滤」→「开启过滤」
adb shell "am broadcast -a top.zztweb.zshield.action.DEBUG_HTTPS_UIDS \
  -n top.zztweb.zshield/.filters.DebugCommandReceiver --es uids 10146"
# I ZShield : https uids -> [10146]: applied

# 4. 注入 testcases.agrd.dev 的配套测试过滤列表（走真实的用户规则→编译→热替换路径）
adb shell "curl -s https://testcases.agrd.dev/Filters/element-hiding-rules/test-element-hiding-rules.txt" \
  > /tmp/eh-test.txt
# 用单引号把整个文件传进 --es（内部单引号用 '\'' 转义）
adb shell "am broadcast -a top.zztweb.zshield.action.DEBUG_SET_RULES \
  -n top.zztweb.zshield/.filters.DebugCommandReceiver --es rules '<文件内容>'"
# I ZShield : user rules changed, compile scheduled
# I ZShieldCore: compiled 10 lists: … 422380 network …
# I ZShield : hot reload finished: ok=true

# 5. 浏览器打开元素隐藏测试页（会走 h2 + gzip）
adb shell am start -a android.intent.action.VIEW \
  -d 'https://testcases.agrd.dev/Filters/element-hiding-rules/test-element-hiding-rules'
# D ZShieldCore: https decrypt testcases.agrd.dev (uid 10146) negotiated h2
# D ZShieldCore: cosmetic: response 200 Some("text/html; charset=utf-8") enc Some("gzip") injectable true
# I ZShieldCore: cosmetic: 742 specific, 6 generic, scriptlet false, cspMeta false
```

`742 specific, 6 generic` 就是这一页实际注入的选择器数：742 条来自内置订阅 + 测试过滤列表里
hostname 作用域的选择器，6 条是按文档里的 class/id 命中的通用规则（含 case-2 与 case-3 的 `h3`）。

```bash
# 6. 通用规则 + 注入内容的核对（不需要浏览器：curl 带上 Sec-Fetch-Dest: document）
adb shell "curl -s --cacert /sdcard/Download/ZShield-CA-*.crt \
  -H 'Sec-Fetch-Dest: document' --max-time 25 \
  'https://testcases.agrd.dev/Filters/element-hiding-rules/test-element-hiding-rules'" \
  | grep -oE 'data-zshield="[^"]*"'
# data-zshield="specific"
# data-zshield="generic"
```

```bash
# 7. 正常站点不破版（截图核对）
adb shell am start -a android.intent.action.VIEW -d 'https://www.baidu.com'
adb shell am start -a android.intent.action.VIEW -d 'https://www.bilibili.com'
adb shell am start -a android.intent.action.VIEW -d 'https://github.com'
adb shell am start -a android.intent.action.VIEW -d 'https://www.zhihu.com'
adb shell screencap -p /sdcard/<name>.png && adb pull /sdcard/<name>.png
```

```bash
# 8. 性能（见 docs/PERF.md §13）
adb shell "dumpsys meminfo top.zztweb.zshield | grep 'TOTAL PSS'"
```

### 10.6 收尾（每次真机测试都必须做）

```bash
# 关闭 HTTPS 过滤、停止 VPN
# 删除用户 CA：设置 → 安全与隐私 → 更多安全与隐私 → 加密与凭据 → 受信任的凭据 →
#            「用户」标签 → 选中 ZShield CA → 卸载 → 确认
adb shell locksettings clear --old "$ZSHIELD_TEST_PIN"
adb shell rm -f /sdcard/Download/ZShield-CA-*.crt /sdcard/eh-test.txt /sdcard/shot*.png /sdcard/s.xml
```

### 10.7 已知边界（记录，不是缺陷）

| 边界 | 说明 |
|---|---|
| 元素隐藏测试页在浏览器里显示为空白 | 该页把全部测试夹具放在 `position: absolute; top: -2500px` 的容器里，QUnit 的结果区在它下面。注入的 CSS 让夹具不可见本身是**期望行为**；通过数要读 QUnit 的 DOM，不能用截图判断 |
| `Sec-Fetch-Dest` 缺失的客户端不会被注入 | 那是任务卡 §1 的判据。`curl` 默认不发这个头，所以设备上用 `curl` 验证注入必须显式带上 `-H 'Sec-Fetch-Dest: document'`（第 6 步） |
| 系统浏览器的 socket 有时归属不可知 | `getConnectionOwnerUid` 对 Jelly 的部分 socket 返回 -1（见 9.6），此时一律不解密。表现为重开几次才能解密，不是本卡的缺陷 |

### 10.8 大页面停在约 97%：根因与回归测试（返工第 2 轮）

**症状**：经解密转发 1.2 MB 的 chunked + gzip 文档时，客户端收到的字节停在文档末尾之前，随后超时。

**根因**：`core/src/http/relay.rs` 写完客户端字节后从不 `flush`。解密腿是 `tokio-rustls` 的
`WriteHalf`，放不进一个 TLS record 的尾部留在会话写缓冲里；注入路径一次写出的是一整块重写后的正文，
于是最后一段留在缓冲里直到连接被关闭。文档必现而 PDF 不现，是因为只有文档走
`Rewriter`/`BodyInjector` 这条一次写大块的路径。

**修复**：主循环与 `write_pumping` 在写出**被重写的**字节后 `flush`（`ResponseState::rewriting()` 判定），
`finish_cosmetic` 的尾巴之后同样 `flush`。未重写的响应不 flush，行为与 v0.0.7 一致。

**回归测试**：见 §10.2 的四条 `a_large_*` 用例。它们用一个 16 KiB 的客户端管道加每读 2 ms 的延迟，
让「写端领先于读端」成为必然；去掉 `flush` 时前两条停在约 1.12 MB 并失败，加回后通过。

**真机（修复后构建）**：注入开启连抓 `rfc9110.html` 30/30 完整（中位 1.53 s，v0.0.7 为 1.49 s）；
解密不注入连抓 1.26 MB PDF 30/30 完整。

## 11. M4a：后台保活与自动恢复

实现与平台限制的核对结论见 `docs/KEEPALIVE.md`；本节只写**怎么测**。

设备占用、安全约束与其它真机测试相同（`AGENTS.md`「测试设备安全」「设备占用锁」）：先拿锁，测完释放，
不切飞行模式、不关 Wi-Fi / 移动数据。

### 11.1 主机侧

```bash
./gradlew :app:testDebugUnitTest     # 含 RecoveryPolicyTest / HealthStateTest / AppSettingsTest 新增用例
./gradlew :app:lintRelease           # 0 error
./scripts/build.sh release           # APK ≤ 10 MB
```

单元测试覆盖三块，都是纯逻辑、不碰设备：

| 文件 | 覆盖点 |
|---|---|
| `RecoveryPolicyTest` | 决策表的全部组合：`protectionWanted=false` 时任何触发器都不恢复（穷举）、`true` 且隧道缺失时每个触发器都恢复、always-on 让路、`alwaysOn=null` 仍恢复、已运行时不去重建、无授权时只报告、判定优先级（意图 > 运行中 > 授权 > 系统接管） |
| `HealthStateTest` | 健康设备无待办项、九项问题的排列顺序、读不到的值是 `null` 且不进待办清单、全部探针抛异常时退化成文档规定的回退值而不是崩、standby bucket 的阈值方向、`revokedBySystem` 与授权状态互不影响 |
| `AppSettingsTest` | 意图默认关闭、开关持久化、用户重开时清掉 `revokedBySystem`、**系统撤销不改意图**、跨进程重启后两者都在、v2 文档升级后恢复默认关闭、文档版本号 |

### 11.2 真机命令

```bash
D="adb -s $SERIAL"
PKG=top.zztweb.zshield

# 拿锁（被别的 issue 占用就先做主机侧工作）
$D shell 'cat /data/local/tmp/zshield-device.lock 2>/dev/null'
$D shell "echo 'MYS-2729 '\$(date -Iseconds) > /data/local/tmp/zshield-device.lock"

$D install -r dist/zshield-0.0.9-release.apk
```

开启 / 关闭隧道（不走 UI，避免依赖屏幕坐标；`DEBUG_TOGGLE_VPN` 是既有的调试入口）：

```bash
$D shell "am broadcast -a $PKG.action.DEBUG_TOGGLE_VPN -n $PKG/.filters.DebugCommandReceiver"
```

真机断言用 `ping` 一个已知被拦截的域名：被拦截时解析到 `127.0.0.1`，隧道不在时解析到真实地址。

```bash
$D shell 'ping -c 1 -W 2 doubleclick.net'      # 拦截命中：PING doubleclick.net (127.0.0.1)
```

**场景 1：Doze 强制空闲 30 分钟后仍拦截**

```bash
$D shell 'dumpsys battery unplug'
$D shell 'dumpsys deviceidle force-idle'
# 等待 30 分钟（期间不要碰屏幕）
$D shell 'dumpsys deviceidle get deep'; $D shell 'dumpsys deviceidle get light'
$D shell 'ping -c 1 -W 2 doubleclick.net'
$D shell 'dumpsys deviceidle unforce'
$D shell 'dumpsys battery reset'
```

**场景 2：受限待机桶后服务仍在且能恢复**

```bash
$D shell "am set-standby-bucket $PKG restricted"
$D shell "am get-standby-bucket $PKG"          # 期望 45
$D shell 'dumpsys activity services top.zztweb.zshield | grep isForeground'
$D shell "am set-standby-bucket $PKG active"   # 测完恢复
```

**场景 3：进程被杀后自动恢复（记录耗时）**

`am kill` 只会杀**后台**进程，对持有前台服务的进程按设计无效；`kill -9 <pid>` 又因 uid 不同被拒
（`Operation not permitted`），而开 root 调试会重启 adbd、**断掉 Wi-Fi 上的 adb**（`AGENTS.md` 禁止）。
因此用应用内的测试入口 `RecoveryTestReceiver`（`android.permission.DUMP` 保护，普通应用拿不到）让它
对自己发 `SIGKILL`：在 AMS 看来与低内存杀进程是同一条路径（进程死亡、无 Java 异常、无「应用已停止」标记），
`START_STICKY` 的重启逻辑照常执行。

```bash
$D logcat -c
$D shell "am broadcast -a $PKG.action.DEBUG_SUICIDE -n $PKG/.vpn.RecoveryTestReceiver"
$D logcat -d | grep -E 'SIGKILL on request|Scheduling restart|Start proc.*for service|Established by top'
$D shell 'dumpsys activity services top.zztweb.zshield | grep -E "isForeground|startRequested"'
```

**场景 4：重启后自动恢复（always-on 开 / 关两种）**

```bash
# 4a：始终开启的 VPN 关闭（靠 BOOT_COMPLETED）
$D shell 'settings get secure always_on_vpn_app'      # 期望 null
$D reboot
$D wait-for-device
$D logcat -d | grep -E 'restore after android.intent.action.BOOT_COMPLETED|recovery trigger=BOOT|Established by top'

# 4b：始终开启的 VPN 打开（系统负责拉起，应用主动让路）
$D shell "settings put secure always_on_vpn_app $PKG"
$D shell 'settings put secure always_on_vpn_lockdown 0'
$D reboot
$D wait-for-device
$D logcat -d | grep -E 'recovery trigger=BOOT outcome=MANAGED_BY_SYSTEM|Established by top'
$D shell "settings delete secure always_on_vpn_app"   # 测完恢复
```

**场景 5：覆盖升级后自动恢复**

```bash
$D logcat -c
$D install -r dist/zshield-0.0.9-release.apk
$D logcat -d | grep -E 'restore after android.intent.action.MY_PACKAGE_REPLACED|recovery trigger=PACKAGE_REPLACED|Established by top'
```

**场景 6：网络切换**（只做不断开 adb 的部分）

```bash
$D shell 'ping -c 1 -W 2 doubleclick.net'        # 切换前
$D shell 'cmd wifi list-scan-results' >/dev/null  # 触发一次扫描
$D shell 'cmd wifi status'
$D shell 'ping -c 1 -W 2 doubleclick.net'        # 切换后仍拦截
```

Wi-Fi ↔ 移动数据 ↔ 飞行模式三态切换必然断开 Wi-Fi 上的 adb，按 `AGENTS.md` 不测，作为已知未测项记录。

**场景 7：熄屏浸泡（≥1 h）与能耗对比**

```bash
$D shell 'dumpsys batterystats --reset'
$D shell 'input keyevent KEYCODE_SLEEP'
# 静置 ≥ 1 h
$D shell 'input keyevent KEYCODE_WAKEUP'
$D shell "dumpsys batterystats $PKG" | grep -E 'Wakelock|wake|CPU'
$D shell "dumpsys batterystats --charged $PKG" | head -40
```

与 v0.0.9 基线对比：同条件、同版本以外的唯一变量是本卡改动。

**磁贴与「用户关闭后不恢复」**

```bash
$D shell 'cmd statusbar expand-settings'    # 或直接在快捷设置里添加「ZShield 净盾」磁贴
$D shell 'cmd statusbar collapse'
# 用户主动关闭后再重启，验证不会被自动拉起：
$D shell "am broadcast -a $PKG.action.DEBUG_TOGGLE_VPN -n $PKG/.filters.DebugCommandReceiver"  # 关闭
$D reboot; $D wait-for-device
$D logcat -d | grep 'recovery trigger=BOOT outcome=USER_TURNED_OFF'
$D shell 'dumpsys activity services top.zztweb.zshield'   # 期望 (nothing)
```

### 11.3 收尾

```bash
$D shell 'dumpsys deviceidle unforce; dumpsys battery reset'
$D shell "am set-standby-bucket $PKG active"
$D shell 'settings delete secure always_on_vpn_app'
$D shell 'rm /data/local/tmp/zshield-device.lock'
```

## 12. M5a：过滤效果测量（规则覆盖 / 公开测试页 / 20 站对照）

三个测量脚本都在 `scripts/effectiveness/`，一条命令跑一种条件。它们不修改产品代码，只观测设备。

### 12.1 前置

| 项 | 说明 |
|---|---|
| 设备 | Pixel 5（Android 16），`adb -s "$SERIAL"`；`svc power stayon true` 保持亮屏 |
| 浏览器 | `org.lineageos.jelly`（uid 10146）。它是本机唯一「信任用户 CA 且走 h2」的客户端；**不在** `assets/https/browsers.txt` 里，所以 HTTPS 条件通过 `DEBUG_HTTPS_UIDS` 把它的 uid 加进解密名单 |
| CDP 依赖 | 主机侧 `pip install websocket-client`；`adb` 在 PATH 里 |
| 设备锁 | `condition.sh` 写 `/data/local/tmp/zshield-device.lock`（首行 `<issue> <ISO 时间>`，另加 `…lock.state/meta`），`cleanup` 删除；语义见 §14.6 |
| WebView 调试 | Jelly 默认已开 `webview_devtools_remote_<pid>`；`cdp.py` 按 pid 动态绑定 forward，并把浏览器切到前台（后台会被节流，socket 存在但请求全部超时） |

### 12.2 规则覆盖（主机侧，不需要设备）

```bash
scripts/effectiveness/fetch-lists.sh                      # 下载 27 个内置列表到 .effectiveness/lists
cargo run --release --example coverage_probe --manifest-path core/Cargo.toml -- \
    app/src/main/assets/filters/catalog.json .effectiveness/lists docs/coverage.json
```

输出 `docs/coverage.json` 并打印对账结果。**对账通过**是最重要的自检：**九个**类别的条数之和必须
等于每个列表的有效规则行数，脚本对 27 个列表逐条校验，不通过就以非 0 退出。

分类的判据是两条**真实解析路径**的结论，不是语法猜测：DNS 层用 `zshield::dns::filter::classify_line`
（产品自己用的那个解析器），网络/外观层用 `adblock::lists::parse_filter`（引擎自己的解析器）。一个
「解析得动但本 core 从不消费」的规则因此被记为**无效**而不是有效——这个区分是这张表存在的意义。

M5b 之后的过程式与 `$modifier` 类判定走的是**出货代码**而不是重新实现一遍：

| 类别 | 判据 |
|---|---|
| `proceduralApplied` | 引擎把它放进 `procedural_actions`，且 `cosmetic::procedural::Screen` 会接受它 |
| `extras` | `https::extras::collect` 对同一行能产出 `$popup`/`$denyallow`/`$removeparam` 规则 |
| `procedural` | 仍无法应用的过程式规则（M5b 之后为 0） |
| `adguardModifier` | 引擎拒绝、且本 core 也不求值（`$urlskip`、`$replace`、`##^` …） |

`scripts/check-procedural-runtime.mjs` 是过程式运行时的**行为**测试（`node scripts/check-procedural-runtime.mjs`，
需要 `npm install jsdom`）。它从 `core/src/cosmetic/procedural.rs` 里抽出 `RUNTIME` 常量，在 jsdom 里
跑 20 个用例，覆盖每个算子与动作、以及「规则参数不能变成标记」这条安全性质。Rust 侧的
`the_runtime_is_self_contained_and_syntactically_a_program` 只做静态检查（括号平衡、无模板字面量、
无 `eval`/`innerHTML`/`document.write`），因为 Rust 测试里没有 JavaScript 引擎。

### 12.2b 过程式运行时（M5b）

```bash
npm install jsdom                                   # 一次性
node scripts/check-procedural-runtime.mjs           # 20/20 passed
```

**为什么需要它**：`RUNTIME` 是一段 JavaScript 字符串常量，Rust 编译器不会检查它。一个语法错误在 Rust
里完全看不出来，在浏览器里表现为「所有过程式规则静默不生效」。这个脚本把它抽出来在真 DOM 上跑，是
唯一的防线。

**测了什么**：每个算子（`:has-text()` 字面与正则、`:min-text-length()`、`:matches-attr()` 名字与值、
`:matches-path()`、`:upward()` 数字/选择器/越界、`:xpath()`）、每个动作（无 action、`:style()`、
`:remove()`、`:remove-attr()`、`:remove-class()`）、选择器续段（`:has()` 过滤当前节点、`>` 向下走）、
未知算子停止规则、浏览器拒绝的选择器不影响下一条规则、规则参数不能变成标记。

### 12.2c 逐页测 QUnit（M5b 起）

```bash
# 14 份测试列表不能一起装：generichide 那一份带 @@||testcases.agrd.dev$generichide，
# 装上它会让所有页面的通用元素隐藏失效。逐页只装该页自己那一份。
#
# 这件事现在由 testpages.py 自己按页做（install_test_list）：抓取该页的配套列表 → push 到
# /data/local/tmp → DEBUG_SET_RULES → 等 hot reload 真的完成（wait_for_reload）→ 打开页面。
# 所以一条命令就能测完全部 14 页：
python3 scripts/effectiveness/testpages.py --condition zshield-https --out .effectiveness/results

# 只复测修复涉及的几页，不必等其余 11 页（每页约 70 s）：
python3 scripts/effectiveness/testpages.py --condition zshield-https \
    --out .effectiveness/results --suffix=_fix --pages element-hiding,generichide

# A 组（不装配套列表，测「本 build 说不说这套语法」）：
python3 scripts/effectiveness/testpages.py --condition zshield-https \
    --out .effectiveness/results --suffix=_A --no-test-lists
```

`--suffix` 让每次测量写自己的文件，`sites.py`/`testpages.py` 的 `--only` 会**覆盖**同名结果文件——
所以复测单个站点时一定要给 `--suffix` 或换 `--out`，否则会把整轮结果换成那一个站点
（本轮踩到过，`docs/EFFECTIVENESS.md` §10.5 有记录）。`testpages.py` 现在**每测完一页就落盘一次**，
所以中途被打断也不会丢掉已测的页。

配套列表的抓取走 `urllib`：该站对裸 `Python-urllib/3.x` 的 User-Agent 返回 **403**，所以脚本带浏览器
UA；传输层错误（`SSL: UNEXPECTED_EOF_WHILE_READING` 在 2026-11-10 多次出现）会重试 4 次并回退到
`.effectiveness/lists/` 的缓存副本，因为一次传输抖动不应该毁掉一轮 15 分钟的设备测量。

#### 12.2d 三处会让读数失真的地方（I2 修掉，`docs/EFFECTIVENESS.md` §13.4）

| 缺陷 | 现象 | 现在怎么做 |
|---|---|---|
| `wait_for_qunit` 见到 `completed` 就返回 | QUnit 跑到第 8 条输出的就是 `8 / 14 tests completed.Running: …`，页面被提前读取，结果记成「abort + N 条失败」 | 判据是**完成数 == 总数**；只有真停在总数以下才走 6 s 静默判定 |
| `install_test_list` 固定等 10 s | 实测重载要 ~9 s（编译 2.1 s + 防抖 + 排队），经常不够，页面加载到**上一页**的规则集 | `logcat -c` → 广播 → 轮询 `hot reload finished: ok=true` |
| 跨页复用浏览器缓存 | 同一 URL 在不同页出现时命中缓存，请求根本不到隧道（`$subdocument` 页的 `transferSize=0`） | 需要区分「来自哪个框架」的页面，必须在 URL 上加一次性参数 |

另外两点：

- **`response.url` 观测不到子资源的原地改写。** `$removeparam` 对非导航请求是原地改写（设计如此），
  客户端读到的 URL 不变；验收要看**上游实际收到的 URL**，`testcases.agrd.dev` 的 `$removeparam` 页
  因此永远显示低分。正确性用 `https_e2e.rs` 的集成用例验证。
- **换 APK 之后先确认 `.so` 真的换了**：`unzip -p dist/*.apk lib/arm64-v8a/libzshield.so | strings |
  grep <改动引入的新字符串>`。

### 12.3 公开测试页

```bash
# 三种条件各跑一次；不带 --only 就跑全部 14 个 QUnit 页 + adblock-tester
scripts/effectiveness/run.sh vpn-off
scripts/effectiveness/run.sh zshield-default
scripts/effectiveness/run.sh zshield-https

# 只测某一类
python3 scripts/effectiveness/testpages.py --condition <name> --only adblock-tester
scripts/effectiveness/run.sh zshield-https --test-pages --with-agrd-test-lists
```

`--with-agrd-test-lists` 把 testcases.agrd.dev 每个 QUnit 页自带的配套过滤列表（共 497 行）通过
`DEBUG_SET_RULES` 注入成用户规则，再测量。**不加这个参数测的是「本 core 说不说这套语法」，加了测的是
「自带规则集 + 该页测试列表能不能产生正确的 DOM」**，报告里两组分开标注。

两个页面的读法不同，因为它们的打分方式不同：

- `adblock-tester.com` 渲染 `h3.final-score[data-color]` 里的 `b.final-score-value` 与每个服务的
  `✅/❌` 行；脚本读总分**和**分项。
- `testcases.agrd.dev` 是 QUnit 页，脚本读 `#qunit-testresult` 的汇总句（`N tests completed … with K
  failed … M assertions of P passed, Q failed`）与 `#qunit-tests` 逐条状态，同时读页面自己的
  `subscribe-to-…-filter` 横幅是否被隐藏，用来证明配套列表确实生效了。

> **踩过的坑**：`Page.navigate` 之后立刻读 `document.readyState` 得到的是**上一个文档**的 `complete`，
> 于是每次测量读到的都是上一页的结果。`cdp.py` 的 `wait_for_load` 因此要求 URL 与目标一致（跳过
> `.html` 后缀与末尾 `/` 的差异）之后才算到达；这是把「第一页读到上一轮的报错页」这个真实故障修掉的地方。

### 12.4 20 个站点

```bash
scripts/effectiveness/run.sh zshield-default --sites                 # 全部 20 个
python3 scripts/effectiveness/sites.py --condition vpn-off --only cn,github   # 分组/按 slug
```

每个站点、每种条件记录：CDP `Network.requestWillBeSent` 的请求数与分类型分布、`loadingFailed` 里被浏览器
记为 blocked 的条数、应用自己的计数器增量（DNS 拦截 / HTTP 拦截 / 拦截连接，从调试页 `uiautomator` 读，
原生 View 可读——不可读的只有 WebView 内容）、首屏截图、以及**机器可判**的破版信号：`blank`（文本
< 120 字符且无图）、`horizontal-overflow`（内容宽 > 视口 5%）、`browser-error-page`（`net::ERR_…`）、
`app-blocked-page`。截图之外的「视频不播」「布局微妙错乱」只能人眼看，JSON 里记 `needsReview`。

### 12.5 汇总

```bash
python3 scripts/effectiveness/report.py                     # Markdown 表格，直接贴进文档
python3 scripts/effectiveness/report.py --format json        # 机器可读
```

### 12.6 收尾（每次都做）

```bash
scripts/effectiveness/condition.sh cleanup
```

它会关 HTTPS 过滤、停 VPN、清用户规则、强停应用、释放设备锁。**它不会**删用户 CA、不会清 PIN——那两步
必须走系统设置界面，见 §9.5。三条手工项：

```bash
# 1. 删用户 CA：设置 → 安全与隐私 → 更多安全与隐私 → 加密与凭据 → 受信任的凭据 →「用户」标签
# 2. 清 PIN（若为装 CA 设过）：adb shell locksettings clear --old "$ZSHIELD_TEST_PIN"
adb shell rm -f /sdcard/Download/ZShield-CA-*.crt /sdcard/zs-*.xml /data/local/tmp/zshield-test-lists.txt
adb forward --remove-all
```

### 12.7 已知边界

| 边界 | 说明 |
|---|---|
| `PUT /json/new` 不可用 | Android WebView 的 devtools 端点对它返回 500（标签页归宿主应用所有）。测量改为 `Page.navigate` 复用现有 page target，并在导航前清缓存/存储 |
| 后台 WebView 被节流 | 浏览器切到后台后 socket 仍在、`adb forward` 也成功，但每个 CDP 请求都超时。`attach()` 先唤醒屏幕并把应用切到前台再绑定 |
| `logcat -s <tag>` 在设备上不可用 | 该设备的 `logcat` 对 tag 过滤的行为与桌面版不同，`-s ZShield` 返回空。脚本改为 grep 全量 dump |
| `run-as` 被拒 | release 包不可调试，读不到 `files/settings/app-settings.json`；HTTPS 状态因此从 core 的 `https filtering: …` 日志行读，日志被冲掉时重启一次隧道让它重新打印 |
| QUnit 页会 Abort | 少数页面（`network-rules`、`removeparam`）在规则缺失时中途 abort，汇总句变成 `N / M tests completed`。此时记的是已完成的部分，不是失败 |

## 13. 修复批次 2 复审（MYS-2742，PR #14 打回后重做）

### 13.1 主机侧

```bash
cargo test --manifest-path core/Cargo.toml            # 连跑 3 次
cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings
./gradlew :app:testDebugUnitTest
./scripts/build.sh release
```

| 测试类 | 覆盖点（本次新增） |
|---|---|
| `FilterRepositoryDownloadTest` | **主线程不联网**：`updateAll` / `setEnabled` 的下载线程名不等于调用线程且为 IO 线程；**编译不清下载错误**：有旧内容的列表重下失败后经过一次成功编译仍带 `Error`，成功下载才清除；**优先级**：无内容列表先于仅需刷新的列表被请求；**并发上限**：6 个列表峰值并发 == `DOWNLOAD_CONCURRENCY`；**排队状态**：等待槽位的列表状态为 `Queued`；**每 URL 日志**：单个候选地址一行、含耗时与结果 |
| `ListUpdaterTest` | 慢速传输在总时长上限内换镜像、全部镜像耗尽预算时以「超时」失败、预算耗尽的镜像被跳过但仍有日志行、HTTP 错误码进日志 |
| `ListSanityTest` | **EasyList 形状的网络规则**（`-ad-manager/$~stylesheet`、`&rb=&uuid=$third-party` 等 15 条真实行）被判为规则；单行散文仍被判为非规则；EasyList 比例的列表通过合理性检查 |

### 13.2 真机（Pixel 5 / A16）

设备锁：`/data/local/tmp/zshield-device.lock` 写入 `MYS-2742 <ISO>` 后开始，测完删除。

| 项 | 操作 | 结果（v0.0.10 + 本卡改动） |
|---|---|---|
| 开启未下载列表 | 过滤器页开启 EasyList | `list candidate: https://easylist.to/easylist/easylist.txt -> ok in 1784 ms, 2023261 B`，`list easylist: updated from … (EasyList, expires=96h)`；界面 **42,406 条规则**，从点击到编译完成 ≈ 8 s ✅ |
| 开启新列表后立刻「全部更新」 | 开启 uBlock 后 0.08 s 点「全部更新」 | 新列表在 1.4 s 内开始并完成下载（`-> ok in 1577 ms`），未排在整轮之后 ✅ |
| 每个候选 URL 的耗时 | logcat | `list candidate: <url> -> ok/not-modified/timeout in <ms>, <bytes>`，每列表每地址一行 ✅ |
| 日志与计数对账（关 HTTPS 过滤） | 开 VPN 浏览 6 个站点 | 首页 `已拦截 24`（DNS 17 + 连接 7）；日志页 `已拦截 24` —— **24 == 24** ✅ |
| 日志三类内容 | 日志页过滤「已拦截」 | 可见 `dot`（DoT 拒绝 `10.111.222.2:853`）、`quic`（`182.40.68.184:443`）、`已拦截 · A` 与 `CNAME → …`（CNAME 反隐藏命中）✅ |
| 停止隧道清空日志 | 停 VPN 后停留日志页 | `全部 0 / 已拦截 0 / 已放行 0`，页面回到「保护未开启」空状态 ✅ |
| 模拟器 `cannot allocate the result string` | Pixel 5 全量 logcat | **0 次**；编译正常（`compiled 11 lists: … 3504 ms`）。确认为 native bridge 特有，真机不复现 ✅ |

### 13.3 本次在真机发现的既有缺陷（已修）

`ListSanity` 的「规则行」判定只认 `||`/`|`/`@@`/`##`/裸域名，而 EasyList 正文绝大多数是不带这些前缀的
网络规则（`-ad-manager/$~stylesheet`、`&rb=&uuid=$third-party`、`.ads.controller.js$script`）。真机实测
EasyList 的规则行占比被判为 **0.4%**（阈值 5%），因此**正版 EasyList 永远下载失败**，界面停在错误上——
单元测试此前只用 `||host^` 形状的合成列表，所以没暴露。修复后同一份 EasyList 占比 **63.4%**（抽样 2000 行）
/ 全文 **81.7%**，正常通过；散文仍是 0%。


## 14. 隧道请求路径的并发 / 收尾回归（MYS-2804 → MYS-2817）

本节回答一个问题：**怎么证明一次请求真的经过了 VPN，过滤真的生效了，并且 20 个请求真的同时在途**。
上一轮把主机 `urllib` 的结果当成隧道证据（`docs/EFFECTIVENESS.md` §13.10），第二轮又出现「工具本身
把错数据判成 PASS」，所以这一版的重点不是「跑起来」，而是**每一条判据都必须能非零退出，且缺观测不能当成
通过**。

> 本节的工具已在 MYS-2817 重写。§14.1–14.6 是 I2 阶段 2 的原文保留（可达性实测仍然有效），§14.7 起
> 记录阶段 3 修复后的契约。真机测量在阶段 4 进行，**本节不含任何真机测试结果**。

### 14.1 为什么必须先解决「路径可达性」

隧道开启后核心接管**全部** IPv4 目标，**包括手机所在局域网**。这不是推断，是真机日志：

```text
D ZShieldCore: connect 10.111.222.1:38674 -> 192.168.0.2:3000 failed: No route to host (os error 113)
```

推论：准备回显服务时，**不能**假设「主机和手机在同一网段」。

| 方案 | 实测结果 | 结论 |
|---|---|---|
| 主机开端口，手机访问主机 LAN 地址 | 不可达 | ✗ |
| `adb reverse tcp:PORT tcp:PORT` | 手机可访问该端口，但它绑定在本机回环，**不出隧道** | ✗ 只能当本机夹具 |
| 主机公网 IP + 端口 | 无公网入向 | ✗ |
| `httpbin.org/anything` | 可达、证书受信、ALPN h2、回显 `args` | △ **无请求 ID、无 body 字节摘要**，见 §14.7 |
| `httpbingo.org/anything` | 同上，20 并发 POST 无限流 | △ 同上，且 `form` 字典是归一化后的结果 |
| 自建 `tunnel_origin.py`（`--https-port` + 证书） | 本机 h2 实测可用（`ver=2 code=200`） | ✓ **唯一满足验收契约的回显** |
| `scripts/effectiveness/tunnel_origin.py` + 公网隧道 | 契约相同 | ✓ 有可控公网入口时用 |

### 14.2 组件

| 文件 | 作用 |
|---|---|
| `scripts/effectiveness/tunnel_origin.py` | 受控回显：逐请求记录 **上游看到的请求 ID**、method、target、**raw body 的 SHA-256**、TLS/ALPN、在途计数；提供 `/__fault/{500,url,body,disconnect,redirect}`、`/__id`、`/__stats`；三个监听（明文 / TLS-h2 / TLS-仅 h1） |
| `scripts/effectiveness/tunnel_concurrency.py` | 并发回归主验收入口；`--selftest` 证明判据能失败，`--readiness` 用行为证明本轮规则生效 |
| `scripts/effectiveness/tunnel_fault_selftest.py` | 经真实隧道注入故障 + 正向对照，必须全部被检出 |
| `scripts/effectiveness/tunnel_snapshot.sh` | 运行前/收尾快照与差值；**缺观测即拒绝** |
| `scripts/effectiveness/pss_idle.sh` | 空闲 PSS 采样（6 样本，原始 kB 中位数；**必须**用 `--expect-identity(-from)` 声明目标；同 PID/UID/handle/generation/目标身份；`--identity <dir>` 打印目标身份；`--diagnostic` 只出诊断值不出 median） |
| `scripts/effectiveness/tunnel_acceptance.sh` | 把上述步骤串成一条命令，失败路径也恢复规则与配置 |
| `scripts/effectiveness/concurrency_smoke.py` | **已废弃**：任何调用都非零退出并指向替代入口 |
| `scripts/effectiveness/tests/` | 工具契约测试：`python3 -m unittest discover -s scripts/effectiveness/tests -p 'test_*.py'` |
| `core/examples/rebuild_edits_perf.rs` | `HttpsModifiers::edits` 每请求开销（5 表 / 9 表） |
| `core/examples/rules_identity_cost.rs` | 规则内容身份（SHA-256）在启动/热替换路径上的实测成本，及每请求成本为 0 |

### 14.3 并发模型：页面内一批，三条腿各自独立页

`cdp.Page.send` 在**单条 WebSocket** 上按 id 匹配响应，并对其它 id 的消息只做事件缓存，所以从 Python
多线程并发调用 CDP 会互相吞掉响应。正确做法是**一次 `Runtime.evaluate` 里发一个 `Promise.all`**。

阶段 3 补上两件此前缺失的事：

* **三腿必须各有自己的 page target**。`cdp.py` 过去一律选 `targets[0]`，两次 `Browser.open()` 其实是
  同一个页面，第二次导航会打断第一批请求——所以「20 并发」从来没有成立过。现在 `open_target()` 由调用方
  显式挑 target，`validate_isolation()` 用 target id 证明三条腿互不相同；目标不足时脚本明说改为串行布局，
  而不是假装并行。
* **在途数量由上游作证**。每条回显记录带 `inflight`（到达时的在途计数），每组必须达到**最忙那条腿**
  的份额，串行执行达不到。这不是客户端自报的数字。

### 14.4 判据（每一条都能非零退出）

1. 状态码非 200（导航用 CDP 的真实响应码，不是常量）；
2. 传输错误/超时；
3. **上游回显没有收到该请求**——`id` 取自**上游记录**，与客户端报告和计划三者一致；错误/缺失/重复/
   计划外/跨轮 ID 全部失败；
4. 该删的参数**仍出现在上游**，或设计要求保留的参数**丢了**；
5. POST 的 method 或 **raw body 字节摘要**不符（`form` 字典这类归一化形态不算证据）；
6. 该腿没有协商到声明的协议（明文与 TLS-H1 要 `http/1.1`，TLS-H2 要 `h2`），
   且上游报告的 ALPN 与浏览器一致；
7. 数量/场景分布与计划不符（`PASS: 0 request(s)` 这类）；
8. **组总量**的在途数低于 `--concurrency`，或上游的 `peak`/`overlap` 低于同一数值；
9. 两条腿共用同一个 page target（并行布局下）；
10. 两种 framing 没有同时出现。

### 14.5 命令

```bash
# 0. 受控 origin（三个监听：明文 / TLS-h2 / TLS-仅 http/1.1）
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=origin \
    -addext 'subjectAltName=DNS:origin.test' \
    -keyout .effectiveness/origin/key.pem -out .effectiveness/origin/cert.pem
python3 scripts/effectiveness/tunnel_origin.py --port 18200 --https-port 18443 --https1-port 18444 \
    --cert .effectiveness/origin/cert.pem --key .effectiveness/origin/key.pem \
    --hold-ms 400 --log .effectiveness/results/tunnel-origin.jsonl \
    --ready-file .effectiveness/results/origin-ready.json
#   `--hold-ms` 让响应保持打开一会儿，20 并发才可被观测为重叠。它只延迟响应，
#   不影响 method/target/body 的断言。

# 1. 条件（必须给锁归属）
LOCK_OWNER=MYS-2817 scripts/effectiveness/condition.sh zshield-https

# 2. 一条命令跑完全部（取锁 → 备份规则 → 装规则并行为就绪 → 故障自检 → 并发 → 收尾 → 恢复）
LOCK_OWNER=MYS-2817 scripts/effectiveness/tunnel_acceptance.sh \
    --origin https://ORIGIN --http-origin http://ORIGIN --https-origin https://ORIGIN \
    --tls1-origin https://ORIGIN:18444 --rounds 5 --concurrency 20
```

单独跑：

```bash
# 判据本身能不能失败（不需要设备）
python3 scripts/effectiveness/tunnel_concurrency.py --selftest

# 本轮规则是否真的生效（行为判定，不读日志计数）
# 除最后一个参数外都必须被上游删掉，最后一个是对照、必须保留
python3 scripts/effectiveness/tunnel_concurrency.py --origin https://ORIGIN \
        --readiness track,rxparam,zs_keep_me

# 并发回归本体
python3 scripts/effectiveness/tunnel_concurrency.py --origin https://ORIGIN \
        --http-origin http://ORIGIN --tls1-origin https://ORIGIN:18444 \
        --rounds 5 --concurrency 20 --snapshot-label accept \
        --json .effectiveness/results/tunnel-concurrency.json

# 快照与收尾判定
RUN_ID=<本次 run> scripts/effectiveness/tunnel_snapshot.sh before accept
RUN_ID=<本次 run> scripts/effectiveness/tunnel_snapshot.sh settled accept
RUN_ID=<本次 run> scripts/effectiveness/tunnel_snapshot.sh check accept   # 0 收尾 / 1 未收尾 / 2 输入不可用
RUN_ID=<本次 run> scripts/effectiveness/tunnel_snapshot.sh delta accept

# 规则备份与恢复（逐字节；恢复后重读编辑器核对）
python3 scripts/effectiveness/rules_backup.py capture --out .effectiveness/results/rules.json
python3 scripts/effectiveness/rules_backup.py show    --from .effectiveness/results/rules.json
python3 scripts/effectiveness/rules_backup.py restore --from .effectiveness/results/rules.json

# 设备锁（canonical 文件；语义见 §14.6）
LOCK_OWNER=<issue> scripts/effectiveness/condition.sh status       # 含 lock: free / owner=… remaining=…
LOCK_OWNER=<issue> scripts/effectiveness/condition.sh lock-take    # 取锁并留给后续命令
LOCK_OWNER=<issue> LOCK_TOKEN=<token> scripts/effectiveness/condition.sh renew
LOCK_OWNER=<issue> LOCK_TOKEN=<token> scripts/effectiveness/condition.sh lock-release

# 工具契约测试（主机侧，无设备）
python3 -m unittest discover -s scripts/effectiveness/tests -p 'test_*.py'
```

### 14.6 设备锁、规则事务与恢复（MYS-2820 重写）

#### 设备锁：canonical 文件 + 共同临界区 + token

锁就是 `AGENTS.md` 规定、其他任务已经在读写的那个文件 **`/data/local/tmp/zshield-device.lock`**，
首行 `<issue> <ISO 时间>`：

```text
MYS-2820 2026-11-12T21:55:27Z
```

上一版把锁放在 `…lock.d/` 目录里，别的脚本看不见它。负责人实测的后果是：canonical 文件里写着另一个
活跃 issue，`lock_take` 仍然 exit 0，两台任务同时用手机。**别人看不见的锁不是锁。** 现在 canonical
文件就是锁本体；本协议自己的元数据（`issued/renewed/token`）放在旁边的 `…lock.state/meta`，互斥用的
临界区放在 `…lock.guard/`，两者都是**附加**，不替代 canonical 文件。

* **必须给归属**：`LOCK_OWNER=<issue>` 或 `--issue <issue>`，无默认值。owner 必须是裸 token（不含空格、
  引号），否则会截断 `AGENTS.md` 约定的 `<issue> <时间>` 行，直接拒绝。
* **读/验证/改在同一个临界区**：`mkdir …lock.guard` 是原子的，首次获取、过期接管、续租、释放全部在
  里面完成，由设备端的 `trap … 0` 释放。
  * 旧的「先读旧时间、再 `mv` 路径」不是原子接管：B 读完旧锁停在 `mv` 前，A 接管并写新锁，B 恢复后把
    A 的新锁移走，两个进程都 exit 0。负责人用确定性 barrier 复现过，现在这条路径不存在了。
  * **临界区获取失败立即非零，无等待**：测量脚本里无限等待就是没人能归因的挂起。
  * 崩溃留下的 guard **安全拒绝、不抢占**，并在报错里给出确切路径和 `adb shell rmdir` 的操作方式。
* **过期接管**：canonical 行的时间（ISO 或裸 epoch 秒都能解析）+ 同名 state 的更精确 `renewed` 取较大值
  判断；超过 `LOCK_TTL`（默认 7200 s）才接管。未来时间戳永不评估为过期，因此直接拒绝。
* **兼容上一版的目录锁**：`…lock.d`（旧默认路径）和 canonical 路径上的**目录**都被识别为该格式。
  活跃的拒绝、不可读的拒绝、只有过期的才在临界区内 `mv` 到 `…stale.<token>` 后删除。新代码不再写这个
  格式。
* **token 而不是只有 owner**：`renew`/`release` 只在 token 匹配时动作。一个事务在第一步取锁、后续命令
  在事务里跑，`condition.sh` 退出时不会释放这个事务的锁；同一任务跑两次也不会互相删锁。
* **写入必须回读**：`TAKEN`/`RENEWED`/`RELEASED` 只在设备端回读确认后打印。写失败、元数据写失败、回读
  不一致分别给出 `WRITE_FAILED` / `VERIFY_FAILED`，一律不是「拿到了锁」。
* **没有裁决行就是失败**：每个操作最后一行是 `TAKEN` / `TAKEN_STALE` / `HELD` / `HELD_FUTURE` /
  `HELD_LEGACY` / `HELD_UNKNOWN_FORMAT` / `GUARD_BUSY` / `RENEWED` / `RELEASED` / `NOTMINE` /
  `WRITE_FAILED` / `VERIFY_FAILED`。读不到或读不懂一律拒绝。
* **传输用 base64**：`echo <base64> | base64 -d | sh`，没有引号规则可被弄错（`printf %q` 是 bash 专有）。
* **失锁必须被主进程看到**：后台续租失败以前只结束那个子 shell，事务继续往手机写。现在失败会落一个
  marker 文件，`lock_require` 读它，后续每次设备写入都拒绝；`condition.sh` 的写操作全部走 `w_`，
  `tunnel_acceptance.sh` 在安装规则前显式 `lock_require`。收尾时撤不回来就报「未恢复」并让退出码非零。
* **「本地没见到失锁」不是「已持锁」**：`lock_require` 除了看 marker，还会向**设备**确认（`lock_verify`，
  同一临界区内读 canonical 行与 state，答案 `HELD_BY_ME` / `NOTMINE` / `EXPIRED` / `FREE`），每次写入前重新核验，
  不缓存成功。租约过期或所有者变化必须拒绝后续写入。`cleanup`、`restore`、直接规则安装都是新进程，marker 天然
  为空——上一版据此放行，实测在别人持有 canonical 锁时仍然 `DEBUG_SET_RULES` + `force-stop` 且 exit 0。
* **每个设备写入口都要持锁**：`cleanup` 与 `restore` 现在自己 `take_lock`；有效他人锁一律拒绝且零写入。
  `cleanup` **不再**发送 `DEBUG_SET_RULES ''`（那会删掉本任务没见过的规则集），改为按本任务自己的备份恢复，
  没有备份就明确「保持原样」。
* **退出状态是进程的，不是 trap 的返回值**：EXIT trap 里 `return` 不能改变退出码（shell 原本要用的状态
  优先），所以「规则没恢复」「续租子进程没回收」这类判断过去只停在输出里。现在统一：先 `trap - EXIT
  INT TERM HUP` 防重入、累积最终状态、显式 `exit "$code"`；信号走 `exit 130` 落到同一个 EXIT 入口，因此
  被信号打断的运行一定非零。`pss_idle.sh` 与 `tunnel_acceptance.sh` 同一处理。
* **续租子进程精确回收**：renewer 把每个 `sleep` 的 pid 记到文件，`lock_stop_renewer` 逐个 kill 并
  有限次确认；仍有存活则返回非零（不遗留 sleep）。EXIT/INT/TERM 都走同一条清理路径。

#### 规则事务：先备份、后写入、全部退出路径恢复

`tunnel_acceptance.sh` 的顺序是硬约束：

1. 参数与 origin 检查（不碰设备）；
2. **取锁并持有整个事务**（`lock-take` 语义，退出时才释放）；
3. **读用户规则，失败即退出**——上一步之前什么都没写；
4. 安装本轮的规则并**用行为证明**（`--readiness`）；
5. 故障自检用 `--no-install-rules`，跑在同一套规则事务里；
6. 并发回归；
7. 收尾轮询；
8. 恢复（`trap` 覆盖 EXIT/INT/TERM/HUP）。

`condition.sh` 的入口同一口径，而且这里是上一轮被打回的地方：

* `apply-test-lists` 与三个 condition 命令把 `backup_state` 当**前置条件**：读不到原规则就返回非零、
  **任何规则覆盖之前**终止、设备零写入。上一版只记 `known: false`、调用方 `|| true` 继续，
  `apply-test-lists` 于是在输出「user rules NOT restored」的同时覆盖了规则并 exit 0。
* 失败判定取自 capture 的**退出码**，不是它打印的文本。上一版 `python3 … capture | sed …` 的管道状态是
  `sed` 的，任何 capture 失败都被读成成功。
* 备份失败后不再探测隧道/HTTPS 开关：`https_state` 在日志环回绕时会重启隧道取那一行，属于设备写；
  已经决定不碰设备的运行不应为了写记录而碰它。备份文件里这两个字段记 `unknown`，不是猜。

#### 规则读取：编辑器原文，不猜

`rules_backup.py` 读的是**规则编辑器输入框的原文**，不是诊断页那行：

* `DebugActivity` 把规则渲染成 `userRules.ifBlank { "（空）" }`，于是**空集**、**纯空白**、**字面就是
  `（空）` 的规则集**在这一行上产生同一个字符串。上一版把标记映射成空串并记 `known: true`，负责人实测
  的结果是备份拿到 `''`、恢复时把用户规则**删掉**了。所谓「观察等价」不是备份。
* 编辑器由 `RulesEditorScreen.kt:57` 直接从 `FilterRepository.userRules.value` 取值（不改 UI），字段里
  就是原文，所以三者互不相同、尾部换行也在。
* 读不到、或 dump 里有 **≠1 个**可编辑字段、或两次读不一致，一律 `known: false` 并给出原因；调用方
  因此**零次 `DEBUG_SET_RULES`**。
* dump 里出现**字面** tab/CR/换行时拒绝：XML 属性值归一化会把它们折成空格，读回来已经不是用户的空白。
  这是和「`$(cat …)` 吃掉尾部换行」同一类损失，答案也相同：拒绝而不是装一个近似值。
* 只接受 `android.widget.EditText` 且带 `text` 属性的节点；同屏 `TextView`（诊断标签、提示）不是这个面。

#### 规则恢复：逐字节，并回读核对

* 规则以**文件** push 上去，再由设备端脚本读取：`V=$(cat F && printf 'X'); V=${V%X}`。
  `"$(cat F)"` 会删掉**所有尾部换行**，而 `adb shell` 会把内联参数重新过一遍 `sh`、吃掉
  `$removeparam`/`|`/`*`/`(`。脚本还会比较文件字节数与取出的字节数，不等就 `RULE_ROUNDTRIP_MISMATCH`。
* 备份 JSON 带 `sha256`、`rules_bytes`、`trailing_newlines` 和读源（`source=editor`）。恢复前校验
  sha256，备份被改过或截断就拒绝；`source=debug` 的备份一律拒绝恢复。
* 恢复后**重新读编辑器**并逐字符比较（尾部换行、实体、引号、`$`、反斜杠、多行都算），不一致报
  `MISMATCH` 并保留备份，退出码 2。
* 正常、失败、信号三种退出都证明「先备份后写、按所有权恢复」。拒绝路径不写规则。

> **仍然存在的限制**：以上全部在**主机侧**用真实 `sh` + `adb` 替身验证。编辑器导航（首页 →
> 过滤器 → 自定义规则 → 读输入框）在真实 Pixel 上的原文读取**尚未验证**，需要阶段 4 做只读核对。
> 如果真机导航或 dump 与假设不符，工具的答案就是「拒绝」，不是猜。

### 14.6b 并发：20 是「同一时刻」，不是「三条腿各 7 条」

`validate_concurrency` 现在要求**组总量**：

* 逐请求的 `inflight`（上游在到达时记录的共享计数，跨页面共用一个 counter）最大值得达到 `--concurrency`；
* `GET /__stats` 的 `peak`（上游到达/离开的运行最大值）与 `overlap`（用每个请求的
  `[at, done]` 区间**重新计算**的重叠深度）都必须达到同一数值。

两个独立数字都达标才算「20 并发」，而不是任一方自报。之前的版本只比「最忙那条腿的份额」，评审实测
7/7/6 的计划给出 `peak=7` 并通过——那正是三条腿完全不重叠时的读数。

单 target 时脚本明说改为**串行布局**：每腿满载并发、每腿执行前**重新导航**到该腿自己的 origin
（否则明文腿会从上一腿的 TLS 文档发 `fetch`，那是混合内容/CORS 失败，不是过滤结果）。

### 14.6c 导航：CDP 生命周期，不是 `location.assign` 后立刻读

`location.assign` 之后旧文档被拆掉，脚本紧接着读 `document.readyState`/`location.href` 读的是
**旧文档**，`status`/`redirected` 也只能是写死的常量。现在导航由 `cdp.Page.navigate` 完成：
`Page.frameNavigated` 给出新 `loaderId` 与最终 URL，`Network.responseReceived`（Document）给出真实
状态码，`Network.requestWillBeSent` 给出 302 链；随后再读新文档的 `document.body.innerText`。

### 14.6d 快照：run / 时刻 / 可读 / 采集完整，缺一不可

每条快照带 `run=<id>`、`at=<epoch>`、`pid`、`uid`、`readable=yes|no`、`sockets=`、`collected=k/n`、
`ok=yes|no`。`check` 要求：

* 两侧都存在且非空的 `run`/`at`/`pid`/`uid`/`readable`，且 `run` 等于本次 `RUN_ID`；
* `at` 不早于 `TIMESTAMP_SLACK`（默认 600 s），旧文件不会被当成这一次；
* `readable=yes` 且 `sockets` 不为 `UNAVAILABLE`——**读取失败与真实零连接分开编码**，
  空表（可读、没有该 uid 的行）是合法观测，可以正向通过；
* `01`/`05`/`08` 任一状态**不得增长**。应用 uid 不享受任何容差：浏览器自己的 keep-alive 记在浏览器的
  uid 上，不计到这个应用名下，所以应用名下的 ESTABLISHED 增长就是应用自己的（评审实测的 1 -> 3 现在 exit 1）。

### 14.7 已知边界（记录，不是缺陷）

* **未加类型的 `$removeparam` 只对 document 生效**：`||host^$removeparam=p` 不匹配 `fetch()`/XHR
  （官网定义如此，本 core 也照此实现）。`fetch` 驱动的用例必须写 `||host^$removeparam=p,all`。实测对照
  （`extras::RemoveParamRules::rewrite`，同一 URL）：

  ```text
  规则 ||httpbin.org^$removeparam=track     Xhr -> None      Document -> Some(...)
  规则 ||httpbin.org^$removeparam=track,all Xhr -> Some(...) Document -> Some(...)
  ```
* **`$removeparam` 只在解密连接上生效**（`core/src/http/relay.rs`：`modifiers: None` 表示明文连接）。
  明文腿因此断言参数**保留**——在那里断言删除等于断言设计禁止的行为。
* **`adb shell` 会吞掉规则里的 `$`**：规则必须**先 push 成文件**再 `--es rules "$(cat …)"`。
* **`am start` 失败不会让脚本失败**：它打到 stderr、退出码仍是 0，启动后必须显式检查；启动类是
  `.ui.MainActivity`。
* **shell uid（2000）读不到 `/proc/<pid>/fd`**，文件描述符泄漏改用**按应用 uid 统计
  `/proc/net/tcp{,6}`** 代替。`/proc/net/tcp` 读不到与「读到 0 条」是两件事，快照用 `readable=` 区分。
* **`am broadcast` 打到已强杀的应用是空操作**：切隧道要趁进程还活着。
* **`httpbin`/`httpbingo` 不能满足本轮验收**：它们不返回请求 ID，也不返回 raw body 摘要，`form` 是解析后的
  字典。用它们跑 `tunnel_concurrency.py` 会得到明确的「echo 太弱」失败，而不是静默 PASS——这是有意的。
* **`concurrency_smoke.py` 已废弃**：它测的是主机 `urllib`，什么都证明不了。现在任何调用都非零退出并指向
  `tunnel_acceptance.sh`，旧命令不会「悄悄跑出绿色」。

### 14.8 阶段 4 在真机上发现的两处测量前提（MYS-2818）

本节记录阶段 4 实测中**推翻两个默认假设**的发现。两条都不是产品缺陷，但都会让测量读错。

#### 14.8a PSS 的就绪行不能用 `hot reload finished: ok=true`

`pss_idle.sh` 的默认 `--ready-line` 是 `hot reload finished: ok=true`。这一行由
`FilterRepository.reloadIfTunnelRunning()` 打印，而该方法在 `activeHandle == 0L` 时**直接 return**：

```kotlin
private fun reloadIfTunnelRunning() {
    val handle = activeHandle
    if (handle == 0L) return
    …
    android.util.Log.i("ZShield", "hot reload finished: ok=$ok")
}
```

**在实测到的冷启动路径上**，隧道在 `reloadIfTunnelRunning()` 有机会运行之前尚未起来，`activeHandle`
是 0，因此这一行不会出现。这是由代码条件与冷启动时序共同决定的**限定结论**，不是「永远」——
规则变更发生在隧道已运行时，这一行照常打印（§14.8 末尾的 hot-reload 例子）。本轮的证据是：
冷启动 3 次、每次清空 logcat 后都只有 `compiled` / `engine loaded` / `engine started`，没有该行。
`pss_idle.sh` 于是等到 90 s 超时后正确地拒绝采样：

```text
## waiting for this launch's readiness line: hot reload finished: ok=true
FAIL: no 'hot reload finished: ok=true' from this launch within 90s; refusing to sample a non-idle process
```

**更重要的更正（阶段 4 返工）**：`engine started` **不是**「空规则」标记，不能当就绪锚点。
`core/src/jni_api.rs:862` 在隧道启动**之前**就调用 `resolve_http_filter` 加载序列化 `engine.bin`；
真机冷启动实测的顺序是 `compiled N lists` → `engine loaded in … ms, … B` → `engine started` +
`tunnel stack up`。也就是说**编译在引擎加载之前结束，引擎加载又在隧道能承载流量之前完成**，
不存在「规则还没好但请求已经放行」的窗口。上一版把 `engine started` 当成这种窗口的证据，已撤回。

现在 `pss_idle.sh` 的就绪判据见 §14.8e（MYS-2825 重写）：它要求本次启动 pid 的成功
`rules identity:` 事件，并用 `--expect-identity` 把「本轮要测的规则内容」钉死到 SHA-256 上：

```bash
LOCK_OWNER=<issue> scripts/effectiveness/pss_idle.sh <label> \
    --expect-identity-from <compiledDir>
```

#### 14.8b 重装 APK 后 HTTPS 过滤可能是 off（14 页测量前必须核对，而非假定）

本轮观察到 `adb install -r` 之后 `condition.sh status` 报 `https: off`。**这是一次观测，不是普遍规律**：
HTTPS 过滤状态由设置文档与 CA 安装态共同决定，重装是否清掉它取决于哪些数据被保留，本轮没有做
「重装 vs 不重装」的对照实验，因此只把它写成一条**必须核对**的前置检查，而不是断言重装必然重置。
需要核对的具体状态是：

- `logcat | grep "https decrypt"` → **0 条**；
- `logcat | grep "cosmetic:"` → 无注入行；
- 14 页 QUnit 读到 `element-hiding 1/17`、`extended-css 1/34` 这类**全面崩塌**的分数。

这不是产品回归，而是**没解密就没有外观注入**（因果关系有日志支持：0 条 `https decrypt`、无
`cosmetic:` 注入行）。正确顺序是：装 APK → 重新 `condition.sh zshield-https` → 确认日志出现
`https filtering: true (ca installed true, N uids` **和** `https decrypt … negotiated h2`
**和** `cosmetic: … specific, … generic` → 再测。本轮第一轮 14 页就是漏了这一步，已作废重测；
作废数据不作为证据。

#### 14.8c `tunnel_concurrency.py:1006` 的 `{{}}` 会在开腿前 abort

`open_page()` 里读协议的表达式写成了 `…||{{}}).nextHopProtocol`——`{{}}` 是 Python `str.format` 的转义，
漏进了 JavaScript。浏览器解析成 `||{{}}` 直接抛 `SyntaxError`：

```text
cdp.CdpError: JS threw: Uncaught: (performance.getEntriesByType('navigation')[0]||{{}}).nextHopProtocol
```

只要运行需要给三条腿各开一个 page target（即真实并发模式），就会在**发出任何请求之前**失败。
`cdp.py:597` 的同名表达式是正确的 `||{}`，可对照。

**阶段 4 返工已修**（负责人授权）：生产表达式改为 `||{}`；新增
`tests/test_generated_javascript.py::test_every_expression_open_page_evaluates_parses`，用
`harness_fixtures.ParsingBrowser` 驱动**真实的** `open_page`，把它实际 `evaluate` 的每个字符串交给
`node --check`，并覆盖独立 target 与单 target 回退两条分支；**先红后绿**（修复前两条分支各报
`SyntaxError: Unexpected token '{'`）。原先那条把正确字符串抄一遍的测试已删除——它正是漏报的原因。

#### 14.8f `DEBUG_TOGGLE_VPN` 是切换，不是「打开」——冷启动脚本必须先关再开

`DebugCommandReceiver.kt:96–101` 的实现是：

```kotlin
when (controller.state.value) {
    is VpnState.Running, is VpnState.Starting -> controller.stop(...)
    else -> controller.start(...)
}
```

所以广播一次是**翻转**，不是「打开」。阶段 4 首次冷启动测量没有先确认隧道是关的，当隧道已经 up 时
那一次广播把它**关掉**，被测流量根本没经过 core——读到的 74/68 分是「没有过滤」的分数，不是
「过滤还没就绪」的分数。

**判据（本次实测）**：每一轮都要看 `https decrypt` 行数。

| 情形 | `https decrypt` 行数 |
|---|---|
| 隧道被误关（流量没进 core） | **0** |
| HTTPS 条件正常解密 | 7 |
| `zshield-default` 条件（HTTPS 过滤关，应有行为） | **0** |

注意最后一行：**默认条件下 0 条 decrypt 是正确状态**，不能只凭「0 条」就判无效——必须结合条件
（`condition.sh status` 的 `https: on/off`）一起读。

**正确流程**：断言隧道 down（必要时反复广播直到 `dumpsys connectivity` 无 `IS_VPN`）→ 强杀 →
`logcat -c` → 冷启动 → 显式广播并**断言 up** → 立刻测 → 记录分数与 `https decrypt` 行数。

#### 14.8e PSS 就绪判据：证明「这套规则」在跑（MYS-2825，两轮返工后）

三版判据先后被否，原因都不是「检查得不够多」，而是**相信了不是证据的东西**：

| 版本 | 判据 | 为什么被否 |
|---|---|---|
| 一 | 等 `hot reload finished: ok=true` | 该行只在规则**变更**触发 `reloadIfTunnelRunning()` 时打印，冷启动永远不满足 |
| 二 | `engine loaded` + `engine started` + **制品字节数/规则条数** | 字节数与条数都不是内容身份：同长度、同条数、不同规则的两套规则数字完全相同 |
| 三 | 工具自己读 pid、只匹配「就绪行」文本；后来改用 `rules identity:` 但**只警告不拒绝** | 日志全来自别的进程、不存在的 `--ready-line`、末尾 `ok=false`、**未声明目标**、**缺字段的身份行**、**末次读期间换代次**、**`MEMINFO in pid 9999`** 全部 exit 0 并出中位数 |

现在的判据读的是**引擎在安装规则时自己给出的观测**（`core/src/rules_identity.rs`），并且**每一环都
按证据强度收紧**。

**正式采样必须声明目标**（启动前校验，未声明直接 exit 2，不碰设备）：

```bash
scripts/effectiveness/pss_idle.sh --identity <compiledDir>   # 先算出目标
#   dns=sha256:…:1209834 engine=sha256:…:7411949 extras=sha256:…:147360

LOCK_OWNER=<issue> scripts/effectiveness/pss_idle.sh <label> \
    --expect-identity-from <compiledDir> --samples 6
```

目标格式在**任何设备命令之前**校验：每个分量必须是 `sha256:<64 hex>:<bytes>` 或 `-`，三个分量都
必须出现，且不能全是 `-`。诊断用途必须显式 `--diagnostic`，它**不打印 `## median`**、明确写
`NOT acceptance evidence`，因此不能被当成验收结果引用。

**就绪 = 以下全部成立**：

| 事实 | 来源 | 排除了什么 |
|---|---|---|
| 本次启动 pid 至少一条**字段完整**的 `rules identity:` | logcat threadtime 的 pid 列 + 行内 `pid=`，两者必须一致 | 别的进程；上一次启动；**无 pid 列的不可归属行**；`event=start ok=true` 这种缺字段行 |
| 最后一条是 `ok=true`（`handle`/`generation` 必须为正整数） | 同上 | 加载失败却「看起来起来了」 |
| 该行之后没有失败信号、也没有**不可解析**的身份行 | `ok=false` 行、`hot reload finished: ok=false` | 热替换失败后的新旧混合态；无法读懂的后续状态 |
| `engine started` / `tunnel stack up` | 日志 | 只有进程、没有转发路径 |
| `--expect-identity` 每个分量相等；给了 `--ready-line` 时该文本出现 | 调用方声明 + 日志 | 「测的是另一套规则」 |

**启动边界是被验证的，不是被断言的**：`am force-stop`、`logcat -c`、`am start` 的**退出码**都要检查，
且不能只看退出码——`logcat -c` 成功后还要**读回缓冲**确认没有任何本工具会当作证据的行；force-stop
之后还要确认包真的没有 pid；`am start` 之后要确认进程真的起来了。主机侧记录的时间戳不能证明设备
缓冲的状态，所以结果文件里写的是「`logcat -c` exit 0 且读回 0 条证据行」。

**每个样本前后各验证一次状态，出中位数前再验证一次**：pid、handle、generation、目标内容、以及
就绪之后有无失败/不可解析事件。任何一项变化都 **整批作废**（`batch voided`，非零退出，**不打印
中位数**）。就绪前失败则 **0 次 `dumpsys`**。

**meminfo 必须属于被测进程**：按明确 PID 采样（`dumpsys meminfo <pid>`），并要求返回块恰好有**一个**
`** MEMINFO in pid N [process] **` 头、pid 等于被测 pid、进程名等于包名（或其 `pkg:` 子进程），且
恰好**一个** `TOTAL PSS`。缺头、多头、pid 不符、进程名不符都拒绝——上一版只取第一个 `TOTAL PSS`，
于是 `MEMINFO in pid 9999` 被记成 4242 的样本。

**原始证据保留**：每次采样的 `dumpsys` 原文、每次决策用的 logcat 快照、以及 force-stop / 清日志 /
启动 / 广播的输出，全部落在 `<out>/pss-<label>.raw/`，读者可以自己重算而不是相信摘要。

**回归**：`scripts/effectiveness/tests/test_pss_readiness.py`（30 例，跑真实脚本 + stub 设备）。stub
**真的执行生产命令的语义**：`am force-stop` 真删 pid、`am start` 真建 pid 并把本次启动的行写进缓冲、
`logcat -c` 真清空、`logcat -d … | grep -E '<pattern>' | tail -N` 真的应用那个 pattern 与 tail、
`am broadcast DEBUG_TOGGLE_VPN` 真翻转隧道、`dumpsys connectivity` 据此回答；故障用真失败（非零退出）
或真「成功但没做」注入。覆盖：正向对照（threadtime 格式）、未声明目标、诊断模式不出 median、目标格式
/缺分量、外来 pid、未满足 `--ready-line`、末尾失败热替换、同长度不同内容、缺字段身份行、无 pid 列、
行内 pid 与列不一致、加载失败、engine 缺失、清日志失败、清日志「成功但没清」、launch 没建进程、
force-stop 失败、同 pid 旧启动、**末次读期间换代次**、采样窗口内换进程、meminfo 错 pid / 错进程名 /
无头、缓存启动、辅助字节数、`--identity` 口径与非制品拒绝、`--identity-from` 端到端。每个新回归都做过
**变异验证**（去掉对应检查后该用例确实变红）。

#### 14.8d 受控 origin 的公网入口只有原始 TCP 隧道可用

§14.1 的结论（隧道吞掉全部 IPv4，含 LAN）在阶段 4 再次确认，并补测了三条候选路径：

| 路径 | 实测 |
|---|---|
| 主机 LAN / easytier 地址 | 不可达（超时） |
| 主机公网 IP | 不可达（无公网入向） |
| `cloudflared` / `localhost.run` quick tunnel | 本机到边缘不可达；且 TLS 在边缘终止，无端到端证据 |
| **`bore.pub`（原始 TCP）** | **可达且保留端到端 TLS**，手机 `curl` 明文 200 / TLS 200（自签需 `-k`） |

但可达 ≠ 可信：core 的上游校验用 `rustls-platform-verifier` → Android `AndroidCAStore`，
自签 origin 证书不在其中（手机 `curl` rc=60）。因此**协议矩阵仍缺 TLS 两条腿的端到端证据**，
除非 origin 拿到设备信任的证书（三条可行路径都越界，见 §15.7）。
