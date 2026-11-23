# extras 单独变化时的重载身份（MYS-2859）

`Native.reload` 在 `extras.txt` 单独变化时会错误地提前返回，导致新的 `$removeparam` 等规则不生效。
本卡修复该误判，并保证「三类制品完全未变」时的跳过路径仍然保留。本文记录复现、根因、修复范围、
失败语义、验证证据与剩余设备验收。**没有** 做 Pixel/CA/PIN 操作，也**没有** 部署、合并或发布。

## 复现

负责人在 `61ea5a8`（生产代码与 `i2-device-final-evidence` 分支 HEAD 相同）用真实
`jni_api::start_engine → compile_request → reload_engine` 路径复现，输出：

```json
{"extras_changed":true,"fingerprint_equal":true,"reload_returned":true}
```

日志同时出现 `rules reload: artifacts unchanged, keeping the loaded rule sets`，且没有新的安装代次。

复现方式（本轮已固化为可断言的控制，见下）：先编译
`||example.test^$xmlhttprequest,removeparam=/^old=/` 并启动引擎，再编译
`||example.test^$xmlhttprequest,removeparam=/^new=/` 并调用同一 handle 的 `reload_engine`。
两条规则都只存在于 `extras.txt`（adblock 引擎不接受 `$removeparam=/regex/` 这一形态），
所以 `dns.bin` 与 `engine.bin` 两次编译后逐字节相同，只有 `extras.txt` 变化。

## 根因

`core/src/jni_api.rs` 的 `ArtifactFingerprint` 只包含 `dns.bin` 与 `engine.bin` 的
`(payload 长度, CRC32)`；`reload_engine` 用它判断「制品没变」并直接返回 `true`。`extras.txt` 不在
判据里，因此一条 `$removeparam`/`$popup`/`$denyallow` 规则的编辑被完全忽略。

同一处还有一个相关的失败语义问题：旧代码在 `extras.txt` 无法读取时装入**空**规则集，然后仍然
写入新的 fingerprint。后果是用户已有的修饰规则被静默删除，且错误不会被重试——下一次 compile 写出
同样的 `dns.bin`/`engine.bin` 后 fingerprint 匹配，重载继续跳过。

## 修复范围

只改两个文件（外加一个宿主控制 example 与本文）：

- `core/src/jni_api.rs`
  - `ArtifactFingerprint` 增加 `extras: Option<(u32, u32)>`，由 `read_extras_identity` 填充：
    文件不存在 → `Some(None)`（合法空态）；可解码 → `Some(Some(..))`；
    **存在但不可用 → `None`**，使整个 fingerprint 为 `None`，调用方因此不会跳过。
  - `reload_engine` 在交换任何东西**之前**用新函数 `load_extra_modifiers_checked` 决定
    「装什么、记什么」，两者取自同一个值 `ExtrasPlan`，不可能互相矛盾。
  - 只有三类制品全部成功安装时才记录 fingerprint；任一组件的失败都把
    `loaded_artifacts` 置为 `None`，使下一次调用可以重试。
  - 失败时 `reload_engine` 返回 `false`（并写 `lastError()`），不再用 `true` 冒充「已安装」。
- `core/src/compile.rs`
  - 新增 `ExtrasLoad { Missing, Loaded, Unusable }` 与 `load_extra_modifiers_checked`，
    把「缺失 / 有效空 / 损坏」三态显式区分。
  - `load_extra_modifiers_with_identity` 改为基于它实现，**start 路径语义不变**：
    `extras.txt` 损坏仍降级为「无额外修饰规则」，隧道照常起来。
- `core/examples/extras_reload_identity.rs`：宿主控制，一次性跑 28 条断言（见「验证」）。
- `docs/I2_EXTRAS_RELOAD.md`：本文。

未改动：`removeparam` 求值语义、HTTP/HTTPS 策略、过滤列表、UI/Kotlin、`version.properties`、
DESIGN/ROADMAP/EFFECTIVENESS。

## 与任务卡的偏差

1. **`docs/JNI.md` 未改**（该文件不在允许范围内）。它第 1 节 `reload(handle, compiledDir)` 一行仍写
   「替换**两套**规则（`dns.bin` 与 `engine.bin`）」且未说明返回值在部分失败时为 `false`。本卡的新契约
   记在本文，`docs/JNI.md` 的同步留给负责人在 review 时一并处理。
2. **`core/examples/extras_reload_identity.rs`**：任务卡允许「`core/tests/` 或单独测试模块」。
   本仓库没有 `core/tests/`，既有做法是把宿主控制放在 `core/examples/`（`review_i2.rs`、
   `review_identity.rs`、`removeparam_path.rs` 等），因此沿用该位置。它只被显式 `cargo run` 调用，
   不参与构建产物。
3. **`reload_engine` 返回值变严**：见上文「语义」小节。这是为满足任务卡「不以返回 true 冒充所有部分都已安装」
   所必需，但它确实改变了一个既有行为，对应测试断言已按 `docs/JNI.md` 既有契约更新。

## 语义：缺失 / 有效空 / 损坏

| 磁盘状态 | 旧行为 | 新行为 |
|---|---|---|
| 无 `extras.txt` | 装入空集，记 `extras=None` | 不变（合法的「无规则」态） |
| 空 payload（compile 没找到修饰规则） | 装入空集，记空内容的 identity | 不变；identity 为 `bytes=0` |
| 存在但不可用（magic/版本/截断/CRC/非 UTF-8） | 装入**空集**、仍记新 fingerprint | 不装入，保留在用规则，`ok=false`、返回 `false`、不记 fingerprint，下次重试 |

`reload_engine` 返回值：`true` 仅当三类制品全部按编译结果生效。DNS 已换、engine 或 extras 失败时
返回 `false`——「生效的规则集不是刚编译出来的那一套」，这正是 Kotlin 侧
`CompileState.Failed(lastError)` 要表达的状态。这会改变一个既有行为：旧代码在
「DNS 换成功、engine 不可用」时返回 `true`。相应测试
（`a_partial_swap_is_reported_as_the_mixture_it_is`）的断言已按 `docs/JNI.md`
「失败返回 false」的既有契约更新，混合态本身仍由 identity/generation 如实记录。

快速跳过路径保留：三类制品全部逐字节相同（且 `extras.txt` 可解码）时不重建任何规则对象。

## 初次交付验证（dc9f50d）

宿主，release profile，UnixDatagram 假 TUN（tokio 可注册，非 `/dev/null`），全部同步跑完并 stop。

1. 控制程序 `core/examples/extras_reload_identity.rs`：**28/28 PASS**，退出码 0。
   覆盖 extras-only 更新、四种 transition（新增/改内容/清空/删除）、损坏后保留与重试、
   20 次 unchanged 复用同一 `Arc`、A/B 交替 12 轮。
   同一程序在**未修复**的 `61ea5a8` 上：**17 passed / 11 failed**，退出码 1。
   red/green 原始输出见证据包 `red-controls.log` / `green-controls.log`。
2. `cargo test --manifest-path core/Cargo.toml`：**779 passed / 0 failed**（耗时约 5.6 s）。
   新增 6 个集成回归，均在真实 `compile_request → start_engine → reload_engine` 路径上断言，
   并且通过生产求值入口 `HttpsModifiers::edits` 检查实际删参结果（不是只看返回值）。
3. `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings`：无警告，退出码 0。
4. `node scripts/check-procedural-runtime.mjs`：**21/21 passed**。

已知与本卡无关的既有不稳定项：`cosmetic::inject_tests::the_injection_latency_budget_is_met`
（注入延迟上限断言）在本机负载下偶发失败。它在**未修改**的 `61ea5a8` 基线上同样复现
（基线 6 次中 4 次失败，本分支 8 次中 2 次失败），断言内容是 p50 延迟 < 20 ms，与本卡改动路径无关。
报告里给出的 779/779 是一次全绿运行；交付时请以此为基线，但不要把它当成「该测试稳定」。

## 证据包

`docs/reviews/mys2859-extras-reload/`：red/green 控制输出、`cargo test`/clippy/node 原始日志、
源码 SHA 与 `MANIFEST`。其中源码 SHA 对应初次交付 dc9f50d，后续修改应以各自提交为准。
不含私钥、CA 或签名材料。

## 负责人复核补充（2026-11-14）

已同步 `docs/JNI.md` 的三类制品、部分失败与返回值契约。
原宿主程序的 `mem::forget(peer)` 会让每组控制遗留一个 FD；新增资源检查后
复现为28条行为断言通过、5条收尾断言失败。改为持有对端至 stop 后关闭，并验证句柄消失，
33条控制全部通过，五组 FD/线程均从 `[4, 1]` 回到 `[4, 1]`。
这些观测仅适用于该宿主程序，不能替代真实连接并发或设备收尾验收。
默认并行全量测试两次均为778/779，注入延迟p50分别20.29/20.80ms；未放宽20ms断言。
串行全量在原交付树及集成候选树均为779/779（50.69s、52.36s）；clippy与JS21/21通过。
本次按串行完整用例评审重载功能，保留并行计时失败记录，不将其报告为默认命令全绿。

## 剩余设备验收（不在本卡）

本卡只证明宿主重载簿记正确。以下仍属阶段 8/9，不由本轮宣称：
Pixel 5 上真实 VPN 会话中改一条 `$removeparam` 后 HTTPS 页面的实际行为、并发重载下的稳定性、
PSS/内存归因、TLS 公网入口。
