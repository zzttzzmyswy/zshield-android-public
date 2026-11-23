# ZShield (净盾) 总体设计

> 状态：v1 设计基线（2026-11-07，技术负责人-贵）。修改本文件中的「固定决策」需要在对应 issue 中说明理由，并经技术负责人确认。

## 1. 目标与验收口径

在 Android（minSdk 28，targetSdk 36，重点保障 Android 16）上提供不低于 AdGuard for Android 的广告拦截与隐私防护能力，**无需 root**。

| 维度 | 目标 | 验收口径（可执行） |
|---|---|---|
| 过滤效果 | ≥ AdGuard 同等配置 | AdGuard 公开测试用例 `https://testcases.agrd.dev` 通过率、`adblock-tester.com` 得分、国内外 20 个常用网站的拦截数与不破版对照（`scripts/effectiveness/`）。不在真机上与 AdGuard 做同条件直接对比（MYSWY 2026-11-09 决定） |
| 规则兼容 | EasyList / AdGuard / uBO 语法主体 | 内置订阅全部能解析，不支持的规则计数并上报到「规则统计」 |
| HTTPS 过滤 | 自生成随机根证书，按域名签发叶子证书 | 信任用户 CA 的浏览器中，HTTPS 页面上的路径级规则、元素隐藏、scriptlet 生效 |
| 后台保活 | Android 16 上长期运行 | Pixel 5（A16，API 36）上通过 Doze 强制、受限待机桶、进程被杀、重启、升级等场景回归（见第 7 节） |
| 能耗 | 不以过滤效果换省电 | `dumpsys batterystats` 对比无 VPN 基线，24h 屏幕关闭待机额外耗电记录在 `docs/PERF.md` |
| 安装包 | 足够小 | release arm64-v8a APK ≤ 10 MB（构建脚本强制检查） |
| UI | 明了清晰、易用 | 首页一键开关 + 拦截统计；三级以内到达所有设置 |

## 2. 总体架构

```
┌──────────────── Android app (Kotlin) ────────────────┐
│ UI (Jetpack Compose, Material 3)  ← 技术负责人亲自实现 │
│ ViewModel / Repository                                │
│ FilterManager  订阅目录、下载、更新(JobScheduler)、编译│
│ ZShieldVpnService  建立 TUN、前台通知、保活            │
│ CertManager    根证书生成/导出/安装引导                │
│            │ JNI (单一入口类 top.zztweb.zshield.core.Native)  │
└────────────┼─────────────────────────────────────────┘
┌────────────▼────────── Rust core (libzshield.so) ─────┐
│ tun: 用户态 TCP/IP 栈（ipstack + tokio）               │
│ dns: 拦截 → 规则匹配 → DoH/DoT/UDP 上游 → 缓存          │
│ engine: adblock-rust（网络规则 + 元素隐藏 + scriptlet） │
│ proxy: 连接分流（直通 / 拦截 / HTTPS 解密过滤）        │
│ mitm: rcgen 签发 + rustls 服务端/客户端 + hyper H1/H2   │
│ stats: 计数与请求日志（环形缓冲，按需拉取）            │
└───────────────────────────────────────────────────────┘
```

## 3. 固定决策

1. **标识**：applicationId 与 Kotlin 包均为 `top.zztweb.zshield`（名称为暂定，开源前可改）。仓库 `zzttzzmyswy/zshield-android`，暂为私有。
2. **语言分层**：所有数据面（包处理、DNS、规则匹配、TLS）在 Rust core；Kotlin 只做控制面与 UI。JNI 仅通过 `top.zztweb.zshield.core.Native` 一个类，接口用 JSON 字符串或基本类型，避免大量 JNI 对象往返。
3. **构建**：Gradle（Kotlin DSL）+ AGP 最新稳定版；Rust 通过 `cargo-ndk` 构建，由 Gradle 任务调用；release 只打 `arm64-v8a`（调试可加 `x86_64`）。Rust release profile：`opt-level="z"`、`lto=true`、`codegen-units=1`、`panic="abort"`、`strip=true`。启用 R8 + 资源压缩。不引入 Firebase / Play Services / 任何统计 SDK。
4. **VPN 路由**：
   - 本应用自身 `addDisallowedApplication(自身包名)`，core 的出站 socket 天然绕过隧道，不需要 JNI `protect()` 回调。
   - 虚拟 DNS 地址固定（IPv4 `10.111.222.2`，IPv6 `fd00:7a73::2`），TUN 地址 `10.111.222.1/30` 与 `fd00:7a73::1/126`，MTU 1500。
   - 两种模式：**完整模式**（默认，路由 `0.0.0.0/0` 与 `::/0`，支持 HTTPS 过滤与按连接拦截）与 **仅 DNS 模式**（只路由虚拟 DNS 地址，作为兼容/省电选项）。
   - 被过滤应用的 QUIC（UDP 443）默认丢弃，迫使回退到 TCP/TLS，以便过滤（与 AdGuard 行为一致）。
   - 支持按应用排除（白名单）与按应用仅过滤 DNS。
5. **DNS**：拦截发往虚拟 DNS 的查询；规则匹配支持 hosts 格式、`||domain^`、`@@`、`$important`、`$badfilter`、`$dnsrewrite`；**CNAME 反隐藏**（对应答中的 CNAME 链逐个匹配）；拦截应答默认 `0.0.0.0`/`::`（可选 NXDOMAIN/REFUSED）。上游默认 DoH（可配置 DoH/DoT/明文 UDP，带 bootstrap IP），带 TTL 缓存与乐观缓存。
6. **规则引擎**：使用 Brave `adblock` crate（MPL-2.0）。订阅编译后的引擎序列化到 app 私有目录，启动时直接反序列化，避免每次启动解析文本。AdGuard 专有而 adblock-rust 不支持的修饰符，按「出现频次 × 影响」排序后逐步自研补齐，未支持规则必须计数可见。
7. **HTTPS 过滤**：
   - 首次启用时生成随机根 CA（ECDSA P-256，有效期 10 年，CN 带随机后缀），私钥用 Android Keystore 包装的 AES 密钥加密后存储于 app 私有目录；支持「重新生成」。
   - 叶子证书按 SNI 即时签发并 LRU 缓存。出站校验使用 `rustls-platform-verifier`（走 Android 系统信任库），**绝不对上游放宽校验**。
   - Android 11+ 无法由应用静默安装 CA：导出 `.crt` 到「下载」并引导用户到系统设置安装。非 root 时只有信任用户 CA 的应用（多数浏览器）会被解密；其余应用仍享受 DNS + SNI 级过滤。root 场景（系统证书目录）列为后续可选项。
   - 默认排除：银行/支付/证书钉扎类域名与应用；客户端握手失败（不信任我们的 CA）时，该 host 自动进入临时直通名单，避免断网。
   - 解密后在 HTTP/1.1 与 HTTP/2 上做：完整 URL 网络规则、`$removeparam`、`$removeheader`、`$csp`、`$redirect`，以及向 HTML 注入元素隐藏样式与 scriptlet。
8. **订阅**：内置目录（EasyList、EasyPrivacy、AdGuard Base/Tracking/Mobile/Annoyances/Chinese、EasyList China、uBlock filters 全家、Peter Lowe、URLhaus、HaGeZi、OISD、anti-AD 等），支持 URL / 本地文件导入、自定义规则、`!#include`、ETag/Last-Modified 条件更新；平台 JobScheduler 周期更新（默认 24h，可设仅 Wi-Fi；不引入 WorkManager 以控制体积）。
9. **保活**：前台服务 + 常驻通知（显示拦截计数）；引导开启系统「始终开启的 VPN」与忽略电池优化；`BOOT_COMPLETED` / `MY_PACKAGE_REPLACED` 自动恢复；`onRevoke` 正确处理；Quick Settings 磁贴；JobScheduler 周期自检。前台服务类型以官方文档为准并在 Pixel 5 A16 上验证。
10. **能耗原则**：事件驱动（epoll，不轮询）；tokio 运行时线程数受控（默认 2）；直通连接走零拷贝/大缓冲双向转发；DNS 缓存；屏幕关闭时不做任何定时 UI 统计推送。
11. **隐私**：除下载过滤列表和用户配置的 DNS 上游外，应用不发起任何网络请求；无遥测、无崩溃上报。
12. **许可证与开源**（MYSWY 2026-11-09 决定）：项目整体采用 **GPL-3.0-or-later**（见 `LICENSE`），第三方组件见 `docs/THIRD_PARTY.md`。与 uBlock Origin 的关系要写准：uBO 是 **GPL-3.0-or-later**，不是 GPL-3.0-only —— 其 `src/js/contentscript-extra.js`（1.76.0）声明「either version 3 of the License, or (at your option) any later version」，scriptlet 与过程式过滤语义都按该条款使用，因此本项目采用 `or-later` 与上游一致。仓库**何时公开由 MYSWY 单独确认**：原计划是第一个稳定版（v1.0.0）之后，2026-11-23 MYSWY 要求提前做公开预览，故先准备 0.1.x 公开预览（0.1.4 起，`README.md` 说明预览定位与已知限制）；这不等于已授权公开。许可证与第三方归属核对、仓库可见性变更、历史改写各自仍需 MYSWY 确认，公开前必须完成 ROADMAP「M6 开源准备」中尚未完成的检查项（尤其①全量历史扫描与②提交作者邮箱处理）。

## 4. 仓库结构（目标）

```
app/            Android 应用（Kotlin）
core/           Rust core crate（cdylib：libzshield.so）
scripts/        build.sh（清理旧包→构建→尺寸检查）、device-test.sh 等
docs/           DESIGN.md、ROADMAP.md、PERF.md、TESTING.md
version.properties   唯一版本源（versionName/versionCode）
```

## 5. 构建与发布纪律

- **编译前删除旧包**：`scripts/build.sh` 第一步删除 `app/build/outputs/`、`dist/` 下旧 APK 和旧的 `jniLibs` 产物，产物只保留当前版本。
- 版本唯一来源 `version.properties`；影响 APK 的改动发布新版本（GitHub Release 附 APK + SHA256），禁止 `--clobber` 覆盖同版本资产。
- 签名：release keystore 保存在仓库外 `~/.config/zshield/release.jks`（密码在同目录 `keystore.properties`，不入库）。
- 不使用 GitHub Actions，以本地构建 + Pixel 5 真机测试为准（构建机要求见 `README.md`）。

## 6. 测试设备

- Pixel 5（redfin），Android 16 / API 36。设备序列号由 `SERIAL` 环境变量提供（`scripts/effectiveness/device-serial.sh`：显式值优先，否则要求恰好连接一台设备，多台或零台即拒绝），仓库不记录任何具体地址。设备上默认无浏览器，HTTPS/元素隐藏验证需安装测试浏览器（如 Firefox 或 Chromium 稳定版 APK）。
- 每次真机测试前卸载旧测试包或覆盖安装同签名包，测试后保持设备干净（不遗留调试 CA 以外的修改）。

## 7. 后台保活回归场景（M4 必须全部通过）

1. `adb shell dumpsys deviceidle force-idle` 后 30 分钟，DNS 拦截仍生效；
2. `adb shell am set-standby-bucket top.zztweb.zshield restricted` 后服务仍在；
3. `adb shell am kill` / 低内存杀进程后自动恢复；
4. 设备重启后自动恢复（含「始终开启的 VPN」开/关两种情况）；
5. 覆盖安装升级后自动恢复；
6. 网络切换（Wi-Fi ↔ 移动数据 ↔ 飞行模式）后恢复；
7. 屏幕关闭 8 小时浸泡，记录耗电与唤醒次数。
