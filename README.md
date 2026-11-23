# ZShield 净盾

无需 root 的 Android 广告拦截与隐私防护应用。**规则匹配全部在本机完成**：应用自建本地 VPN
隧道，用本机上的规则引擎判断每个请求，没有任何过滤服务在远端参与。

但"本机过滤"不等于"零网络请求"——下面三类流量是真实存在的，说明在这里而不是留给读者猜：

| 流量 | 去往哪里 | 什么时候 |
|---|---|---|
| DNS 查询 | 你配置的 DNS 上游（默认两个 DoH：`dns.alidns.com`、`doh.pub`，可改成 DoT 或明文 UDP） | 每次域名解析。**上游能看到你查询的域名**，这是任何非本机递归解析器的固有代价 |
| 过滤列表下载 | 内置目录指向的公开镜像（`filters.adtidy.org`、`easylist.to`、`cdn.jsdelivr.net`、`anti-ad.net`、`oisd.nl` 等），以及你自己添加的订阅地址 | 首次启用列表时，以及之后每 24 h 的条件更新 |
| 你自己的正常上网流量 | 目标站点 | 隧道只是在本机内部转一圈，内容不被转发给第三方 |

除此之外没有别的连接：无遥测、无崩溃上报、无 Play Services、无统计 SDK。想做到「连 DNS 都不出本机」，
目前不支持——那需要一个本地递归解析器，本项目没有做。

> **当前阶段：公开预览（0.1.x）。** 这是一个能日常使用、但仍在打磨的版本：核心链路已经完整并通过
> 真机验证，仍有已知的性能与站点兼容限制（见下文「已知限制」）。接口、默认规则集和内置订阅都还可能
> 变化，也不承诺跨大版本的配置兼容。

- DNS 过滤（DoH / DoT / 明文 UDP 上游，CNAME 反隐藏）
- 完整本地 VPN 隧道：按连接拦截、QUIC 控制、按应用规则
- HTTPS 过滤：本机随机生成根证书，URL 规则、元素隐藏、scriptlet
- 兼容 EasyList / AdGuard / uBlock Origin 过滤语法，支持订阅
- 无遥测、无 Play Services、无统计 SDK

设计与决策见 [`docs/DESIGN.md`](docs/DESIGN.md)，里程碑见 [`docs/ROADMAP.md`](docs/ROADMAP.md)，
实测数据见 [`docs/EFFECTIVENESS.md`](docs/EFFECTIVENESS.md) 与 [`docs/PERF.md`](docs/PERF.md)。

## 系统要求

| 项 | 要求 |
|---|---|
| Android | 9.0（API 28）及以上；Android 16（API 36）为当前主要验证目标 |
| ABI | **arm64-v8a**（release 包只含这一个 ABI；x86_64 仅用于 debug 构建与模拟器） |
| 体积 | release APK ≤ 10 MB（构建脚本强制检查；v0.1.3 实测 8,461,681 字节） |
| root | 不需要 |
| 网络 | 只有三类：DNS 查询发往你配置的上游、过滤列表下载发往目录里的镜像、以及你自己的正常上网流量（见上文） |

## 安装

从 [Releases](https://github.com/zzttzzmyswy/zshield-android-public/releases) 下载 `zshield-<版本>-release.apk`
和同名 `.apk.sha256`，先校验再安装：

```bash
# 1. 校验（两个文件放在同一目录）
sha256sum -c zshield-0.1.4-release.apk.sha256
#   期望输出：zshield-0.1.4-release.apk: OK

# 2. 安装
adb install zshield-0.1.4-release.apk
#   或把 APK 传到手机后点击安装（需允许「安装未知来源应用」）
```

**覆盖安装（升级）**：`adb install -r`，或直接点击新 APK 安装。**新旧版本必须是同一个签名**——
官方 Release 的包都用同一把密钥签名，所以官方版本之间可以互相覆盖升级；如果你自己重新签名构建，那就
属于另一个签名身份，无法覆盖安装官方包，必须先卸载（会清掉应用数据、规则与已生成的根证书）。

## 首次使用

1. **开启保护**：首页一键开关。首次开启时 Android 会弹系统 VPN 授权对话框，必须同意——这是本地
   VPN 隧道的系统要求，流量只在本机内部绕一圈，不出设备。
2. **选择过滤列表**：「过滤器」页选择订阅。内置目录里的列表需要先下载并编译一次，之后启动直接加载
   编译产物。
3. **（可选）HTTPS 过滤**：见下一节。不做这一步也有 DNS + SNI 级过滤，只是看不到 URL 级规则。

建议同时在系统设置里为本应用开启「始终开启的 VPN」并忽略电池优化，否则系统在深度休眠时可能回收隧道
（应用会尝试自动恢复，但系统策略优先）。

## HTTPS 过滤与用户 CA

Android 11 起应用无法静默安装 CA 证书，因此这一步必须手动完成：

1. 在「HTTPS」页生成根证书（ECDSA P-256，有效期 10 年，名称带随机后缀；私钥用 Android Keystore
   包装的 AES 密钥加密后存在应用私有目录，导出不了）。
2. 导出 `.crt` 到「下载」目录。
3. 到系统设置里安装：**设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书**，选择刚导出的文件。
   Android 会要求确认并可能要求锁屏密码。
4. 回到应用，「HTTPS」页应显示「已安装」。

**这会带来什么**：任何信任用户 CA 的应用（多数浏览器）经本应用解密后，HTTPS 流量由本机签发的叶子
证书重新加密。仅信任系统 CA 的应用（银行、部分即时通讯、证书钉扎的应用）不受影响，仍然是 DNS + SNI
级过滤。这正是「无需 root」的边界——想拦 URL 就必须能解密，能解密就必须让客户端信任你的 CA，
而是否信任由系统与每个应用自己决定。

**HTTPS 过滤是可选且有代价的**：解密会增加内存与 CPU 开销。默认排除银行/支付/钉扎类域名与应用；
客户端握手失败时会自动把该 host 加入临时直通名单，避免断网。

## 自己构建

只有需要改代码、或不想信任预编译的 APK 时才需要这一步。

### 工具链

| 组件 | 版本 | 说明 |
|---|---|---|
| JDK | 17 | `app/build.gradle.kts` 的 `sourceCompatibility`/`targetCompatibility` 是 17；`JAVA_HOME` 指向它 |
| Android SDK | `compileSdk 36` + 对应 build-tools | `ANDROID_SDK_ROOT`（或 `ANDROID_HOME`，或 `local.properties` 的 `sdk.dir`） |
| NDK | **28.2.13676358** | 与 `app/build.gradle.kts` 的 `ndkVersionUsed` 一致；已装到 `$ANDROID_SDK/ndk/28.2.13676358` |
| Rust | **1.91 或更新**（stable） | 下限由锁定的依赖决定，不是项目自选：`Cargo.lock` 中 `smoltcp 0.14.0` 声明 `rust-version = "1.91"`，`time`/`rcgen`/`icu_*` 声明 1.88。低于 1.91 会直接拒绝构建 |
| Rust target | `aarch64-linux-android`（release）<br>`x86_64-linux-android`（debug） | 由 `app/build.gradle.kts` 的 `releaseAbis`/`debugAbis` 决定。用 `rustup target add aarch64-linux-android x86_64-linux-android` 安装 |
| cargo-ndk | 4.x | `cargo install cargo-ndk`（构建时由 Gradle 任务调用） |
| Node.js | 20+ | 只有 `scripts/check-procedural-runtime.mjs` 需要（诊断用，不参与 APK 构建）；另需 `npm install jsdom` |
| 其他 | `unzip`、`keytool` | 尺寸报告与签名 |

本仓库在 Rust **1.98.0**、cargo-ndk **4.1.2**、JDK 17、SDK/NDK 如上、Node 26 的组合上实际构建通过；
1.91 只是依赖声明的下限，未逐版本验证。

`scripts/build.sh` 会自己找 SDK、NDK 与 JDK 17：先看 `ANDROID_SDK_ROOT`/`ANDROID_HOME`，再看
`local.properties` 的 `sdk.dir`，最后试常见安装位置；JDK 依次试 `/usr/lib/jvm/java-17-openjdk`、
`-amd64` 与 macOS 的 Temurin 路径。都找不到才报错并说明要设哪个变量。

### 命令

```bash
git clone https://github.com/zzttzzmyswy/zshield-android-public.git
cd zshield-android-public

# 签名材料必须在仓库外。官方身份在本项目维护者手里；你自己构建就用自己的：
ZSHIELD_KEYSTORE_DIR="$HOME/.config/zshield-contributor" scripts/gen-keystore.sh

# 构建（release 会先跑 lintRelease，再打包并检查 10 MB 预算）
ZSHIELD_KEYSTORE_DIR="$HOME/.config/zshield-contributor" scripts/build.sh release
# 产物：dist/zshield-<版本>-release.apk
```

`ZSHIELD_KEYSTORE_DIR` 把密钥目录换到别处，`ZSHIELD_RELEASE_KEYSTORE` / `ZSHIELD_KEYSTORE_PROPERTIES`
可以分别指定两个文件。**不要**把密钥放进仓库（`.gitignore` 已排除常见后缀，但更稳妥的做法是根本
不放在工作树里）。

### 关于自行签名

自己签名的 APK 属于**你自己的身份**：

- 可以装在任何设备上，也能覆盖你自己之前签的同密钥版本；
- **不能**覆盖安装官方 Release 的包，反之亦然 —— 签名不同，Android 会拒绝；
- 因此从官方包切换到自签包（或反过来）必须先卸载，会丢失应用数据、自定义规则与已生成的根证书。

构建时的绝对路径不会进入产物：`scripts/build.sh` 用 `--remap-path-prefix` 把构建机主目录、cargo
registry 与项目路径重映射成固定前缀，所以两台不同机器构建出的原生库连调试字符串都一致。

## 贡献

见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。简版：开分支 → 改代码 → 跑测试 → 提 PR。UI 视觉层由维护者
统一负责，改动前先开 issue 说明。

## 已知限制

这些是**当前版本真实存在**的问题，写在这里而不是藏起来：

### 内存

后台空闲 PSS 有一道门槛：固定五张 AdGuard 列表下 **≤ 84.6 MiB**。这个门槛没有为发布而调整。

下表只列 v0.1.3 候选包 `62fbbf2`（即已发布的 `1ecc502b…`）在**同一台设备、同一套方法**下的实测值，
逐条可在 [`docs/EFFECTIVENESS.md`](docs/EFFECTIVENESS.md) §17–19 的原始 meminfo 中复算：

| 条件（v0.1.3） | 六次 PSS 中位 | 判定 |
|---|---|---|
| 固定五表，重装后强杀→启动→Home 静置 90 s | **86.199 MiB** | **未达标**（> 84.6 MiB） |
| 固定五表，前台确认后 Home 静置 90 s | **88.784 MiB** | **未达标** |
| 默认九表 | **95.464 MiB** | 观测值，未设验收门槛 |

也就是说，**以项目自己的判据衡量，v0.1.3 的五表内存没有达标**，是在 MYSWY 明确知情并授权的情况下
发布的（决定记录见 §19）。表中两组五表数字是同一候选的两次独立窗口，都保留，不取其中较低的一组当作
结论；两组都高于门槛，因此「未达标」这个判定与取哪组无关。

关于对照组：§17 另有官方 v0.1.2 在同内容配置下的实测（五表 90.867 MiB、九表 99.237 MiB），
它是**同一台设备上的旧版本对照**，两者相减只说明这一次的相对变化，不构成跨版本或跨机器的通用结论。
本项目没有在多台机器上重复过这组测量，因此本文不给出「新版比旧版省多少内存」的说法。

后续目标是继续降低固定规则下的后台 PSS。完整数据、失败记录与前置检查拒绝记录都在
[`docs/EFFECTIVENESS.md`](docs/EFFECTIVENESS.md) §17–19 与 [`docs/PERF.md`](docs/PERF.md)。
不要把这几个数字读成「无内存泄漏」——它们只说明指定输入下的实测值，不构成全局结论。

### 站点兼容

- **CNN、Stack Overflow**：开启保护后页面不能完整加载（Stack Overflow 停在安全验证页）。这两个在
  更早版本的源码上同样复现，属于尚未定位的兼容性问题，不是本版引入的。**不要**把它们描述成「站点
  正常」。
- **京东**：出现协议错误。
- 20 站对照测量的结论是「无新增破版信号」，不是「所有站点业务功能全部通过」。

### 过滤效果

公开测试页的实测分数（v0.1.3，Pixel 5 / Android 16）：

| 测试 | 结果 |
|---|---|
| `adblock-tester.com`（HTTPS 过滤开启） | 96/100 |
| `testcases.agrd.dev` 14 页合计 | 48/115 |
| 关注误杀：20 站对照 | 无新增破版信号 |

分数不等于体验：公开测试页覆盖的是规则语法与元素隐藏的边角，日常的中文站点广告拦截效果与这些
数字不是一回事。原始逐项数据在 [`docs/EFFECTIVENESS.md`](docs/EFFECTIVENESS.md)。

### 其他

- 只发布 arm64-v8a：32 位设备与 x86 设备需要自己从源码构建。
- 不做遥测，所以维护者看不到你的崩溃——遇到问题请开 issue 并附日志。
- 项目不使用 GitHub Actions；测试与构建都在维护者的机器上完成，因此 PR 的 CI 状态是空的，这属于
  预期。

## 许可证

GPL-3.0-or-later，见 [`LICENSE`](LICENSE)。第三方组件与随包分发的过滤资源见
[`docs/THIRD_PARTY.md`](docs/THIRD_PARTY.md)。
