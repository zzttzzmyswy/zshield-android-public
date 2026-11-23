# 第三方资源、许可证与归属

本文件是 ZShield **分发义务的登记表**：随源码和 APK 一起提供的每一样第三方内容，在哪个版本、
以什么条款、版权归谁、义务落在哪里。新增任何随包分发的第三方内容必须在此登记（见文末「记录纪律」）。

- 本仓库整体授权：**GPL-3.0-or-later**。正文在 `LICENSE`（GNU GPL v3 逐字副本）；项目声明在
  `README.md` 与 `core/Cargo.toml`。
- 登记的基线：`version.properties` 的 `0.1.3` / `versionCode 15`（提交
  `451d12fd95719c6644793d42a0c0d0e27f230684`）。下一候选 `0.1.4` / `16` 沿用同一份清单。
- 两条分发路径：**公开源码**与**分发 APK**。义务落点不同，分别在 §1 与 §6 说明。

## 0. 结论速览

| 问题 | 结论 |
|---|---|
| 整个项目能不能用 GPL-3.0-or-later？ | 能。带 copyleft 的随包内容只有 uBlock Origin scriptlet（GPL-3.0-**or-later**）与 adblock 等 5 个 MPL-2.0 crate（可再许可为 GPL）。两者都与 GPL-3.0-or-later 兼容。 |
| 有没有不兼容的组件？ | 没有。139 个 Rust 运行时 crate、74 个 Android 运行时构件、随包资源逐个核对；最严格的条款是 MPL-2.0 与 GPL-3.0-or-later，均可与 GPL-3.0-or-later 组合。 |
| `LICENSE` 正文可用吗？ | 可用。已换成 gnu.org 的逐字正文（§2）。原文件不是逐字副本，见 §2 的差异说明。 |
| 生成文件保留了上游版权头吗？ | 保留了。113 个条目来自 28 个 uBO 文件，生成文件头部逐文件列出各自的版权行（§3.3）。 |
| APK 里有没有通知？ | 有。`app/src/main/assets/licenses/` 共 120 个文件：118 份上游条款文件 + 索引 + GPL 正文（§6）。 |
| 条款文件从哪来？ | 从各 crate **发布包里的原始文件逐字节复制**，不是自拟的 SPDX 模板。复合包（如 `ring`）的全部引用文件与嵌套文件都在包内（§6.2）。 |

## 1. 义务落点

| 义务 | 落点 | 谁在用 |
|---|---|---|
| 许可证正文 | 仓库根 `LICENSE`；APK `assets/licenses/GPL-3.0-or-later.txt` | 源码读者、APK 接收者 |
| 版权与来源声明 | 本文件；APK `assets/licenses/THIRD-PARTY-NOTICES.txt` 及其指向的条款文件 | 同上 |
| 对应源码 | 见 §9 | APK 接收者 |

## 2. 项目自身的许可证正文

- `LICENSE` = gnu.org 的 `gpl-3.0.txt`，**逐字节一致**：
  `sha256sum LICENSE` → `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`，
  674 行 / 35149 字节，与 <https://www.gnu.org/licenses/gpl-3.0.txt> 相同。
- 替换前的正文不是逐字副本：条款被合并成单行长段落（232 行 / 34674 字节），并把
  `Copyright (C) 2007` 写成 `Copyright © 2007`、末尾链接写成 `gnu.org/philosophy/why-not-lgpl.html`
  （该地址 301 跳到 `/licenses/`，页面等价但不是逐字）。条款本身没变，但 GPL 自己要求许可证文档
  不得修改，所以必须恢复。
- `LICENSE` 只放逐字正文，不放项目声明——把声明混进正文会让「正文未被修改」无法核验。
- README 的许可证声明由 MYS-3034 补充（`README.md` §许可证），本卡不改该文件。

## 3. uBlock Origin scriptlet（GPL-3.0-or-later，**随包分发**）

### 3.1 来源与锁定

| 项 | 值 |
|---|---|
| 上游 | <https://github.com/gorhill/uBlock> |
| 标签 | `1.76.0` |
| 提交 | `aa9236cb351e369cbb68113dbe8175b87f3cd134` |
| 许可证 | GPL-3.0-**or-later**（每个源文件头部都是「either version 3 … or any later version」） |
| 版权 | `Copyright (C) 2019-present Raymond Hill`，部分较新文件为 2022 / 2025 / 2026（见 §3.3） |
| 落点 | `core/src/cosmetic/scriptlet-resources.rs` → 编译进 `libzshield.so` |

**条款不是 `-only`**：按每个源文件的头部措辞判断，不是按仓库 badge（写 `GPLv3`）或
`package.json`（写 `GPLv3`）判断——两者都不构成条款选择。这是整个作品能用 GPL-3.0-or-later 的前提。

### 3.2 收录范围

生成器取**非 trusted** scriptlet（`requiresTrust !== true`）：**63 个 scriptlet + 50 个 helper**，
合计 **188,970 字节** JavaScript。`trusted-` 开头的 28 个不收录：adblock-rust 用默认权限编译列表
（`PermissionMask::default()`），trusted scriptlet 永不可能被注入。

### 3.3 逐项归属

113 个条目分布在 **28 个上游文件**里，各文件版权年份不同，因此逐条记录，不能统一盖一个年份。
生成器按「函数体逐字匹配」定位来源文件；匹配数 ≠ 1 时**拒绝生成**（0 匹配 = 函数体在加载时被改写；
>1 = 无法区分两个文件，两种情况下归属都是猜测）。

| 上游文件 | 条目数 | 版权行 |
|---|---|---|
| `src/js/resources/json-edit.js` | 27 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/scriptlets.js` | 22 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/utils.js` | 11 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/cookie.js` | 6 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/json-prune.js` | 4 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/prevent-settimeout.js` | 4 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/prevent-xhr.js` | 4 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/attribute.js` | 3 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/localstorage.js` | 3 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/proxy-apply.js` | 3 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/set-constant.js` | 3 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/abort-current-script.js` | 2 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/object-prune.js` | 2 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/prevent-fetch.js` | 2 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/prevent-innerHTML.js` | 2 | `Copyright (C) 2025-present Raymond Hill` |
| `src/js/resources/run-at.js` | 2 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/stack-trace.js` | 2 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/href-sanitizer.js` | 1 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/noeval.js` | 1 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/prevent-addeventlistener.js` | 1 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/prevent-bab.js` | 1 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/prevent-dialog.js` | 1 | `Copyright (C) 2025-present Raymond Hill` |
| `src/js/resources/prevent-navigation.js` | 1 | `Copyright (C) 2026-present Raymond Hill` |
| `src/js/resources/safe-self.js` | 1 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/spoof-css.js` | 1 | `Copyright (C) 2019-present Raymond Hill` |
| `src/js/resources/vod.js` | 1 | `Copyright (C) 2026-present Raymond Hill` |
| `src/js/jsonpath.js` | 1 | `Copyright (C) 2025-present Raymond Hill` |
| `src/js/urlskip.js` | 1 | `Copyright (C) 2022-present Raymond Hill` |

这张表写在**生成文件的头部注释**里（每条一行）。它不进运行时：`.so` 里没有注释，把这些字段做成
结构体字段要么增加体积、要么被编译器当作无用数据消除——后者更糟，因为义务会落在没人能核验的
数据上。随包的通知改由 `app/src/main/assets/licenses/` 承担，两个测试分别断言生成文件头部完整
（`the_header_keeps_each_upstream_files_own_copyright`）与通知文件覆盖同一组文件
（`the_notices_list_the_same_ub_origin_files_as_the_generated_header`）。

### 3.4 重新生成（首选修改形式）

```bash
git clone --depth 1 --branch 1.76.0 https://github.com/gorhill/uBlock /tmp/uBlock
node scripts/gen-scriptlet-resources.mjs /tmp/uBlock > /tmp/regenerated.rs
cmp /tmp/regenerated.rs core/src/cosmetic/scriptlet-resources.rs && echo "与仓库内容逐字节一致"
```

生成是确定性的，这条 `cmp` 是有效的完整性校验。预期 stderr：
`generated 63 scriptlets + 50 helpers, 188970 bytes of JavaScript, 28 upstream files`。
脚本从 checkout 的 **git tag** 读版本、从 `HEAD` 读提交；未打 tag 的 checkout 会拒绝生成
（否则文件头会盖章一个不存在的版本）。

GPL-3.0 §6 要求「修改的首选形式」可得——这就是首选形式。要改任何一个 scriptlet 的行为：改 uBO
源码或改这个生成器，然后重新生成；不要手改 `scriptlet-resources.rs`（文件头写明 do not edit，
cargo 测试会拦住绕过生成器的手改）。

## 4. 其他随包内容

| 内容 | 位置 | 来源 / 版权 | 许可 |
|---|---|---|---|
| `$redirect` 占位资源（11 个） | `core/src/http/resources.rs` | 各自的极简字节串：1×1 GIF、2×2/3×2/32×32 PNG、单帧静音 MP3/MP4、空 JS/CSS/TXT/HTML、`{}` | ZShield 自有（GPL-3.0-or-later） |
| 内置测试规则 `builtin-test.txt` | `app/src/main/assets/rules/` | 自写域名清单 | 自有 |
| 加密 DNS 端点清单 | `app/src/main/assets/rules/encrypted-dns-hosts.txt` | 各服务商**公开文档**里的端点主机名（文件内逐条给出处 URL） | 主机名列表不构成受版权保护的表达；不复制任何服务商文本 |
| 可解密浏览器名单 / 永不解密名单 | `app/src/main/assets/https/` | 自写（包名与域名） | 自有 |
| 订阅目录 `catalog.json` | `app/src/main/assets/filters/` | 自写，仅含 URL 与元数据 | 自有 |
| **Mozilla 公共后缀列表（PSL）** | 经 `psl` crate 编译进 `libzshield.so` | Mozilla / publicsuffix.org；`psl 2.1.248`，10406 条规则 | MPL-2.0 |
| 图标（启动器 / 磁贴） | `app/src/main/res/drawable/` | `verified_user` 路径数据（见 §8.2） | Apache-2.0（Material Icons） |
| Gradle wrapper | `gradlew`, `gradlew.bat`, `gradle/wrapper/` | Gradle, Inc. | Apache-2.0（文件头 SPDX 行） |

**PSL 是容易漏的一项**：`adblock` 的 `embedded-domain-resolver` 把 `psl` 拉进依赖树
（`psl ← addr ← adblock`），而 `psl` 把 10406 条规则编译成 Rust 代码进 `.so`。它有独立版权方
（Mozilla）与独立许可文件。**不要用 `strings` 搜标签判断它是否进包**——strip 后的 release 二进制里
规则编译成了字节比较，搜 `blogspot` 是 0 命中；用 `nm` 在未 strip 构建里能看到
`psl::list::lookup_*` 系列函数。

**占位资源与 uBO 的关系**：`http/resources.rs` 的注释原先写「uBlock Origin placeholders」。逐字节
核对结果是**不同**：1×1 GIF 42 字节（uBO 43）、MP3 144 字节最小帧（uBO 813）、MP4 58 字节
（uBO 3753）。这些是自有实现，不是复制品；注释已改正，避免把自有内容误标成 GPL 来源。

## 5. 订阅列表（**不随包分发**）

`catalog.json` 里的 27 个列表由用户**在应用内按需下载**，不进入 APK，也不进入二进制。各自遵循
原条款（AdGuard 过滤器 GPL-3.0、uBO filters GPL-3.0、EasyList GPLv3+CC BY-SA、URLhaus
CC-BY-SA-4.0、pgl.yoyo CC-BY-NC-SA-4.0、anti-AD MIT 等，逐条记在 `catalog.json` 的 `license` 字段）。
以数据形式被解析，不产生 GPL 衍生作品关系。

**边界情形**：`peter-lowe`（CC-BY-**NC**-SA-4.0）带非商业限制。它只是用户可选下载的数据，不随包
分发、默认关闭，因此不约束本项目自身授权。若将来要随包内置，必须重新评估。

## 6. APK 内通知

### 6.1 做法

`app/src/main/assets/licenses/` 由 `scripts/gen-license-assets.py` **从锁定的依赖集生成**：

1. `cargo metadata --locked --filter-platform aarch64-linux-android` 解析运行时依赖集；
2. 遍历每个 crate 发布包，收取**所有**条款文件（任意层级——嵌套文件才是重点）；
3. 每份文件**逐字节复制**；内容相同的只留一份，命名规则见下；
4. 生成 `THIRD-PARTY-NOTICES.txt` 作为索引：crate → 它适用的文件；
5. 有 crate 一份条款文件都没有时**生成失败**，缺口是构建失败而不是静默漏项。

`python3 scripts/gen-license-assets.py --check` 会重新生成到临时目录并逐文件比对，用来发现
资产与依赖版本之间的差异。当前 139 个 Rust 运行时 crate 对应 118 份去重的条款文件，
APK 另含通知索引及 GPL 正文，共 120 个资产。

命名：只被一个 crate 附带的文件保留 `<crate>-<版本>-<上游文件名>`（便于对着 crate 包核对）；被多个
crate 共用的同名正文命名为 `shared-<许可证族>-<内容哈希前 8 位>.txt`——把通用的 MIT 正文叫
`adler2-LICENSE-MIT.txt` 会让其它 crate 的索引指向一个以无关 crate 命名的文件，看着像错。

**为什么用 assets 而不是 `META-INF/`**：Gradle 的 `packaging.resources.excludes` 会清掉
`META-INF/LICENSE*` / `NOTICE*`，Android 构件中嵌套的 `META-INF/androidx/…/LICENSE.txt` 可随构件打包。
项目的 `assets/licenses/` 同时提供依赖索引及 Rust 原生库对应的条款文件。

### 6.2 复合包：`ring` 是判据，不是例外

`ring 0.17.14` 的根 `LICENSE` 只是一段索引，指向随包附带的其它文件。**只放一份通用 Apache 正文是
不够的**——引用文件里在 Apache 正文之后还有额外声明：

| 文件 | 内容 | 为什么必须单独在包里 |
|---|---|---|
| `LICENSE` | 索引（ISC + 指向下列文件） | 说明另外几份为什么存在 |
| `LICENSE-other-bits` | ISC，`Copyright 2015-2025 Brian Smith.` | 年份范围只在这里 |
| `LICENSE-BoringSSL` | Apache 2.0，**之后**还有 `Copyright (c) 2009 The Go Authors` 与 `Copyright 2015 The Chromium Authors` 两段 BSD 声明 | 这两段在任何通用 Apache 文本里都不存在 |
| `third_party/fiat/LICENSE` | Apache-2.0，`Copyright 2015-2020 the fiat-crypto authors` | ring 内嵌的第三方代码，`nm` 可见 `fiat_25519_*` 符号 |
| `src/polyfill/once_cell/LICENSE-MIT` / `LICENSE-APACHE` | MIT / Apache-2.0 | ring 内嵌的 once_cell |

六份文件全部在 `assets/licenses/` 里。测试
`the_match_ring_package_keeps_every_file_its_root_license_points_at` 断言上述三条只存在于引用文件里的
版权行**逐条出现**——删掉 `LICENSE-BoringSSL` 或 `LICENSE-other-bits` 都会让测试失败。

同样的方法覆盖其它复合/内嵌资源：`tracing-core` 内嵌 `src/spin/LICENSE`（Mathijs van de Nes）、
`atomic-waker` 的 `LICENSE-THIRD-PARTY`、`aho-corasick`/`byteorder`/`memchr` 的 `UNLICENSE`、
`regex-syntax` 的 `src/unicode_tables/LICENSE-UNICODE`、`miniz_oxide` 的四份并行条款文件，
都在生成器遍历范围内，不靠人工列举。

### 6.3 发布包没有条款文件的 crate

5 个运行时 crate 的发布包里**根本没有**许可证文件。用通用 SPDX 模板替代会丢掉版权行，所以改为
按上游 commit 取得原始文件，放在 `scripts/licenses-extra/`，生成器一并收进 APK 并在索引里注明
「补充件」。取得地址与 commit 见 `scripts/licenses-extra/README.md`：

| crate | 处理 |
|---|---|
| `flatbuffers 25.12.19` | 上游 `LICENSE`（Apache-2.0 正文，与 canonical 逐字节一致） |
| `jni 0.22.4` | 上游 `LICENSE-APACHE` + `LICENSE-MIT`（双许可，两份都要；MIT 带 Prevoty, Inc. 版权行） |
| `rustls-platform-verifier-android 0.2.0` | 上游 `LICENSE-APACHE` |
| `seahash 4.1.0` | 上游 GitLab `LICENSE`（MIT 正文，同样**没有**版权行——上游如此，如实记录） |
| `selectors 0.32.0` | 无文件可收：该 crate 把 MPL-2.0 Exhibit A 通知放在**每个源文件头**，收一份 `LICENSE-LOCATION.txt` 说明 |

seahash 4.1.0 发布源码的提交是 `94b632ae`，Cargo 清单声明 MIT。上游后续提交
`3088c5c9` 补入 MIT 正文，随包副本与该提交的 LICENSE 逐字节一致。完整标识和复核方法见
[scripts/licenses-extra/README.md](../scripts/licenses-extra/README.md)。

### 6.4 版权行逐 crate 保留

MIT / ISC / 0BSD 的义务核心是「保留版权声明」，不是「附一份通用正文」——每个版权持有人各有自己的
`Copyright (c) …` 行。生成器逐文件复制，所以这些行随文件一起进包；118 份不同的条款文件里有 60 余条
不同的版权行。

`Apache-2.0 §4(d)`（传递上游 NOTICE）的结论是「无需额外传递」：139 个 Rust crate 与 74 个 Android
构件逐个解包，`NOTICE` 文件 0 个。结论写进索引，避免下一个人重新猜。

## 7. 贡献者授权（由父任务 MYSWY 征询）

本卡只记录**类别**，不在拟公开的树里写个人身份、联系方式或雇主推断。

| 贡献类别 | 项目拟用条款 | 第三方已核实条款 | 仍须权利人确认 |
|---|---|---|---|
| 本项目自有代码（各提交作者） | GPL-3.0-or-later | — | **是**：贡献者是否同意以 GPL-3.0-or-later 分发，需权利人答复 |
| uBlock Origin scriptlet | 随本项目 GPL-3.0-or-later | **已核实**：上游每文件 GPL-3.0-or-later，© Raymond Hill | 否（上游已授权） |
| 139 个 Rust crate | 各自条款，均与 GPL-3.0-or-later 兼容 | **已核实**：逐个查发布包文件与 MPL Exhibit B 声明 | 否 |
| 74 个 Android 构件 | Apache-2.0 | **已核实**：来自 POM | 否 |
| Mozilla PSL | MPL-2.0 | **已核实** | 否 |

**自有贡献的权属尚未确认**：Git 作者名、仓库访问权、`Co-Authored-By` 尾注都不能单独证明权属
（许多提交带工具署名，那是署名不是版权共有人）。若部分提交属于职务作品，著作权可能归雇主。
这个问题**只有权利人能回答**，由父任务 MYS-3031 向 MYSWY 征询；本卡不宣称权属已核实。
具体提交数量、邮箱与身份的核对结论记在私有任务，不写进本文件。

## 8. 例外与边界

### 8.1 已核实可用、但需要记录判断过程的项

1. **`ring` = `Apache-2.0 AND ISC`**，不是二选一：同时含 BoringSSL 派生代码与自有代码，两者都要满足。
   ISC 与 Apache-2.0 都与 GPL-3.0 兼容。
2. **5 个 MPL-2.0 crate**（`adblock`、`cssparser`、`cssparser-macros`、`selectors`、`dtoa-short`）均未
   声明 Exhibit B「Incompatible With Secondary Licenses」——逐个查 `LICENSE` 与源码，0 命中——因此
   允许按 GPL-3.0 再分发（MPL-2.0 §3.3）。这是「整个 APK 可整体按 GPL-3.0-or-later 分发」的关键
   前提，逐 crate 核实过，不是推定。
3. **`unicode-ident` = `(MIT OR Apache-2.0) AND Unicode-3.0`**、18 个 `icu_*` = `Unicode-3.0`。Unicode
   条款要求随附其声明，已收进包内。
4. **`flatbuffers` = Apache-2.0**（adblock 的序列化格式），无附加条款。

### 8.2 图标

`ic_launcher_foreground.xml` 与 `ic_launcher_monochrome.xml` 使用 Google Material Icons 的
`verified_user` 路径数据，与上游 `material-design-icons/src/action/verified_user/materialicons/24px.svg`
逐字符一致（本卡比对过）。Material Icons 以 Apache-2.0 发布，已在索引中作为 Apache-2.0 内容登记。
`ic_tile_shield.xml` 是本项目按启动器图标几何重画的占位图（文件注释自述，正式图标由技术负责人替换），
不引入新的第三方权利。

### 8.3 历史分发

7 个历史版本（v0.0.9–v0.1.3）的 APK 内含 uBO scriptlet，但没有随包通知。实测：`git cat-file` 查
`core/src/cosmetic/scriptlet-resources.rs` 自 v0.0.9 起存在（v0.0.1–v0.0.8 不存在）；
APK 侧 v0.0.8 的 `libzshield.so` 里 `safeSelf` 命中 0 次、v0.0.9 命中 76 次（同一方法，阳性对照成立）。

旧标签记录了项目选择的 GPL-3.0-or-later 条款。公开旧版本仍需确认自有贡献的授权，
逐版核对相应源码、随包声明和已有附件的处理方式。

## 9. 对应源码怎么取得

三类来源分别说明，都不用「依赖锁文件即可」这种说法搪塞：

### 9.1 本项目源码

仓库即源码。按 APK 的 `versionName`/`versionCode` 找到同名 tag，该 tag 的树是完整对应源码
（含 `core/Cargo.lock`、`scripts/build.sh`、`gradle/` 与全部构建脚本）。公开仓库后，tag 页面可直接下载。

### 9.2 锁定的上游源码（未修改的 crate）

139 个运行时 crate **未被本项目修改**，版本锁定在 `core/Cargo.lock`。取得方式二选一：

```bash
# 按版本从 crates.io 下载同一发布包
cargo vendor --locked --manifest-path core/Cargo.toml vendor/
# 或按 lock 文件逐条解析出名称/版本后自行下载
cargo metadata --locked --manifest-path core/Cargo.toml \
    --filter-platform aarch64-linux-android --format-version 1
```

`cargo vendor` 得到的是与 lock 完全对应的完整源码副本，这是可复核的，不是「有 lock 文件就算数」。

### 9.3 随包分发但需修改首选形式的资源

uBlock Origin scriptlet：来源、修订与重新生成办法见 §3.4。这是 GPL-3.0 §6 要求提供的「首选形式」，
`scripts/gen-scriptlet-resources.mjs` 与生成文件头部都写明了做法。

### 9.4 阶段 2 解包核对清单

拿到候选 APK 后逐条核，任一不满足即视为归属未完成：

```bash
APK=zshield-0.1.4-release.apk

# 1. 条款资产确实进包
unzip -l "$APK" | grep -c 'assets/licenses/'       # 期望 120
unzip -p "$APK" assets/licenses/GPL-3.0-or-later.txt | sha256sum
sha256sum LICENSE                                   # 必须同为 3972dc97…b36986

# 2. ring 的引用文件在包里，且带着只存在于引用文件的版权行
unzip -p "$APK" assets/licenses/ring-0.17.14-LICENSE-BoringSSL.txt | grep -c 'The Go Authors'
unzip -p "$APK" assets/licenses/ring-0.17.14-LICENSE-other-bits.txt | grep 'Copyright 2015-2025 Brian Smith.'

# 3. 索引不是空壳：它点到的每个文件都在包里
unzip -p "$APK" assets/licenses/THIRD-PARTY-NOTICES.txt | grep -c '^        -> '

# 4. uBO scriptlet 确实在二进制里（归属不是空谈）
unzip -p "$APK" lib/arm64-v8a/libzshield.so | strings | grep -c 'safeSelf'   # 期望 > 0

# 5. 版本映射：APK 的 versionName/versionCode 对应到同名 tag
aapt dump badging "$APK" | grep package

# 6. r8/shrinkResources 没有把 assets 删掉（isShrinkResources = true 时必须实测）
unzip -l "$APK" | grep -c 'assets/licenses/.*\.txt'
```

本卡已在 `:app:assembleDebug` 产物上预跑 1–4 与 6 条，实测：①120 个文件；②GPL 正文 SHA 与
`LICENSE` 均为 `3972dc97…b36986`；③`The Go Authors` 1 处、`LICENSE-other-bits` 的年份行 1 处；
④索引指向 240 个文件条目；⑤`safeSelf` 73 次。debug 变体只验证打包路径，**第 5 条（版本映射）与
release 变体上的第 6 条由阶段 2 复跑**。

第 6 条是本卡留给阶段 2 的关键点：`isShrinkResources = true`。resource shrinker 只处理 `res/`，
理论上不碰 `assets/`，但**必须实测**而不是推定。

## 10. 复核命令

```bash
# 通知资产是否与当前依赖集一致（会重新生成并逐文件比对）
python3 scripts/gen-license-assets.py --check

# Rust 运行时依赖集（aarch64-linux-android，含直接与传递）
cargo metadata --locked --manifest-path core/Cargo.toml \
    --filter-platform aarch64-linux-android --format-version 1

# Android release 运行时依赖
./gradlew :app:dependencies --configuration releaseRuntimeClasspath

# 重新生成 scriptlet 资源并逐字节比对（§3.4）
node scripts/gen-scriptlet-resources.mjs /tmp/uBlock > /tmp/regenerated.rs
cmp /tmp/regenerated.rs core/src/cosmetic/scriptlet-resources.rs
```

拆分口径：`cargo metadata` 的 `resolve.nodes[].deps[].dep_kinds[].kind` 为 `normal` 的边是链接进二进制
的运行时依赖（**139 个第三方** + 本项目自身 1 个）；`build` 与 proc-macro（**45 个**，其中 17 个
proc-macro）不进入产物。`cargo metadata` 共 185 个包 = 139 + 1 + 45，三个数字都给出，避免
「少列一项」的歧义。完整列表见 §11/§12。

### 10.1 关于 `git diff --check`

裸 `git diff --check`（工作树 vs 索引）在干净工作树上恒为 0，它**不能**代表 PR 范围。PR 范围的
正确命令是 `git diff --check origin/main...HEAD`。

本卡的该命令会报 **10 行**警告，分布在 **8 个** `assets/licenses/` 文件里，全部来自**必须原样分发的
上游许可证文本**：

- 其中 2 行是上游自带的**尾随空格**（MPL 正文里 `in ` 之后的空格、BSD 正文末句后的空格）；
- 其余是该文件的 **CRLF 行尾**（上游 `smoltcp`/`subtle`/`combine` 等就是这样发布的）。

两种都不能「修」：转成 LF 或裁掉尾随空格，就不再是上游文件的逐字副本，而逐字性正是这些文件的意义
所在（§13 纪律 2）。

因此这些警告是**预期内的**，不是待修项。本卡的检查范围是：

```bash
# 本项目自己的文件（排除 assets/licenses 下的上游逐字文本）
git diff --check origin/main...HEAD -- ':(exclude)app/src/main/assets/licenses'
# 期望：无输出（exit 0）
```

已实测该命令返回 0（见交付说明）。许可证资产本身的正确性由「逐字节来自上游」保证，不由空白检查
保证——把上游文本「修」成符合本项目空白规范的副本，才是真的把许可做错。

## 11. 登记表：Rust 依赖（`core/Cargo.toml`）

### 11.1 运行时链接依赖（139 个第三方）

| crate | 版本 | 许可证 |
|---|---|---|
| `adblock` | 0.13.5 | MPL-2.0 |
| `addr` | 0.15.6 | MIT OR Apache-2.0 |
| `adler2` | 2.0.1 | 0BSD OR MIT OR Apache-2.0 |
| `aho-corasick` | 1.1.5 | Unlicense OR MIT |
| `arrayvec` | 0.7.8 | MIT OR Apache-2.0 |
| `asn1-rs` | 0.7.2 | MIT OR Apache-2.0 |
| `atomic-waker` | 1.1.2 | Apache-2.0 OR MIT |
| `base64` | 0.22.1 | MIT OR Apache-2.0 |
| `base64` | 0.23.1 | MIT OR Apache-2.0 |
| `bit-vec` | 0.9.1 | Apache-2.0 OR MIT |
| `bitflags` | 1.3.2 | MIT OR Apache-2.0 |
| `bitflags` | 2.13.2 | MIT OR Apache-2.0 |
| `block-buffer` | 0.10.4 | MIT OR Apache-2.0 |
| `byteorder` | 1.5.0 | Unlicense OR MIT |
| `bytes` | 1.12.1 | MIT |
| `cfg-if` | 1.0.5 | MIT OR Apache-2.0 |
| `combine` | 4.6.9 | MIT |
| `cpufeatures` | 0.2.17 | MIT OR Apache-2.0 |
| `crc32fast` | 1.5.4 | MIT OR Apache-2.0 |
| `crypto-common` | 0.1.7 | MIT OR Apache-2.0 |
| `cssparser` | 0.35.0 | MPL-2.0 |
| `data-encoding` | 2.11.1 | MIT |
| `defmt` | 1.2.0 | MIT OR Apache-2.0 |
| `der-parser` | 10.0.0 | MIT OR Apache-2.0 |
| `deranged` | 0.5.9 | MIT OR Apache-2.0 |
| `derive_more` | 2.1.1 | MIT |
| `digest` | 0.10.7 | MIT OR Apache-2.0 |
| `dtoa` | 1.0.11 | MIT OR Apache-2.0 |
| `dtoa-short` | 0.3.5 | MPL-2.0 |
| `either` | 1.19.0 | MIT OR Apache-2.0 |
| `equivalent` | 1.0.3 | Apache-2.0 OR MIT |
| `flatbuffers` | 25.12.19 | Apache-2.0 |
| `flate2` | 1.1.11 | MIT OR Apache-2.0 |
| `fnv` | 1.0.7 | Apache-2.0 OR MIT |
| `foldhash` | 0.2.0 | Zlib |
| `futures-channel` | 0.3.34 | MIT OR Apache-2.0 |
| `futures-core` | 0.3.34 | MIT OR Apache-2.0 |
| `futures-sink` | 0.3.34 | MIT OR Apache-2.0 |
| `generic-array` | 0.14.7 | MIT |
| `getrandom` | 0.2.17 | MIT OR Apache-2.0 |
| `h2` | 0.4.20 | MIT |
| `hash32` | 0.3.1 | MIT OR Apache-2.0 |
| `hashbrown` | 0.17.1 | MIT OR Apache-2.0 |
| `heapless` | 0.9.3 | MIT OR Apache-2.0 |
| `http` | 1.5.0 | MIT OR Apache-2.0 |
| `http-body` | 1.1.0 | MIT |
| `http-body-util` | 0.1.5 | MIT |
| `hyper` | 1.12.0 | MIT |
| `hyper-util` | 0.1.21 | MIT |
| `icu_collections` | 2.4.0 | Unicode-3.0 |
| `icu_locale_core` | 2.4.0 | Unicode-3.0 |
| `icu_normalizer` | 2.4.0 | Unicode-3.0 |
| `icu_normalizer_data` | 2.4.0 | Unicode-3.0 |
| `icu_properties` | 2.4.0 | Unicode-3.0 |
| `icu_properties_data` | 2.4.0 | Unicode-3.0 |
| `icu_provider` | 2.4.0 | Unicode-3.0 |
| `idna` | 1.1.0 | MIT OR Apache-2.0 |
| `idna_adapter` | 1.2.2 | Apache-2.0 OR MIT |
| `indexmap` | 2.14.2 | Apache-2.0 OR MIT |
| `itertools` | 0.14.0 | MIT OR Apache-2.0 |
| `itoa` | 1.0.18 | MIT OR Apache-2.0 |
| `jni` | 0.22.4 | MIT OR Apache-2.0 |
| `jni-sys` | 0.4.1 | MIT OR Apache-2.0 |
| `lazy_static` | 1.5.1 | MIT OR Apache-2.0 |
| `libc` | 0.2.191 | MIT OR Apache-2.0 |
| `litemap` | 0.8.3 | Unicode-3.0 |
| `log` | 0.4.35 | MIT OR Apache-2.0 |
| `lru` | 0.19.0 | MIT |
| `managed` | 0.8.0 | 0BSD |
| `memchr` | 2.8.3 | Unlicense OR MIT |
| `minimal-lexical` | 0.2.1 | MIT OR Apache-2.0 |
| `miniz_oxide` | 0.9.1 | MIT OR Zlib OR Apache-2.0 |
| `mio` | 1.2.4 | MIT |
| `new_debug_unreachable` | 1.0.6 | MIT |
| `nom` | 7.1.3 | MIT |
| `num-bigint` | 0.4.8 | MIT OR Apache-2.0 |
| `num-integer` | 0.1.47 | MIT OR Apache-2.0 |
| `num-traits` | 0.2.19 | MIT OR Apache-2.0 |
| `oid-registry` | 0.8.1 | MIT OR Apache-2.0 |
| `once_cell` | 1.21.4 | MIT OR Apache-2.0 |
| `pem` | 4.0.0 | MIT |
| `percent-encoding` | 2.3.2 | MIT OR Apache-2.0 |
| `phf` | 0.11.3 | MIT |
| `pin-project-lite` | 0.2.17 | Apache-2.0 OR MIT |
| `potential_utf` | 0.1.6 | Unicode-3.0 |
| `powerfmt` | 0.2.1 | MIT OR Apache-2.0 |
| `precomputed-hash` | 0.1.1 | MIT |
| `psl` | 2.1.248 | MIT OR Apache-2.0 |
| `psl-types` | 2.0.11 | MIT OR Apache-2.0 |
| `rcgen` | 0.14.10 | MIT OR Apache-2.0 |
| `regex` | 1.13.1 | MIT OR Apache-2.0 |
| `regex-automata` | 0.4.18 | MIT OR Apache-2.0 |
| `regex-syntax` | 0.8.11 | MIT OR Apache-2.0 |
| `ring` | 0.17.14 | Apache-2.0 AND ISC |
| `rustc-hash` | 2.1.3 | Apache-2.0 OR MIT |
| `rusticata-macros` | 4.1.0 | MIT OR Apache-2.0 |
| `rustls` | 0.23.46 | Apache-2.0 OR ISC OR MIT |
| `rustls-pemfile` | 2.2.0 | Apache-2.0 OR ISC OR MIT |
| `rustls-pki-types` | 1.15.1 | MIT OR Apache-2.0 |
| `rustls-platform-verifier` | 0.7.1 | MIT OR Apache-2.0 |
| `rustls-platform-verifier-android` | 0.2.0 | MIT OR Apache-2.0 |
| `rustls-webpki` | 0.103.16 | ISC |
| `seahash` | 4.1.0 | MIT |
| `selectors` | 0.32.0 | MPL-2.0 |
| `serde` | 1.0.229 | MIT OR Apache-2.0 |
| `serde_core` | 1.0.229 | MIT OR Apache-2.0 |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 |
| `servo_arc` | 0.4.3 | MIT OR Apache-2.0 |
| `sha2` | 0.10.9 | MIT OR Apache-2.0 |
| `simd-adler32` | 0.3.10 | MIT |
| `slab` | 0.4.12 | MIT |
| `smallvec` | 1.16.5 | MIT OR Apache-2.0 |
| `smoltcp` | 0.14.0 | 0BSD |
| `socket2` | 0.6.5 | MIT OR Apache-2.0 |
| `stable_deref_trait` | 1.2.1 | MIT OR Apache-2.0 |
| `subtle` | 2.6.1 | BSD-3-Clause |
| `thiserror` | 1.0.69 | MIT OR Apache-2.0 |
| `time` | 0.3.55 | MIT OR Apache-2.0 |
| `tinystr` | 0.8.5 | Unicode-3.0 |
| `tokio` | 1.54.1 | MIT |
| `tokio-rustls` | 0.26.6 | MIT OR Apache-2.0 |
| `tokio-util` | 0.7.20 | MIT |
| `tracing` | 0.1.44 | MIT |
| `tracing-core` | 0.1.36 | MIT |
| `try-lock` | 0.2.5 | MIT |
| `typenum` | 1.20.1 | MIT OR Apache-2.0 |
| `untrusted` | 0.9.0 | ISC |
| `utf8_iter` | 1.1.0 | Apache-2.0 OR MIT |
| `utf_types` | 1.0.0 | Apache-2.0 OR MIT |
| `want` | 0.3.2 | MIT |
| `writeable` | 0.6.4 | Unicode-3.0 |
| `x509-parser` | 0.18.1 | MIT OR Apache-2.0 |
| `yasna` | 0.6.0 | MIT OR Apache-2.0 |
| `yoke` | 0.8.4 | Unicode-3.0 |
| `zerofrom` | 0.1.8 | Unicode-3.0 |
| `zeroize` | 1.9.1 | Apache-2.0 OR MIT |
| `zerotrie` | 0.2.5 | Unicode-3.0 |
| `zerovec` | 0.11.9 | Unicode-3.0 |
| `zmij` | 1.0.23 | MIT |

### 11.2 仅构建期（45，不进入产物）

| crate | 版本 | 许可证 |
|---|---|---|
| `asn1-rs-derive` | 0.6.0 | MIT OR Apache-2.0 |
| `asn1-rs-impl` | 0.2.0 | MIT OR Apache-2.0 |
| `autocfg` | 1.5.1 | Apache-2.0 OR MIT |
| `cc` | 1.11.1 | MIT OR Apache-2.0 |
| `cssparser-macros` | 0.6.1 | MPL-2.0 |
| `defmt-macros` | 1.2.0 | MIT OR Apache-2.0 |
| `defmt-parser` | 1.1.0 | MIT OR Apache-2.0 |
| `derive_more-impl` | 2.1.1 | MIT |
| `displaydoc` | 0.2.7 | MIT OR Apache-2.0 |
| `find-msvc-tools` | 0.1.15 | MIT OR Apache-2.0 |
| `jni-macros` | 0.22.4 | MIT OR Apache-2.0 |
| `jni-sys-macros` | 0.4.1 | MIT OR Apache-2.0 |
| `num-conv` | 0.2.2 | MIT OR Apache-2.0 |
| `phf_codegen` | 0.11.3 | MIT |
| `phf_generator` | 0.11.3 | MIT |
| `phf_macros` | 0.11.3 | MIT |
| `phf_shared` | 0.11.3 | MIT |
| `proc-macro2` | 1.0.107 | MIT OR Apache-2.0 |
| `quote` | 1.0.47 | MIT OR Apache-2.0 |
| `rand` | 0.8.8 | MIT OR Apache-2.0 |
| `rand_core` | 0.6.4 | MIT OR Apache-2.0 |
| `rustc_version` | 0.4.1 | MIT OR Apache-2.0 |
| `same-file` | 1.0.6 | Unlicense OR MIT |
| `semver` | 1.0.28 | MIT OR Apache-2.0 |
| `serde_derive` | 1.0.229 | MIT OR Apache-2.0 |
| `shlex` | 2.0.1 | MIT OR Apache-2.0 |
| `simd_cesu8` | 1.2.0 | Apache-2.0 OR MIT |
| `simdutf8` | 0.1.5 | MIT OR Apache-2.0 |
| `siphasher` | 1.0.4 | MIT OR Apache-2.0 |
| `syn` | 2.0.119 | MIT OR Apache-2.0 |
| `syn` | 3.0.9 | MIT OR Apache-2.0 |
| `synstructure` | 0.13.2 | MIT |
| `synstructure` | 0.14.0 | MIT |
| `thiserror` | 2.0.21 | MIT OR Apache-2.0 |
| `thiserror-impl` | 1.0.69 | MIT OR Apache-2.0 |
| `thiserror-impl` | 2.0.21 | MIT OR Apache-2.0 |
| `time-core` | 0.1.9 | MIT OR Apache-2.0 |
| `time-macros` | 0.2.32 | MIT OR Apache-2.0 |
| `tokio-macros` | 2.7.2 | MIT |
| `unicode-ident` | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| `version_check` | 0.9.5 | MIT OR Apache-2.0 |
| `walkdir` | 2.5.0 | Unlicense OR MIT |
| `yoke-derive` | 0.8.4 | Unicode-3.0 |
| `zerofrom-derive` | 0.1.8 | Unicode-3.0 |
| `zerovec-derive` | 0.11.7 | Unicode-3.0 |

## 12. 登记表：Android 运行时依赖（74，`releaseRuntimeClasspath`）

| 构件 | 许可证 |
|---|---|
| `androidx.activity:activity-compose:1.13.0` | Apache-2.0 |
| `androidx.activity:activity-ktx:1.13.0` | Apache-2.0 |
| `androidx.activity:activity:1.13.0` | Apache-2.0 |
| `androidx.annotation:annotation-experimental:1.4.1` | Apache-2.0 |
| `androidx.annotation:annotation-jvm:1.9.1` | Apache-2.0 |
| `androidx.arch.core:core-common:2.2.0` | Apache-2.0 |
| `androidx.arch.core:core-runtime:2.2.0` | Apache-2.0 |
| `androidx.autofill:autofill:1.0.0` | Apache-2.0 |
| `androidx.collection:collection-jvm:1.5.0` | Apache-2.0 |
| `androidx.collection:collection-ktx:1.5.0` | Apache-2.0 |
| `androidx.compose.animation:animation-android:1.11.4` | Apache-2.0 |
| `androidx.compose.animation:animation-core-android:1.11.4` | Apache-2.0 |
| `androidx.compose.foundation:foundation-android:1.11.4` | Apache-2.0 |
| `androidx.compose.foundation:foundation-layout-android:1.11.4` | Apache-2.0 |
| `androidx.compose.material3:material3-android:1.4.0` | Apache-2.0 |
| `androidx.compose.material:material-icons-core-android:1.7.8` | Apache-2.0 |
| `androidx.compose.material:material-ripple-android:1.11.4` | Apache-2.0 |
| `androidx.compose.runtime:runtime-android:1.11.4` | Apache-2.0 |
| `androidx.compose.runtime:runtime-annotation-android:1.11.4` | Apache-2.0 |
| `androidx.compose.runtime:runtime-retain-android:1.11.4` | Apache-2.0 |
| `androidx.compose.runtime:runtime-saveable-android:1.11.4` | Apache-2.0 |
| `androidx.compose.ui:ui-android:1.11.4` | Apache-2.0 |
| `androidx.compose.ui:ui-geometry-android:1.11.4` | Apache-2.0 |
| `androidx.compose.ui:ui-graphics-android:1.11.4` | Apache-2.0 |
| `androidx.compose.ui:ui-text-android:1.11.4` | Apache-2.0 |
| `androidx.compose.ui:ui-unit-android:1.11.4` | Apache-2.0 |
| `androidx.compose.ui:ui-util-android:1.11.4` | Apache-2.0 |
| `androidx.concurrent:concurrent-futures:1.1.0` | Apache-2.0 |
| `androidx.core:core-ktx:1.18.0` | Apache-2.0 |
| `androidx.core:core-viewtree:1.0.0` | Apache-2.0 |
| `androidx.core:core:1.18.0` | Apache-2.0 |
| `androidx.customview:customview-poolingcontainer:1.0.0` | Apache-2.0 |
| `androidx.documentfile:documentfile:1.0.0` | Apache-2.0 |
| `androidx.dynamicanimation:dynamicanimation:1.0.0` | Apache-2.0 |
| `androidx.emoji2:emoji2:1.4.0` | Apache-2.0 |
| `androidx.graphics:graphics-path:1.0.1` | Apache-2.0 |
| `androidx.interpolator:interpolator:1.0.0` | Apache-2.0 |
| `androidx.legacy:legacy-support-core-utils:1.0.0` | Apache-2.0 |
| `androidx.lifecycle:lifecycle-common-java8:2.10.0` | Apache-2.0 |
| `androidx.lifecycle:lifecycle-common-jvm:2.10.0` | Apache-2.0 |
| `androidx.lifecycle:lifecycle-livedata-core-ktx:2.10.0` | Apache-2.0 |
| `androidx.lifecycle:lifecycle-livedata-core:2.10.0` | Apache-2.0 |
| `androidx.lifecycle:lifecycle-livedata:2.10.0` | Apache-2.0 |
| `androidx.lifecycle:lifecycle-process:2.10.0` | Apache-2.0 |
| `androidx.lifecycle:lifecycle-runtime-android:2.10.0` | Apache-2.0 |
| `androidx.lifecycle:lifecycle-runtime-compose-android:2.10.0` | Apache-2.0 |
| `androidx.lifecycle:lifecycle-runtime-ktx-android:2.10.0` | Apache-2.0 |
| `androidx.lifecycle:lifecycle-viewmodel-android:2.10.0` | Apache-2.0 |
| `androidx.lifecycle:lifecycle-viewmodel-ktx:2.10.0` | Apache-2.0 |
| `androidx.lifecycle:lifecycle-viewmodel-savedstate-android:2.10.0` | Apache-2.0 |
| `androidx.lifecycle:lifecycle-viewmodel:2.10.0` | Apache-2.0 |
| `androidx.loader:loader:1.0.0` | Apache-2.0 |
| `androidx.localbroadcastmanager:localbroadcastmanager:1.0.0` | Apache-2.0 |
| `androidx.navigationevent:navigationevent-android:1.0.0` | Apache-2.0 |
| `androidx.navigationevent:navigationevent-compose-android:1.0.0` | Apache-2.0 |
| `androidx.print:print:1.0.0` | Apache-2.0 |
| `androidx.profileinstaller:profileinstaller:1.4.0` | Apache-2.0 |
| `androidx.savedstate:savedstate-android:1.4.0` | Apache-2.0 |
| `androidx.savedstate:savedstate-compose-android:1.4.0` | Apache-2.0 |
| `androidx.savedstate:savedstate-ktx:1.4.0` | Apache-2.0 |
| `androidx.startup:startup-runtime:1.1.1` | Apache-2.0 |
| `androidx.tracing:tracing:1.2.0` | Apache-2.0 |
| `androidx.transition:transition:1.6.0` | Apache-2.0 |
| `androidx.versionedparcelable:versionedparcelable:1.1.1` | Apache-2.0 |
| `androidx.window:window-core-android:1.5.0` | Apache-2.0 |
| `androidx.window:window:1.5.0` | Apache-2.0 |
| `com.google.guava:listenablefuture:1.0` | Apache-2.0（见例外） |
| `org.jetbrains.kotlin:kotlin-stdlib:2.2.20` | Apache-2.0 |
| `org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0` | Apache-2.0 |
| `org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.11.0` | Apache-2.0 |
| `org.jetbrains.kotlinx:kotlinx-serialization-core-jvm:1.7.3` | Apache-2.0 |
| `org.jetbrains:annotations:23.0.0` | Apache-2.0 |
| `org.jspecify:jspecify:1.0.0` | Apache-2.0 |
| `org.rustls:rustls-platform-verifier:0.2.0` | Apache-2.0 OR MIT（选 Apache-2.0） |

例外：`com.google.guava:listenablefuture:1.0` 的 POM 未声明 `licenses` 段（其 parent 为
`com.google.guava:guava-parent`，按 Apache-2.0）；`org.rustls:rustls-platform-verifier:0.2.0` 的 AAR
无 POM 许可证声明，按上游 `LICENSE-APACHE`/`LICENSE-MIT` 记为 Apache-2.0 OR MIT（本项目选 Apache-2.0）。

**仅测试期**（不进入 release APK）：`junit:junit:4.13.2`（EPL-1.0）、
`org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0`（Apache-2.0）、`org.json:json:20260814`
（Public Domain）。

## 13. 记录纪律

1. 新增任何**随包分发**的第三方内容（代码、资源、字体、图标、词典）必须在此登记，并让
   `scripts/gen-license-assets.py` 把它纳入（或手工放进 `assets/licenses/` 并在此说明）。
2. 条款文件**从上游取得、逐字节复制**。不要用 SPDX 的模板文件代替上游文件——模板里有
   `<<var;name=…>>` 占位符，既无版权人也不是授权文本；本卡曾因此出过一次错。
3. 条款写成 `-only` 还是 `-or-later` **按上游文件核实**，不按仓库 badge 或 `package.json` 推定。
4. 归属按文件逐项记录；不要把多个文件的代码归到一个版权行下。
5. 复合包（根 LICENSE 指向其它文件、内嵌 `third_party/`、`polyfill/`）必须收全部引用文件——
   引用文件里常有通用文本中不存在的额外声明。
6. 许可证不兼容必须在交付说明里单列，不得静默处理。
