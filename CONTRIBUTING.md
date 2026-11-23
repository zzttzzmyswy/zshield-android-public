# 贡献指南

欢迎 issue 与 PR。这个项目有几条不太常规的约束，先读一遍能省下往返。

## 提交之前

1. **先开 issue 说清楚要解决什么**。尤其是 UI、默认规则集、内置订阅列表这类有产品判断的改动——
   UI 视觉层由维护者统一负责，直接改很容易白做。
2. **一个 PR 一件事**。一个 PR 修一个 bug 或加一个能力，能单独合并、单独验证。大的重构请先讨论再动手。
3. **不要顺手改无关代码**。格式化、重命名、无关文件清理会让 review 无法聚焦。混进来的无关改动
   会被要求拆出去。

## 环境

见 [`README.md`](README.md) 的「自己构建」一节。要点：

- JDK 17、Android SDK（`compileSdk 36`）、NDK **28.2.13676358**、`cargo-ndk` 4.x。
- Rust **1.91 或更新**：这是 `Cargo.lock` 里 `smoltcp 0.14.0` 声明的下限，不是项目自选；低于它无法构建。
  交叉编译目标 `aarch64-linux-android`（release）与 `x86_64-linux-android`（debug），
  用 `rustup target add aarch64-linux-android x86_64-linux-android` 安装。
- **签名材料必须在仓库外**。用 `ZSHIELD_KEYSTORE_DIR` 指向你自己的目录（构建脚本与 Gradle
  都认这个变量）：

  ```bash
  ZSHIELD_KEYSTORE_DIR="$HOME/.config/zshield-contributor" scripts/gen-keystore.sh
  ZSHIELD_KEYSTORE_DIR="$HOME/.config/zshield-contributor" scripts/build.sh release
  ```

  任何密钥、口令、`keystore.properties` 都不要进版本库，
  也不要在 issue/PR 里贴出来。`scripts/build.sh release` 在缺签名材料时会中止而不是自己生成密钥——
  自动生成的密钥会顶替官方签名身份，让已安装的包无法升级。
- 你在自己机器上签出的 APK 属于你自己的签名身份，装不上官方包，反过来也一样。这是 Android 的
  规则，不是项目的限制。

## 分支与提交

- 从 `main` 开分支，名字说明做什么：`fix/quic-block-ipv6`、`feat/include-directive`。
- 一个 PR 内的提交保持可读：每个提交是一个完整的动作，说明**为什么**改，而不只是改了什么。
- 提交信息用中文或英文都行，与所在模块现有风格一致即可。

## 测试

改动的性质决定要跑什么，但**至少**要跑与改动直接相关的那一层。下面这些是项目实际使用的命令：

```bash
# Rust core：单元测试 + 静态检查（任何 core/ 下的改动都要跑）
cargo test --locked --manifest-path core/Cargo.toml
cargo clippy --locked --manifest-path core/Cargo.toml --all-targets -- -D warnings

# 编译检查（含 examples）：改了 core/examples/ 或公共接口时可单独先跑这个
cargo check --locked --manifest-path core/Cargo.toml --examples

# Kotlin 侧单元测试
./gradlew :app:testDebugUnitTest

# 注入到页面里的 procedural runtime（需要 jsdom：npm install jsdom）
node scripts/check-procedural-runtime.mjs

# 测量/验收工具自身的回归（离线，不需要设备）
python3 -m unittest discover -s scripts/effectiveness/tests -p 'test_*.py'

# 构建（release 会跑 lintRelease 并检查体积预算）
scripts/build.sh release
```

**不要为了让测试通过而删改或跳过已有测试。** 如果某个测试的前提确实变了，在 PR 里说明原因并附带
证据，让 review 能判断这个改动是否成立。

## 代码约定

- **数据面在 Rust，控制面在 Kotlin**。包处理、DNS、规则匹配、TLS 都在 `core/`；Kotlin 只做控制
  与 UI。跨语言只走 `top.zztweb.zshield.core.Native` 一个入口类，参数是 JSON 字符串或基本类型
  （契约见 [`docs/JNI.md`](docs/JNI.md)）。
- **JNI 调用不抛异常**。失败一律「返回 0/空 + 写 `lastError()`」，Kotlin 侧按 `null` 处理。新加
  的 JNI 方法必须遵守这条，否则一次分配失败就会崩掉整个进程。
- **不引入新的运行时依赖**，除非它解决的是现有依赖解决不了的问题，且能在 PR 里说清体积与许可证
  影响。项目对体积有硬预算（release APK ≤ 10 MB），对许可证有明确要求（GPL-3.0-or-later 兼容，
  见 [`docs/THIRD_PARTY.md`](docs/THIRD_PARTY.md)）。
- **不引入任何统计、崩溃上报、Play Services**。应用除了你自己配置的过滤列表地址与 DNS 上游之外
  不发任何网络请求，这条不能破。
- **版本号只在 `version.properties` 改**，那是唯一来源。影响 APK 的改动需要递增版本；是否发版由
  维护者决定。

## 真机测试

项目不使用 GitHub Actions，真机验证在维护者的设备上做。你自己有条件的话，这些约定同样适用：

- 设备序列号通过 `SERIAL` 环境变量传入，**不要**把地址写进代码或文档：

  ```bash
  adb devices                      # 找到序列号
  export SERIAL=<序列号>
  scripts/effectiveness/condition.sh status
  ```

  未设置 `SERIAL` 时，`scripts/` 下的工具只在**恰好一台**设备在线时自动选用；零台或多台都会拒绝，
  而不是猜一个。

- 测试前请检查设备占用锁，测完删掉：`/data/local/tmp/zshield-device.lock`
  （首行 `<issue 标识> <ISO 时间>`，超过 2 小时视为过期）。并行任务共用测试机时，这条是硬要求。
- **不要**执行 `svc wifi disable`、`svc data disable`、飞行模式等会切断 adb 的操作——adb 走 Wi-Fi，
  断了就找不回来了。
- 装用户 CA 需要锁屏凭据（Android 11+）。仓库里**没有**默认值：用 `ZSHIELD_TEST_PIN` 传入你自己
  在测试机上设置的那个，`condition.sh install-ca` 会拒绝在缺少它时继续。不要使用你在别处真正在用的
  锁屏密码。
- 真机结论必须附命令与输出摘要，不能只写「测过了，正常」。

## PR

PR 描述里写清楚：

- 这个 PR 解决什么问题（对应 issue 号）；
- 改了哪些文件、为什么这是最小改动；
- **实际跑过哪些命令、结果是什么**（贴通过数/失败数，不要只写「测试通过」）；
- 与既有设计（`docs/DESIGN.md` 的固定决策）的偏差，以及理由；
- 已知未覆盖的部分。

维护者会复核测试结论后再合并。不要自己合并，也不要为同一个改动重复开 PR。

## 许可证

提交即表示你同意以 GPL-3.0-or-later 授权你的贡献，并确认你有权这样做（例如不是你所在公司的专有
代码）。移入外部代码时，请在 PR 里注明来源与原始许可证，并同步更新
[`docs/THIRD_PARTY.md`](docs/THIRD_PARTY.md)。
