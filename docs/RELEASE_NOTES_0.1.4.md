首个公开预览版。功能与 v0.1.3 一致，本版只做公开发布所需的准备：文档、构建入口脱敏与版本号。

- 新增 `README.md`（定位、安装与 SHA-256 校验、覆盖升级与同签名要求、VPN/用户 CA 权限、自行构建与自行签名、已知限制）和 `CONTRIBUTING.md`（环境、测试命令、代码约定、真机测试与设备锁、PR 要求）。
- 构建不再依赖某一台机器的路径：`scripts/build.sh` 从 `ANDROID_SDK_ROOT` / `ANDROID_HOME` / `local.properties` 查找 SDK，NDK 版本取自 `app/build.gradle.kts`，JDK 17 自动探测；原生库以 `--remap-path-prefix` 重映射构建路径，APK 内不再含开发机主目录、cargo registry 与项目路径。自行构建需要 Rust **1.91+**（`Cargo.lock` 中 `smoltcp 0.14.0` 的下限）、`aarch64-linux-android` target 与 `cargo-ndk`；签名材料通过 `ZSHIELD_KEYSTORE_DIR` 指向仓库外目录。
- 签名材料必须预先存在：`build.sh release` 缺签名时不再自动生成新密钥（那会顶替官方身份、导致无法覆盖升级），改为中止并给出两条路径；`ZSHIELD_KEYSTORE_DIR` 可指向隔离目录，供贡献者用一次性密钥验证构建流程。
- 设备序列号不再写入仓库：`scripts/effectiveness/device-serial.sh` 与 `device_serial.py` 统一解析 `SERIAL`（显式优先，否则只在恰好一台设备在线时自动选用，多台/零台/未授权一律拒绝并说明原因），全部真机脚本与 `docs/` 命令改用 `$SERIAL`。
- 文档脱敏：设备地址、开发机路径、主机别名替换为变量或通用占位；`docs/JNI.md` 的私钥样式示例改为显式省略。实测结论与计数未改动，各文档已注明脱敏范围。
- 新增 `scripts/release/scrub_apk.py`：遍历 APK 每个成员（含 `classes*.dex`、`lib/*/*.so`、`resources.arsc`）扫描主机路径、私钥头与私网设备地址，并要求阳性对照命中，否则扫描结果不作为证据。

已知限制（与 v0.1.3 相同，本版未做性能改动）：固定五表后台 PSS 实测 **86.199 / 88.784 MiB**（同一候选的两次独立窗口，均高于 84.6 MiB 门槛），默认九表 **95.464 MiB**。CNN 与 Stack Overflow 开启保护后页面加载异常，旧版源码同样复现，尚未定位。20 站对照结论为「无新增破版信号」，不代表全部站点业务通过。公开测试 14 页合计 48/115，`adblock-tester` 96/100。

Android arm64-v8a，versionName 0.1.4 / versionCode 16。

SHA256：见同名 `.apk.sha256` 文件。
