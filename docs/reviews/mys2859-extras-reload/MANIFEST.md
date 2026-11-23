# MYS-2859 证据包 MANIFEST

生成主机：一台 x86_64 Linux 构建机（Arch 系），release profile `opt-level="z"`、LTO、单 codegen unit。
所有运行同步完成，结束后无遗留 handle/任务（控制程序每条路径都以 `stop_engine` 收尾）。

> 脱敏说明：日志为工具原始输出，未改任何结论或计数；其中的构建机主目录已按 `scripts/build.sh`
> 的路径重映射约定替换为 `/zshield`，`/tmp` 下的临时工作目录保持原样。

## 文件

| 文件 | 内容 | 结果 |
|---|---|---|
| `red-controls.log` | 同一控制程序在**未修复**的 `61ea5a898271760ce9e1d3afca3694adabf60220` 上的完整输出（仅加了只读 accessor） | `17 passed, 11 failed`，退出码 1 |
| `green-controls.log` | 修复后的完整输出 | `28 passed, 0 failed`，退出码 0 |
| `cargo-test.log` | `cargo test --manifest-path core/Cargo.toml` | 779 passed / 0 failed |
| `clippy.log` | `cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings` | 无警告，退出码 0 |
| `procedural-runtime.log` | `node scripts/check-procedural-runtime.mjs` | 21/21 passed |
| `source-sha.txt` | 被测源码 SHA-256 | — |

## 复现命令

```sh
cargo run --release --manifest-path core/Cargo.toml \
    --example extras_reload_identity -- <workdir>
cargo test --manifest-path core/Cargo.toml
cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings
node scripts/check-procedural-runtime.mjs
```

`<workdir>` 需为空目录；每个控制各用一个子目录，互不依赖前一个的残留制品。

## 不含

无私钥、CA 证书/密钥、签名材料、设备凭据。控制程序只写 `<workdir>` 下的编译产物。
