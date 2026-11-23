# 补录的上游许可证文件（仅用于上游发布包未附条款文件的 crate）

`app/src/main/assets/licenses/` 完全由 `scripts/gen-license-assets.py` 从依赖集生成，其中的条款文件
逐字节取自各 crate 发布包。但有 5 个运行时 crate 的发布包里**根本没有**条款文件；对它们，
`scripts/licenses-extra/<crate>-<version>/` 下的文件是**从上游仓库按 commit 取得**的补充，
生成器会把它们一并收进 APK 的 `assets/licenses/`，并在通知文件里注明「补录」及取得来源。

这不是「代为拟定许可证」——每一条都能按下面的地址与 commit 复核；也不是「推定授权」，
条款与版权人都在上游文件原文里。补录只是因为上游打包时漏了文件。

| crate | 上游仓库 | 取文件的 commit | 文件 | 说明 |
|---|---|---|---|---|
| `flatbuffers 25.12.19` | <https://github.com/google/flatbuffers> | `5eb190f00005b8dd1aa4f7ab2db9f01a39e3c76d` | `LICENSE` | Apache-2.0 正文，与 canonical 逐字节一致 |
| `jni 0.22.4` | <https://github.com/jni-rs/jni-rs> | `dbfb17647988b81ff37b897ce93cc85ee4c84863` | `LICENSE-APACHE`、`LICENSE-MIT` | 双许可，本项目保留两份原文（`MIT OR Apache-2.0`） |
| `rustls-platform-verifier-android 0.2.0` | <https://github.com/rustls/rustls-platform-verifier> | `6e4c1c4fbb9ec5355fcf505995724d6aa9ebf84b` | `LICENSE-APACHE` | 同一仓库的 MIT 分支已在 `rustls-platform-verifier 0.7.1` 里覆盖 |
| `seahash 4.1.0` | <https://gitlab.redox-os.org/redox-os/seahash> | `3088c5c912b70b586d27bf553fbe964e025a2c89` | `LICENSE` | MIT 正文；发布包内既无文件也无版权行，上游仓库的 LICENSE 同样**不含**版权行 |
| `selectors 0.32.0` | <https://github.com/servo/stylo> | 无需取文件 | `LICENSE-LOCATION.txt` | 该 crate 把 MPL-2.0 Exhibit A 通知放在**每个源文件头**，不放 LICENSE 文件 |

## seahash 4.1.0 的源码与许可证

`core/Cargo.lock` 记录的发布包 SHA-256 为
`1c107b6f4780854c8b126e228ea8869f4d7b71260f962fefb57b996b8959ba6b`。
包内 `.cargo_vcs_info.json` 指向 `94b632aeac099031c373599313d5b5f0acbbaec0`，
该提交的 Cargo 清单声明 MIT。上游在后续提交中补入 LICENSE；随包副本的 SHA-256 为
`23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`。
[发布时的 Cargo 清单](https://gitlab.redox-os.org/redox-os/seahash/-/blob/94b632aeac099031c373599313d5b5f0acbbaec0/Cargo.toml) · [上游补入的 LICENSE](https://gitlab.redox-os.org/redox-os/seahash/-/blob/3088c5c912b70b586d27bf553fbe964e025a2c89/LICENSE)

## 复核命令

```bash
# 补录文件与上游是否仍一致（逐个仓库重新下载后比对）
curl -sSL https://raw.githubusercontent.com/google/flatbuffers/5eb190f00005b8dd1aa4f7ab2db9f01a39e3c76d/LICENSE \
  | cmp - scripts/licenses-extra/flatbuffers-25.12.19/LICENSE && echo "flatbuffers 一致"

# 生成器是否把补录文件也算进去了
python3 scripts/gen-license-assets.py --check
```
