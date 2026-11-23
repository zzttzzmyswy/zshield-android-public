# I2 内存诊断与证据边界（MYS-2840）

固定五表空闲 PSS 的验收门槛仍为 **84.6 MiB**。生产根因尚未定位。PR #31 交付离线校验与
宿主探针，设备 `run` 入口保持禁用；本文不宣称 I2 内存验收通过，也不据宿主数字承诺 Android 节省量。

## 当前工具边界（2026-11-14）

离线复算检查输入字段格式、两版列表正文/用户规则/allowlist 相同、逐批加载制品身份、
每个批次恰好一次成功尝试、独立结果目录、真实时间与实际交替顺序。采样间隔须与计划一致，
完成时间须包含最后一个样本；失败尝试保留且不得与成功采样重叠。重跑使用新目录。
字段间一致不等于来源可信：采集方仍须提供设备来源原文，合成夹具仅验证判据。

报告把样本、输入、顺序与五表门槛分开。`ok`/退出0表示证据结构可用于评审，不表示五表
数值达标；必须另外读取 `threshold[].verdict`。默认九表没有84.6 MiB门槛。旧真实包仍非零拒绝，
不改写原始时间或补造输入哈希。设备事务与只读观测方案仍待后续实现验收。

## 1. 二次评审结论

负责人在 `ddb64a9` 复跑 64 项内存工具测试及前一轮六个反例：测试通过，六类旧漏检已拒绝。
附件 MANIFEST 的 293 项均匹配，样本中位数也可从原始 meminfo 重算。但仍有以下限制：

- 最新包的候选六批时间为 `2026-11-13T16:36:03Z` 至 `17:42:55Z`，旧版六批为
  `17:59:54Z` 至 `18:30:09Z`（各批 `result.txt` 首行）。旧版重跑覆盖了原交替序列中的数据，
  `campaign.json.order` 仍保留计划顺序；`finished_at=17:55:28Z` 甚至早于这六次重跑。
  这是两段测量窗口，不能当作完整交替对照。哈希清单只能证明包内文件，不能证明协议正确。
- 候选制品 payload 哈希可证明各批加载内容稳定；设备 pin 不能单独证明选中的是指定五/九表。
  v0.1.2 的加载字节数和规则数不是内容哈希。两版设备列表正文、用户规则、allowlist 与缓存
  同源性未完整证明，因此版本比较为**不可比**。宿主 catalog 的哈希不能替代设备正文哈希。
- 当时工具只把记录中的 `order` 与计划比较；删除 `order` 或把样本相对秒数改为1…6仍成功。
  离线判据已修复，但无法由旧包还原没有保存的事实。
- 已禁用的设备草稿在准备阶段释放锁后，采样器再取锁；候选子命令还未传入 CLI 的 serial/package。
  持锁事务及恢复协议必须补齐，未经复核不重新占用 Pixel。

旧报告通过“版本差小于批间极差”判定差异方向不成立，没有统计依据，已撤回。
批内/批间极差是描述量，不能作为版本影响的显著性或因果判据。

## 2. 设备读数：仅保留诊断记录

每格三批、每批六个原始 PSS 样本；下表为各批中位数的中位数。
这些数值复算一致，但不弥补上述输入与时间顺序缺口。

| 规则集标记 | 版本 | 各批中位数（kB） | 中位数（MiB） | 使用边界 |
|---|---|---|---:|---|
| fixed-five | candidate | 89148.5 / 90688 / 89468 | 87.371093750 | 高于84.6；正式输入尚待证明 |
| fixed-five | v0.1.2 | 88045 / 88622 / 88061 | 85.997070312 | 高于84.6；不能证明无增量回归 |
| default-nine | candidate | 99072 / 100302 / 99261 | 96.934570312 | 单独记录，不套用五表门槛 |
| default-nine | v0.1.2 | 98930 / 98870 / 98557 | 96.552734375 | 不能用旧版数字代替内容身份 |

不输出正式版本差、方向或 PASS。设备与宿主规则计数不同（如180571与180794）的原因仍未知；
“223条差异来自4行用户规则”未经逐项控制，不能成立为原因。

## 3. 宿主实验修正

`core/examples/i2_memory_profile.rs` 是组件探针：加载 DNS、HTTP 与 extras，编译指定列表，
随后仅调用 `http::engine::reload`。它没有调用 `jni_api::reload_engine`，不覆盖 DNS/extras
替换、制品未变早退、JNI尾部 trim、活跃请求与 Android/JVM。因此必须区分组件观测与生产路径。

二次评审发现旧 `--ab-trim` 在 `drop(main_engine)`、`drop(extras)`、`drop(filter)` **之后**执行。
此前约35.2 MiB回收量包含已经释放的规则结构，不能证明活隧道存在同等可回收占用，也不能推出
“在jni_api.rs尾部再加一次trim”的修复建议。另外，旧探针编译到 `recompile-probe/`，却从原目录
reload，未加载本次编译产物；这也已修正。

现在按以下顺序测量，`--ab-trim` 名称仅为兼容原命令，含义不再是生产时机A/B：

1. 加载三类规则，记录计数分配器的活对象字节与RSS。
2. 若指定 `--lists`，编译到独立子目录，并从该目录 reload HTTP组件；失败非零退出。
3. **保留全部三个所有者**，记录 trim 前、第一次及第二次 trim 后的数据。
4. 明确释放三个所有者，再运行独立的 `rules-dropped-control`，仅表示卸载后的对照。
5. 所有观测写入同一个JSON文档，不追加Rust `Some(...)` 调试输出。

每个检查点同时报告 `counted_live_bytes` 与 `/proc/self/smaps_rollup` 原始字段及KiB单位：
`Rss`、`Anonymous`、`Pss_Anon`、`Pss_File`、`Pss_Shmem`、`Private_Dirty` 等。缺字段保留为缺失。
`Private_Dirty` 不等于匿名私有内存，不能用它直接代表“分配器arena”；RSS减计数活对象还包含
代码、映射、栈与非Rust分配器内存，不能据此排除泄漏或宣称全部可回收。

负责人在同一宿主用原列表正文、独立制品副本重跑五/九表各三次（每次为新进程），
全部六次验证规则所有者在第一阶段仍存活、卸载对照独立、reload来自新产物且JSON可解析：

| 输入 | 保留时计数活对象（MiB） | 保留规则时两次trim的RSS变化（MiB，三次） | 卸载规则后两次trim的RSS变化（MiB，三次） |
|---|---:|---|---|
| 五表 | 39.526 | 0 / 0 / 0 | −35.340 / −35.363 / −35.203 |
| 九表 | 48.679 | −0.003906 / −0.003906 / −0.003906 | −4.816 / −4.805 / −4.816 |

这组组件实验不支持“持有过滤规则时再trim可回收约35MiB”的说法。它没有测量完整JNI路径或
Android PSS，不能反向推出其他路径没有可优化占用。原始JSON、输入与二进制哈希、执行命令及
检查脚本随父任务本轮评审附件交付。

## 4. 生产方案的证据要求

目前不建议在生产中连续调用两次 trim；旧实验并不支持这个改动。需要先补齐：

- 完整 `reload_engine` 路径（包括制品未变早退）的同输入、同生命周期控制；观察仍持有规则时
  的活对象和映射，不能用卸载后的降幅估算启动稳态收益。
- 无root、正式APK可取得的输入证据。优先验证已有导入/导出能力；若确实缺接口，单独提交最小
  只读观测方案，说明导出内容与敏感数据边界，在审定之前不改生产或使用调试APK冒充正式包。
- 工具通过后再运行真实交替的两版×五/九表×至少三批；保留每次尝试、作废原因与实际时间，
  不覆盖历史批次或把重跑插回过去的计划位置。恢复原APK、规则/列表、VPN状态并核验。

只有设备受控对照支持的最小生产改动才进入下一张修复卡。不能通过减列表、关闭HTTPS过滤、
放宽84.6 MiB或用两版都超标证明“没有回归”来完成验收。

## 5. 可执行复核

```bash
cargo check --manifest-path core/Cargo.toml --example i2_memory_profile
cargo clippy --manifest-path core/Cargo.toml --example i2_memory_profile -- -D warnings
cargo build --release --manifest-path core/Cargo.toml --example i2_memory_profile
# compiled-dir 使用任务独立副本；编译结果写入其 recompile-probe/。
core/target/release/examples/i2_memory_profile <compiled-dir> \
  --lists <list-bodies-dir> --ab-trim --json > profile.json
python3 -m json.tool profile.json > /dev/null
python3 -m unittest discover -s scripts/effectiveness/tests -p 'test_memory_profile.py'
```

旧证据可用 `memory_profile.py recompute campaign --json` 复算数值并得到明确拒绝原因；退出非零。
报告分别表示“样本有效”“输入可比”“测量顺序有效”“门槛结果”。

## 6. 原宿主输入哈希（不代表设备输入）

以下为已有宿主列表输入，供重跑组件探针对照。新实验需同时保存编译制品和这些正文的SHA256。

| 列表 ID | 默认启用 | 文件大小 | SHA256 |
|---|---|---:|---|
| `adguard-base` | 是 | 6 458 941 B | `1ec4df21f05a99e986e8b1c9d1dce18d2075fa8c4c0fdb52602960c3b4c2e693` |
| `adguard-tracking` | 是 | 15 125 879 B | `297509825b155280a17d68266b079692149e187bfc642c059863dcf46e532308` |
| `adguard-mobile` | 是 | 530 861 B | `f3262a5bb798cf02fe21cdc1720c6a1e43b0b438df83aa967ff84940dc354b61` |
| `adguard-url-tracking` | 是 | 183 673 B | `fe84fc5f8f12be9258b3f64353ad95107d8d57b82d4a2ba2f80d4fae500adece` |
| `adguard-chinese` | 是 | 718 555 B | `0bf9d26038391b6e7a4c2664f029127e050c27379576cd808dff555020f16e5c` |
| `adguard-dns` | 是 | 4 597 885 B | `d0edbf143873d060f03ea35891f2c44398d6cc9097d06f9d76b5d3d453ccf713` |
| `easylist-china` | 是 | 498 597 B | `e4dade0da96371cad630b9d740d5936ea6b41657f9d98e2d3e42530ef5adc3ae` |
| `ublock-unbreak` | 是 | 282 165 B | `91da37caebdcaec0dc111b293c0392dcb7ba5e447f636dd8529803176a825e94` |
| `ublock-quick-fixes` | 是 | 86 138 B | `c6b20fd6fbd8f284539140b5bc6b36cbf6e5d99b5f3dff76b95ce21b68b833c9` |
