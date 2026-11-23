# I2 完整 JNI 生命周期的宿主内存归因（MYS-2866）

本卡是**宿主诊断**，不是 I2 或设备验收。它用真实 `jni_api` 入口复现编译、启动、未变重载、
`extras.txt`-only 重载与停止，交付可重复的宿主归因；**不宣称 Android PSS、不套用五表
84.6 MiB 门槛、不代表 Pixel 行为**。父任务 MYS-2786 的设备侧未完成项仍在原处。

## 0. 本次返工改了什么

首次验收（head `84bc3f3`）不通过，三项缺陷已修，本文数值表从下述 `d67d5d7` 封存证据重算：

| 缺陷 | 修法 |
|---|---|
| 校验器 9 项错误接受 | 从包内输入正文与制品 payload 复算身份，独立推导本控制的期望 URL，核对代次、窗口与摘要；对象复用等运行事实由探针观测 |
| 启动/停止峰值沿用旧阶段 | 每次操作有独立 `Window`：调用前重置、紧接调用捕获；散列/JSON/日志一律移到窗口外。状态点不再带峰值 |
| 报告与上传包不符 | 本文每张表由封存包重算，附复算命令；撤去无证据的 arena 因果与"驻留上界"表述 |

证据封存于新目录（旧包保留未动）。旧包 ID `01a1d83b-8244-7d54-aa9b-f13242acd836`，
SHA-256 `32994f4d…`；那批数据**不再作为本文依据**。

负责人第二次评审又复现7项错误接受：九表误用五表副本、journal内容矛盾、A/B点身份/代次/
窗口与轮次不符、最终代次不符、停止后Weak仍有所有者。已补组内输入定位（缺失时不回退到包外
绝对路径）、逐条journal内容核对、全部A/B点与对应轮次关联及Weak终态判据。
可选trim模式原先被探针与校验器误拒；现在两次trim各自测量，三次smaps读取均在窗口外，
摘要引用已记录的正常状态点，不受随后诊断影响。

下文数值表保留执行者 `d67d5d7` 的六轮原始观测（封存包SHA-256
`b3857ede3b342613d95e98c24886b4476b36d6f0f9d13428b440b9640387c1dd`），
不改写历史数据。负责人新构建的复验结果单独记录在父任务验收附件。

## 1. 结论

1. **未变重载确实不重建任何规则对象。** 20 次同制品重载全部走指纹快路径：代次不动、
   `filter`/DNS filter/engine/extras 四个 `Arc` 全部 `ptr_eq`、判定结果不变。
2. **只改 `extras.txt` 的真实交换仍重新反序列化整份 `engine.bin`。** A/B 两侧
   `engine.bin` 的 payload SHA-256 完全相同，但 A/B 交换的最大窗口峰值在后续稳态之上
   65.43 MiB（五表）/ 83.09 MiB（九表）。
3. **停止后规则、FD、线程全部归还。** 六个进程一致。
4. **启动与停止现在有了自己的测量窗口**：五表启动 66.79 MiB、停止 40.73 MiB，
   与编译（118.52 MiB）、稳态（40.73 MiB）不再是同一个数。

## 2. 输入

固定五表与默认九表的正文由 `/tmp/memprof/lists-{five,nine}` 只读复制到任务目录，逐份复核
`docs/I2_MEMORY_PROFILE.md` §6 的字节数与 SHA-256，复制后设为只读。原缓存未改动。

| 组 | 列表数 | 用途 | 门槛 |
|---|---:|---|---|
| `five` | 5 | 固定五表基准 | 设备侧仍为 84.6 MiB；**本卡不套用** |
| `nine` | 9 | catalog 默认启用集 | 无 84.6 MiB 门槛，仅作同口径对照 |

A/B 的单条差异由真实 `compile_request` 生成，只改一条 typed regex `$removeparam`：

```
A: ||ab-memory.test^$xmlhttprequest,removeparam=/^old=/
B: ||ab-memory.test^$xmlhttprequest,removeparam=/^new=/
```

判定 URL 为 `https://ab-memory.test/p?old=1&new=2&keep=3`，通过生产入口
`HttpsModifiers::edits` 求值。**期望值由规则文本推导**（`removeparam=/^old=/` 必然只删
`old=`），不从探针自报：校验器独立算出 A 应得 `?new=2&keep=3`、B 应得 `?old=1&keep=3`。

## 3. 观测点与结果（本封存包重算）

每点记录 `run_id`、PID、单调时钟、phase、generation 与三类制品身份、计数活对象、
原始 `/proc/self/smaps_rollup` 字段（内核原字段名与 `kB`）、`/proc/self/status` 的
`VmPeak`、FD 与线程数。

**操作点**（编译/启动/首次删参/未变重载/重载/停止）带 `window`：窗口起止单调时钟、
起止活对象、该窗口峰值。`counted.peak_bytes` 与窗口峰值必须相等（校验器逐点核对）。
**状态点**（进程基线、稳态）不带窗口，也不带峰值——这是本次修复的核心。

下表为三个独立进程的**中位数**；编译峰值与RSS存在批间波动。

### 3.1 五表（PID 408219 / 409368 / 409751）

| 阶段 | 计数活对象 MiB | 本阶段窗口峰值 MiB | Rss kB 中位数 |
|---|---:|---:|---:|
| 进程基线 | 0.013594 | —（状态点） | 5 808 |
| 编译 A | 0.450689 | **118.516074** | 102 412 |
| 启动 A | 40.075368 | **66.794513** | 104 452 |
| 首次 `$removeparam` 求值 | 40.529068 | 41.061803 | 104 812 |
| 20 次未变重载 | 40.529068 | **41.031644** | 104 976 |
| 编译 B | 40.725983 | 158.805104 | 166 328 |
| 同 handle 重载 B | 40.732943 | 106.159847 | 127 092 |
| A/B 各 12 轮后（稳态） | 40.732943 | —（状态点） | 127 712 |
| 停止 | 0.692061 | **40.732981** | 91 848 |

### 3.2 九表（PID 412127 / 412981 / 413531，无 84.6 MiB 门槛）

| 阶段 | 计数活对象 MiB | 本阶段窗口峰值 MiB | Rss kB 中位数 |
|---|---:|---:|---:|
| 进程基线 | 0.017151 | —（状态点） | 9 524 |
| 编译 A | 0.457047 | **178.918293** | 60 892 |
| 启动 A | 49.234214 | **84.559145** | 86 628 |
| 首次 `$removeparam` 求值 | 49.749019 | 50.281754 | 87 044 |
| 20 次未变重载 | 49.749019 | **50.273169** | 87 256 |
| 编译 B | 49.948734 | 195.551028 | 141 944 |
| 同 handle 重载 B | 49.955694 | 133.042445 | 118 948 |
| A/B 各 12 轮后（稳态） | 49.955694 | —（状态点） | 119 656 |
| 停止 | 0.701221 | **49.955732** | 79 232 |

编译峰值在进程间有波动（五表 118.516074 / 110.295058 / 118.516074；九表
178.918293 / 172.918628 / 178.918310）。这组数据中的交换峰值相同；编译波动原因未单独验证。

## 4. 未变重载与真实交换

未变重载的差值减去该批次结束后的观测live；A/B差值减去随后settled状态点的live。
峰值与这些状态观测不发生在同一时刻，差值不是额外分配总量，也不等于一次可回收量。

| 组 | 未变重载窗口峰值 | 批次结束后live | 差值 | A/B 峰值 | 后续稳态live | 差值 |
|---|---:|---:|---:|---:|---:|---:|
| 五表 | 41.031644 | 40.529068 | **+0.502576** | 106.163358 | 40.732943 | **+65.430415** |
| 九表 | 50.273169 | 49.749019 | **+0.524150** | 133.045956 | 49.955694 | **+83.090261** |

两条分支同源、差值相差两个数量级，且两类峰值在三个进程间逐位相同，说明**快路径只花指纹
读取的钱，凡是真正交换的路径都要付整份 engine 的代价**。

`engine.bin` 在 A/B 两侧：文件 32 202 921 B（含 20 字节封装头），**payload 32 202 901 B**，
payload SHA-256 相同（五表 `3187ee83…`；文件SHA-256为`4be0c541…`）。日志同期显示 20 次 `artifacts unchanged` 与 13 次
`engine 32202901 B`。

## 5. 可证实的归因

- **未变重载不重建规则。** 代次不动、四个 `Arc` 逐个 `ptr_eq`、判定结果不变、
  五表20次中最大窗口峰值比批次结束后的live高0.50 MiB。
- **整组指纹不等时 `reload_engine` 重建全部三类制品**，含字节未变的 `engine.bin`。
  位置：`core/src/jni_api.rs` 的 `reload_engine` 在指纹不等后无条件调用
  `http::engine::reload_with_identity`。
- **交换后旧规则集释放**，`filter` 对象本身不变。
- **停止后规则、FD、线程归还**：handle 三个访问器全 `None`，四个 `Arc` `strong_count`
  全 0，FD 5→10→5、线程 1→3→1。

## 6. 仍未证实（本卡不做）

- **按单制品复用能降低多少峰值**：本卡没有实现或测量该生产改动，收益尚未证实，
  超出范围，需要单独任务卡。
- **设备上这段峰值是否同样存在、是否同样重要**：未知。Android 用 Scudo + JVM。
- **`Rss` 与计数活对象的差值构成**：未拆解。本卡只报两个读数与差值，**不把它解释为
  arena、不称其为"驻留非计数对象的上界"**——计数活对象不保证全部驻留，差值也就不是上界。
  停止后该差值反而增大，只作为原始现象记录，不给因果。

## 7. 边界

- **这不是 Android PSS。** 宿主 glibc，设备 bionic/Scudo 且旁跑 JVM，绝对数值不可换算。
- **`VmPeak` 不是阶段测量。** 内核无法重置它，本卡只用它作上限交叉检查
  （校验器拒绝任何超过 `VmPeak` 的计数峰值）。
- **计数分配器只覆盖 Rust `GlobalAlloc`。** C 库缓冲、直接 `mmap`、以及设备上的 JVM 堆
  都在它之外。
- **trim 诊断点可选且明确标注。** 仅作对照，**不是生产改动**；正常路径不依赖它。
- **假 TUN。** `UnixDatagram` pair 只让 tokio reactor 能注册、隧道循环真正跑起来；
  不转发数据包，不发起网络流量。

## 8. 设备侧仍未完成（不因本卡改变）

五表空闲 PSS ≤ 84.6 MiB 正式达标、设备输入同源性与只读观测方案、持锁/完整恢复能力、
正式包自证、阶段 8 TLS 443 环境、阶段 9 真机矩阵——仍是父任务 MYS-2786 的未完成项。

## 9. 复现

```bash
cargo check --manifest-path core/Cargo.toml --example i2_jni_memory_profile
cargo clippy --manifest-path core/Cargo.toml --all-targets -- -D warnings
cargo build --release --manifest-path core/Cargo.toml --example i2_jni_memory_profile

# 六进程（五/九各 3 个独立进程）
python3 scripts/effectiveness/jni_memory_profile.py run \
  --binary core/target/release/examples/i2_jni_memory_profile \
  --lists-five <lists-five> --lists-nine <lists-nine> --out <evidence-dir>

# 校验（任一缺陷非零退出并指出原因）
python3 scripts/effectiveness/jni_memory_profile.py check <evidence-dir> --json

# 校验器回归
python3 -m unittest discover -s scripts/effectiveness/tests -p 'test_jni_memory_profile.py'
```

### 9.1 校验器拒绝什么

输入正文的**实际字节**与声明或 §6 不符、列表顺序不符、缺阶段、缺 smaps 字段、缺 FD/线程数、
操作点无独立窗口、状态点谎称窗口、窗口峰值低于自身活对象或超过 `VmPeak`、
`counted.peak_bytes` 与窗口不符、载入身份与在盘制品不符、制品 payload 实际散列不符、
A/B 前提不成立（dns/engine 也变了、extras 没变、A/B 规则不在对应侧）、自报 `expected`
与规则文本矛盾、轮号不是 1..N 各一次、多轮记录完全相同、A/B 实际 URL 与所载制品要求不符、
代次未恰好 +1、上一份规则未释放、filter 对象被替换、停止后 handle 仍可读或资源未归还、
journal 缺观测或与文档不一致、command 与文档不一致、五/九任一组缺失、进程数或独立性不足、
MANIFEST 缺项/散列不符/多余文件/自列。**不做设备门槛判定，不打印 PASS。**

## 10. 交付物

- `core/examples/i2_jni_memory_profile.rs`：宿主探针，真实调用
  `compile_request → start_engine → reload_engine → stop_engine`，每次操作独立测量窗口。
- `scripts/effectiveness/jni_memory_profile.py`：驱动（六进程、只读输入副本、MANIFEST）
  与校验器（从实际字节复算，不信任自报值）。
- `scripts/effectiveness/tests/test_jni_memory_profile.py`：62项回归，包含完整合成campaign及拒绝原因。
  实际验收须同时设置 `ZSHIELD_JNI_EVIDENCE=<封存campaign>` 与
  `ZSHIELD_JNI_PROBE=<新构建example的绝对路径>`，执行真实封存包和真实trim生命周期两项；
  未提供时这两项会SKIP，不能将其报告为已通过。
- 原始证据与 MANIFEST 随交付附件给出。
