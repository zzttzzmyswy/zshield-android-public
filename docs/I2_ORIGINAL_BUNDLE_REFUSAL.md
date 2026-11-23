# 原证据包拒绝报告（MYS-2840 离线复核）

对象：`mys2840-evidence.tar.gz`（293 文件，MANIFEST 全匹配）内的 campaign。
命令：`python3 scripts/effectiveness/memory_profile.py recompute <bundle>/campaign --json`
结果：**exit=1，ok=false，正式对照 0 条（withheld 2 条）**。

本文只**如实报告拒绝**，不重写任何时间、顺序或样本；原包内容一字未改。

## 1. 四层判定

| 层 | 结果 | 依据 |
|---|---|---|
| 样本数值有效 | **是** | 12 批 × 6 样本，每批一行一 raw meminfo，行与 `TOTAL PSS` 逐条一致，中位数可复算 |
| 输入可比 | **否** | 12 格全部 `no input record at all`；旧版 v0.1.2 只输出字节数与规则数，无法给出制品内容身份 |
| 实际顺序有效 | **否** | campaign.json 无 `attempts` 列表；按 result.txt 首行时间看是两段窗口，不是交替 |
| 门槛结果 | **不输出** | 三层未齐；数值以 DIAGNOSTIC 呈现，九表本无门槛 |

## 2. 顺序：证据不支持「交替」

各批 `result.txt` 首行 `at=` 时间（未改动，直接读出）：

```
fixed-five--candidate--b1   16:36:03Z
fixed-five--candidate--b2   16:48:48Z
fixed-five--candidate--b3   17:01:51Z
default-nine--candidate--b1 17:17:02Z
default-nine--candidate--b2 17:30:06Z
default-nine--candidate--b3 17:42:55Z
fixed-five--v012--b1        17:59:54Z
fixed-five--v012--b2        18:05:34Z
fixed-five--v012--b3        18:11:09Z
default-nine--v012--b1      18:18:58Z
default-nine--v012--b2      18:24:33Z
default-nine--v012--b3      18:30:09Z
```

候选 6 批在 16:36:03Z–17:42:55Z 连续跑完，旧版 6 批在 17:59:54Z–18:30:09Z 连续跑完。
两段窗口之间相隔约 17 分钟。这不是「候选→旧版→候选」的交替，旧版是对候选的**集中重跑**。

`campaign.json` 里仍写着计划顺序（`order`），`finished_at=17:55:28Z` 甚至**早于**旧版第一次重跑的
`17:59:54Z`。所以那份 `order` 描述的是**计划**，不是实际执行；把它当执行顺序就是本文要拒的东西。

## 3. 输入：没有一格能证明「测的是同一批输入」

- 12 格全部缺输入记录：设备上的列表 ID/启用状态/正文 SHA、用户规则 SHA、allowlist SHA、
  APK 与已加载制品哈希，一项都没有落盘。
- 旧版 v0.1.2 的 identity 是 `engine_bytes=… block_rules=… network_rules=…`，是计数不是内容身份；
  即使补一份哈希，也不能声称来自该版本设备。因此旧版数值只能诊断，不能进等价比较。
- 宿主 catalog 的哈希不能替代设备正文哈希（设备 180571 vs 宿主 180794 的差异至今未逐项定位）。

## 4. 因此不输出的东西

- 不输出正式 PASS/FAIL，不输出版本差方向，不输出「无回归」。
- 不把九表数字套用五表的 84.6 MiB 门槛。
- 不因为两版都超过 84.6 MiB 就宣布「没有回归」。

## 5. 同一命令下新夹具的对照

`scripts/effectiveness/tests/build_formal_fixture.py --recompute` 生成的构造夹具，
在**同一份判据**下得到 exit=0、`ok=true`、`formally_comparable=true`、2 条对照：

```
exit=0 formally_comparable=True comparisons=2
fixed-five   candidate 86.917480 MiB vs v012 86.429199 MiB → 两条门槛均 FAIL（真实超门槛）
```

这说明本包被拒不是「判据永远拒绝一切」，而是**这份包确实缺两层证据**：同样的工具接受形状
完整的证据。夹具数值是合成的，只用于验证判据本身，不能引用为设备数据。
