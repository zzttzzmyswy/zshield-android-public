# I2 逐请求开销与测量边界（MYS-2826）

候选版在常规删参输入和完整列表上的额外开销仍存在；本卡提供测量依据，不宣布性能问题已经解决。
`eval-reached` 的限定对照中，候选版对部分 document 请求更快，但这不能证明所有规则形态或命中情况无退化。
后续优化必须保留规则组合、例外、important、typed/untyped、重复参数和热更新的正确性。

## 身份、输入与方法

- 被测生产库：候选 `4411747b0c3db29c33c921f49d370adbbc55d9e7`；历史基线 `v0.1.2` / `1bf604a67ef1d5db9c40e0ee71814e4e63c0fbc4`。
  本 PR 仅增加或修正 bench、工具、报告；未改生产算法。负责人补测的候选 checkout 为 `1fd17ae`，生产库与上述候选一致。
- 两版使用同一 `edits_cost_matrix.rs`，release profile：`opt-level="z"`、LTO、单 codegen unit、panic abort。
  输入规则位于 `scripts/perf/rules/`，请求矩阵为 `scripts/perf/matrix.json`。
  每组 `report.json.inputs` 记录实际输入及二进制 SHA-256、CPU 绑核和起始负载，结束负载单独记录。
- 主机 Intel i9-10900X；绑核 19。计时包含全入口 `HttpsModifiers::edits` 和独立阶段。
  A/B 交错执行并轮换先后顺序；每轮子样本取中位数，再报告跨轮 floor、中位数及分布。
  floor 是观测最小值，仍受频率、负载和缓存影响；不等于无噪声成本，不外推到 Pixel。
- 比较前逐字段检查最终决策；缺字段、重复/缺失用例或等价组不一致即停止，不执行计时。
  内部 evaluator 与引擎可用不同组件得到相同最终决策，内部结果另列。
  矩阵中的 capability 组单列差异，不把不同结果当等价工作。
- `report.json` 保留各轮数据、标准差、方差相关统计与分配计数；表的源文件和字段写在生成标记中。
  表内短名规则形态、方法及 URL 以矩阵原文为准，不从名称推断某输入一定命中。
- 原交付证据包含六组测量及 profile。负责人修订后的 `equal-engine-name`、`eval-reached` 与路径记录来自补测；
  其他组保留原交付数据。各组二进制哈希以各自 `report.json` 为准，原包与补测包分别保存，不能混称一次运行。
- 完整五表/九表的原始 union 未随原包提供，仅有列表与 union 哈希。它们可核对结果记录，但下载当前列表不能保证还原历史输入；
  因而完整列表的独立重跑仍依赖保存的同哈希列表快照。本次负责人未重新执行完整列表测量。

## 可支持的结论

- 常规输入的额外开销主要出现在 `removeparam` 路径；独立阶段耗时不可直接相加，也不声称差异被“100%”归因。
- 完整列表两版收下的规则不同，额外防护能力是成本差异的一个因素。等量 regex 未命中控制不能排除其他形态的实现开销。
- `eval-reached` 只测该组 regex、这些请求与结果：gate 开门、带非空 query 才能进入 `in_force`；无 query 行即使 gate 可命中也不进入求值。
- 首次调用与热态成本不同不等于已证明引擎构造次数。冷控制每个样本同时新建线程与 Build，清除 v0.1.2 的线程局部缓存；
  编译和线程创建在计时外。测量覆盖 query 未命中、导航和 POST；线程环境会改变分配器行为，
  因此冷/热表只比较该模式内部，不能与主线程 timing 的绝对值直接拼接。缓存及分配器/CPU 状态仍共同影响数值。
- 源码另提供缓存复用依据：候选 `core/src/https/extras.rs` 的 `form_matches` 先查缓存，未命中才构造，达到容量上限会清空；
  v0.1.2 的 `rule_matches` 使用线程局部缓存。不能据此保证所有流量下都没有缓存反复重建。

## 结果等价与常规输入

<!-- BLOCK equal-edits -->
<!-- generated from equal-engine-name/report.json :: timing → stage=edits, floor=min over rounds, median=median over rounds -->
| 用例 | 候选 floor µs | v0.1.2 floor µs | 倍率(floor) | 候选 中位 µs | v0.1.2 中位 µs | 候选 更慢轮次 |
|---|---:|---:|---:|---:|---:|---:|
| `noquery-script` | 2.528 | 2.437 | 1.04× | 2.667 | 2.707 | 5/7 |
| `noquery-document` | 1.098 | 1.056 | 1.04× | 1.103 | 1.063 | 6/7 |
| `miss-script` | 5.844 | 2.935 | 1.99× | 5.972 | 2.951 | 7/7 |
| `miss-xhr` | 9.260 | 3.104 | 2.98× | 9.324 | 3.124 | 7/7 |
| `miss-document` | 2.896 | 1.480 | 1.96× | 2.926 | 1.492 | 7/7 |
| `hit-typed-xhr` | 10.954 | 3.608 | 3.04× | 11.126 | 3.632 | 7/7 |
| `hit-typed-image` | 10.564 | 3.489 | 3.03× | 10.712 | 3.512 | 7/7 |
| `miss-typed-wrong-kind` | 5.534 | 2.789 | 1.98× | 5.579 | 2.800 | 7/7 |
| `hit-document-navigation` | 5.895 | 2.699 | 2.18× | 5.934 | 2.744 | 7/7 |
| `hit-document-post` | 9.686 | 3.532 | 2.74× | 9.737 | 3.594 | 7/7 |
| `hit-document-zhihu` | 5.694 | 2.398 | 2.37× | 5.756 | 2.433 | 7/7 |
| `miss-duplicate-params` | 3.069 | 1.576 | 1.95× | 3.103 | 1.580 | 7/7 |
| `miss-other-host` | 3.226 | 1.643 | 1.96× | 3.252 | 1.682 | 7/7 |
| `hit-document-fragment` | 5.813 | 2.637 | 2.20× | 5.926 | 2.664 | 7/7 |
<!-- /BLOCK equal-edits -->

<!-- BLOCK no-removeparam -->
<!-- generated from no-removeparam/report.json :: timing → stage=edits, all cases -->
两版都不收任何 `$removeparam` 规则时，`edits` 的倍率区间：**1.00×**（`miss-xhr`）… **1.04×**（`miss-other-host`）。
<!-- /BLOCK no-removeparam -->

<!-- BLOCK self-eval -->
<!-- generated from self-eval-common/report.json :: timing → stage=edits, cases with a ratio ≠ 1 -->
| 用例 | 候选 floor µs | v0.1.2 floor µs | 倍率(floor) |
|---|---:|---:|---:|
| `miss-xhr` | 10.623 | 20.992 | 0.51× |
| `hit-typed-xhr` | 10.942 | 21.374 | 0.51× |
| `hit-typed-image` | 10.160 | 20.095 | 0.51× |
| `hit-document-navigation` | 6.552 | 11.820 | 0.55× |
| `hit-document-fragment` | 6.578 | 11.741 | 0.56× |
<!-- /BLOCK self-eval -->

## 规则覆盖与现实列表

<!-- BLOCK rule-counts -->
<!-- generated from <input>/headers.json :: record=header → removeparam_rules / removeparam_rejected -->
| 输入 | 候选规则 | 候选拒收 | v0.1.2 规则 | v0.1.2 拒收 |
|---|---:|---:|---:|---:|
| `equal-engine-name` | 7 | 0 | 0 | 0 |
| `no-removeparam` | 0 | 0 | 0 | 0 |
| `self-eval-common` | 5 | 0 | 5 | 0 |
| `eval-reached` | 20 | 0 | 20 | 0 |
| `full-5` | 2760 | 2 | 101 | 80 |
| `full-9` | 2770 | 2 | 103 | 81 |
<!-- /BLOCK rule-counts -->

<!-- BLOCK full-5 -->
<!-- generated from full-5/report.json :: timing → stage=edits, floor=min over rounds -->
| 用例 | 候选 floor µs | v0.1.2 floor µs | 倍率(floor) |
|---|---:|---:|---:|
| `noquery-script` | 14.841 | 14.717 | 1.01× |
| `noquery-document` | 4.748 | 4.652 | 1.02× |
| `miss-script` | 20.110 | 19.806 | 1.02× |
| `miss-xhr` | 16.421 | 15.973 | 1.03× |
| `miss-document` | 25.763 | 7.997 | 3.22× |
| `hit-typed-xhr` | 18.585 | 17.965 | 1.03× |
| `hit-typed-image` | 13.419 | 13.109 | 1.02× |
| `miss-typed-wrong-kind` | 17.439 | 17.233 | 1.01× |
| `hit-document-navigation` | 36.929 | 13.102 | 2.82× |
| `hit-document-post` | 31.363 | 9.815 | 3.20× |
| `hit-document-zhihu` | 32.303 | 11.290 | 2.86× |
| `miss-duplicate-params` | 33.480 | 9.709 | 3.45× |
| `miss-other-host` | 31.893 | 10.346 | 3.08× |
| `hit-document-fragment` | 45.105 | 13.844 | 3.26× |
<!-- /BLOCK full-5 -->

<!-- BLOCK full-9 -->
<!-- generated from full-9/report.json :: timing → stage=edits, floor=min over rounds -->
| 用例 | 候选 floor µs | v0.1.2 floor µs | 倍率(floor) |
|---|---:|---:|---:|
| `noquery-script` | 18.885 | 18.463 | 1.02× |
| `noquery-document` | 5.622 | 5.446 | 1.03× |
| `miss-script` | 24.291 | 23.891 | 1.02× |
| `miss-xhr` | 18.638 | 18.056 | 1.03× |
| `miss-document` | 27.831 | 9.599 | 2.90× |
| `hit-typed-xhr` | 22.215 | 21.387 | 1.04× |
| `hit-typed-image` | 15.642 | 15.211 | 1.03× |
| `miss-typed-wrong-kind` | 21.147 | 20.759 | 1.02× |
| `hit-document-navigation` | 40.660 | 16.527 | 2.46× |
| `hit-document-post` | 33.591 | 11.432 | 2.94× |
| `hit-document-zhihu` | 34.935 | 13.383 | 2.61× |
| `miss-duplicate-params` | 36.235 | 11.804 | 3.07× |
| `miss-other-host` | 34.548 | 12.248 | 2.82× |
| `hit-document-fragment` | 49.893 | 17.992 | 2.77× |
<!-- /BLOCK full-9 -->

## 逐阶段与分配

<!-- BLOCK stage-split-miss-document -->
<!-- generated from equal-engine-name/report.json :: timing → id=miss-document, every stage, floor=min over rounds -->
| 阶段 | 候选 floor µs | v0.1.2 floor µs | 倍率(floor) |
|---|---:|---:|---:|
| `parse_url` | 0.616 | 0.645 | 0.95× |
| `adblock_request` | 0.643 | 0.634 | 1.01× |
| `decide` | 1.410 | 1.408 | 1.00× |
| `removeheader` | 0.020 | 0.021 | 0.95× |
| `removeparam` | 1.384 | 0.021 | 67.22× |
| `edits` | 2.896 | 1.480 | 1.96× |
<!-- /BLOCK stage-split-miss-document -->

<!-- BLOCK stage-split-hit-document-navigation -->
<!-- generated from equal-engine-name/report.json :: timing → id=hit-document-navigation, every stage, floor=min over rounds -->
| 阶段 | 候选 floor µs | v0.1.2 floor µs | 倍率(floor) |
|---|---:|---:|---:|
| `parse_url` | 0.661 | 0.686 | 0.96× |
| `adblock_request` | 0.775 | 0.765 | 1.01× |
| `decide` | 2.443 | 2.407 | 1.02× |
| `removeheader` | 0.020 | 0.021 | 0.94× |
| `removeparam` | 3.062 | 0.021 | 143.10× |
| `edits` | 5.895 | 2.699 | 2.18× |
<!-- /BLOCK stage-split-hit-document-navigation -->

<!-- BLOCK stage-verdict -->
<!-- generated from equal-engine-name/report.json :: timing → all stages except removeparam, all equal cases -->
非 `removeparam` 的 4 个阶段在全部 14 个等价用例上的倍率区间：**0.90×**（`miss-script/removeheader`）… **1.13×**（`noquery-script/decide`）。
<!-- /BLOCK stage-verdict -->

<!-- BLOCK alloc -->
<!-- generated from equal-engine-name/report.json :: allocations → --mode=alloc, per call -->
| 用例 | 阶段 | 候选 次/请求 | v0.1.2 次/请求 | 候选 B/请求 | v0.1.2 B/请求 |
|---|---|---:|---:|---:|---:|
| `miss-document` | `decide` | 9 | 9 | 429 | 429 |
| `miss-document` | `removeparam` | 9 | 0 | 429 | 0 |
| `miss-document` | `edits` | 18 | 9 | 858 | 429 |
| `hit-document-post` | `decide` | 23 | 23 | 1047 | 1047 |
| `hit-document-post` | `removeparam` | 38 | 0 | 1679 | 0 |
| `hit-document-post` | `edits` | 62 | 24 | 2738 | 1059 |
| `hit-typed-xhr` | `decide` | 23 | 23 | 1086 | 1086 |
| `hit-typed-xhr` | `removeparam` | 40 | 0 | 2005 | 0 |
| `hit-typed-xhr` | `edits` | 64 | 24 | 3106 | 1101 |
<!-- /BLOCK alloc -->

## 实际路径与等量规则控制

<!-- BLOCK paths -->
<!-- generated from paths.jsonl :: record=path → gate_should_block / enters_in_force per build and input -->
| 输入 | 用例 | 候选 gate 开 | 候选进入 in_force | v0.1.2 gate 开 | v0.1.2 进入 in_force |
|---|---|---|---|---|---|
| `by-value-shared.txt` | `miss-document` | **否** | **否** | **否** | **否** |
| `eval-reached.txt` | `hit-document-fragment` | 是 | 是 | 是 | 是 |
| `eval-reached.txt` | `hit-document-navigation` | 是 | 是 | 是 | 是 |
| `eval-reached.txt` | `hit-document-post` | 是 | 是 | 是 | 是 |
| `eval-reached.txt` | `hit-document-zhihu` | 是 | 是 | 是 | 是 |
| `eval-reached.txt` | `miss-document` | 是 | 是 | 是 | 是 |
| `eval-reached.txt` | `miss-duplicate-params` | 是 | 是 | 是 | 是 |
| `eval-reached.txt` | `miss-other-host` | **否** | **否** | **否** | **否** |
| `eval-reached.txt` | `noquery-document` | 是 | **否** | 是 | **否** |
<!-- /BLOCK paths -->

<!-- BLOCK eval-reached -->
<!-- generated from eval-reached/report.json :: timing → stage=edits, floor=min over rounds -->
| 用例 | 候选 floor µs | v0.1.2 floor µs | 倍率(floor) |
|---|---:|---:|---:|
| `noquery-script` | 2.500 | 2.520 | 0.99× |
| `noquery-document` | 1.097 | 1.072 | 1.02× |
| `miss-script` | 5.792 | 6.366 | 0.91× |
| `miss-xhr` | 5.750 | 6.322 | 0.91× |
| `miss-document` | 5.977 | 32.334 | 0.18× |
| `hit-typed-xhr` | 5.770 | 6.358 | 0.91× |
| `hit-typed-image` | 5.523 | 6.068 | 0.91× |
| `miss-typed-wrong-kind` | 5.507 | 6.070 | 0.91× |
| `hit-document-navigation` | 6.028 | 35.802 | 0.17× |
| `hit-document-post` | 9.792 | 61.991 | 0.16× |
| `hit-document-zhihu` | 6.129 | 35.261 | 0.17× |
| `miss-duplicate-params` | 8.236 | 36.687 | 0.22× |
| `miss-other-host` | 3.700 | 3.622 | 1.02× |
| `hit-document-fragment` | 5.978 | 36.142 | 0.17× |
<!-- /BLOCK eval-reached -->

## 冷/热控制

<!-- BLOCK cache -->
<!-- generated from <input>/report.json :: cache[] → record=cache, median over rounds -->
| 输入 | 用例 | 构建 | 冷（首调用）µs | 热后首调用 µs | 稳态 µs | 冷/稳态 |
|---|---|---|---:|---:|---:|---:|
| `eval-reached` | `miss-document` | candidate | 40.95 | 6.03 | 6.009 | 6.8× |
| `eval-reached` | `hit-document-navigation` | candidate | 27.63 | 6.03 | 6.005 | 4.6× |
| `eval-reached` | `hit-document-post` | candidate | 32.49 | 9.80 | 9.811 | 3.3× |
| `eval-reached` | `miss-document` | baseline | 196.68 | 32.09 | 32.827 | 6.0× |
| `eval-reached` | `hit-document-navigation` | baseline | 177.08 | 35.44 | 36.428 | 4.9× |
| `eval-reached` | `hit-document-post` | baseline | 212.72 | 61.82 | 62.969 | 3.4× |
| `equal-engine-name` | `miss-document` | candidate | 11.81 | 6.62 | 6.921 | 1.7× |
| `equal-engine-name` | `hit-document-navigation` | candidate | 14.63 | 10.55 | 8.755 | 1.7× |
| `equal-engine-name` | `hit-document-post` | candidate | 14.15 | 10.26 | 10.181 | 1.4× |
| `equal-engine-name` | `miss-document` | baseline | 3.19 | 1.79 | 1.802 | 1.8× |
| `equal-engine-name` | `hit-document-navigation` | baseline | 4.80 | 2.97 | 2.946 | 1.6× |
| `equal-engine-name` | `hit-document-post` | baseline | 5.82 | 3.79 | 3.803 | 1.5× |
<!-- /BLOCK cache -->

## 规则形态与分桶

<!-- BLOCK shapes -->
<!-- generated from shapes.jsonl :: record=shape → removeparam stage, min over rounds, µs/call -->
| 形状 | 1 条 | 8 条 | 64 条 | 1→64 增长 | 候选在 1 条时 | 旧版是否收下 |
|---|---:|---:|---:|---:|---:|---|
| `empty` | 0.007 | — | — | — | 0.007 | 否 |
| `exception` | 0.058 | 0.057 | 0.055 | 0.95× | 0.058 | 否 |
| `gate-only` | 1.612 | 1.873 | 4.810 | 2.98× | 1.612 | 否 |
| `inert-other-parameter` | 2.561 | 2.543 | 2.520 | 0.98× | 2.561 | 否 |
| `anchored-regex` | 3.957 | 4.868 | 12.194 | 3.08× | 3.957 | 是（3.548 µs） |
| `typed-script-regex` | 4.058 | 5.019 | 12.394 | 3.05× | 4.058 | 是（3.696 µs） |
| `name-indexed-engine-form` | 3.737 | 3.984 | 5.150 | 1.38× | 3.737 | 否 |
| `name-indexed-hit` | 3.741 | 3.960 | 5.076 | 1.36× | 3.741 | 否 |
| `no-pattern-name` | 2.718 | 2.699 | 3.867 | 1.42× | 2.718 | 否 |
| `no-pattern-regex` | 2.948 | 3.849 | 11.007 | 3.73× | 2.948 | 否 |
| `no-pattern-bare` | 2.621 | 2.733 | 3.554 | 1.36× | 2.621 | 否 |
<!-- /BLOCK shapes -->

<!-- BLOCK shape-growth -->
<!-- generated from shapes.jsonl :: record=shape → candidate, 1 vs 64 copies, min over rounds -->
从 1 条到 64 条**明显增长**（≥1.5×）的形状：`no-pattern-regex` 3.73×、`anchored-regex` 3.08×、`typed-script-regex` 3.05×、`gate-only` 2.98×。**基本不增长**的形状：`exception` 0.95×、`inert-other-parameter` 0.98×、`no-pattern-bare` 1.36×、`name-indexed-hit` 1.36×、`name-indexed-engine-form` 1.38×、`no-pattern-name` 1.42×。
<!-- /BLOCK shape-growth -->

<!-- BLOCK buckets -->
<!-- generated from buckets/report.json :: rows → removeparam stage, min over rounds -->
| 桶 | 行数 | 候选规则 | 候选 µs | v0.1.2 规则 | v0.1.2 µs | 倍率 |
|---|---:|---:|---:|---:|---:|---:|
| `host-shortcut` | 1643 | 1643 | 1.777 | 22 | 1.415 | 1.26× |
| `by-name` | 1007 | 1006 | 2.991 | 7 | 1.420 | 2.11× |
| `by-value` | 112 | 111 | 17.230 | 72 | 1.429 | 12.06× |
| `by-value`（两版共有） | 40 | 40 | 2.155 | 40 | 1.425 | 1.51× |
<!-- /BLOCK buckets -->

## 热更新与序列化

<!-- BLOCK reload -->
<!-- generated from equal-engine-name/report.json :: reload[] → verdict per build and check -->
| 构建 | 检查 | 结论 | 说明 |
|---|---|---|---|
| candidate | `serialized_round_trip` | PASS |  |
| candidate | `hot_swap_same_content` | PASS |  |
| candidate | `hot_swap_new_content` | REPORTED | follows_live_rule_set=True |
| baseline | `serialized_round_trip` | N/A | the build collects no rule from this input, so there is nothing to serialize; the check has no subject (not a failure, not a pass) |
| baseline | `hot_swap_same_content` | PASS |  |
| baseline | `hot_swap_new_content` | REPORTED | follows_live_rule_set=False |
<!-- /BLOCK reload -->

## Profile 与优化建议

原包的 `profile-*.txt` 为 flat profile，记录来源和权限限制见 `profile-LIMITS.txt`。
请求解析、字符串扫描、分配及匹配函数在其中出现；采样从进程启动开始，包含初始化成本，不能把建表符号占比换算成每请求构造次数。
源码路径：`core/src/https/modifiers.rs` 的 `edits`；`core/src/https/extras.rs` 的 `rewrite`、`gate_open`、`in_force`、`form_matches`。

建议先研究一次请求复用已解析的请求模型、减少相同 stripped form 的重复查询；这是待验证方案，不承诺收益。
现有 gate API 只返回是否命中，不提供完整匹配 form 集合。若改成批量匹配，必须先证明能获取全部匹配项，且保留例外与 important 优先级，
不能用第一个命中规则替代并集。实施前应给出该接口或独立索引设计及新基准；本 PR 不实现生产优化。
回归范围至少包含 typed/untyped 同名、simple/regex 叠加、值敏感重复参数、例外/important、导航与 POST、序列化及运行中热替换。

## 复现与校验

```sh
python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py'
CPU=19 WORK=<独立工作目录> LISTS=<同哈希列表快照目录> scripts/perf/run.sh
python3 scripts/perf/render_report.py --results <结果目录> --check docs/reviews/i2-edits-cost.md
python3 scripts/perf/manifest.py --verify <解包目录>
```

`--check` 只核对生成标记内的表和计算句，不能验证人工结论；未被引用的缺失块不会自动成为错误。
manifest 校验文件完整性及记录的哈希，不证明二进制确由源码构建；后者需同源构建日志和重跑。
本报告不替代 I2 真机验收：五表 PSS 门槛、冷启动六轮、DNS 延迟、站点不破版及完整 TLS 并发矩阵仍待后续阶段。
