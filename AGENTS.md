# 协作约定（所有 agent 必读）

- 先读 `docs/DESIGN.md`（固定决策）与 `docs/ROADMAP.md`；偏离固定决策须在交付中说明理由。
- 构建一律用 `scripts/build.sh`：**编译前删除旧包**，产物只保留当前版本；release APK 尺寸超预算即失败。
- 版本唯一来源 `version.properties`；发布不覆盖同版本资产。
- 不引入任何统计、崩溃上报、Play Services 依赖；应用不得发起过滤列表下载与用户 DNS 上游以外的网络请求。
- UI 视觉层（`app/src/main/java/top/zztweb/zshield/ui/**`、主题、图标、动画）由技术负责人实现；开发任务除非任务卡允许，不改这些文件。
- 测试设备：Pixel 5（Android 16）。**设备序列号不写入仓库**：`scripts/` 下所有真机工具通过 `SERIAL` 环境变量选择设备，未设置时只在恰好连接一台设备时自动选用，其余情况直接拒绝。用法 `SERIAL=<adb 序列号> scripts/effectiveness/condition.sh ...`，序列号用 `adb devices` 查看。真机测试结论必须附命令与输出摘要。
- **测试设备安全**：adb 经 Wi-Fi 连接，禁止执行 `svc wifi disable`、`svc data disable`、飞行模式等会切断 adb 的操作；测网络切换类场景须先确认有 USB 或其他恢复手段。设备离线时先完成代码与主机测试，真机项注明「待设备恢复」，不要反复尝试远程恢复。
- **设备占用锁**：并行任务共用测试机，真机测试前检查/写入 `/data/local/tmp/zshield-device.lock`（内容 `<issue 标识> <ISO 时间>`，超过 2 小时视为过期），长测试每 30 分钟刷新，测完删除；被占用时先做主机侧工作。
- 签名文件与密码不得入库。
- 不使用 GitHub Actions。
