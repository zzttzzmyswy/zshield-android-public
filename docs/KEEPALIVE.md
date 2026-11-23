# 后台保活与自动恢复（M4a）

本文记录 ZShield 在 Android 16 上「开了就一直在」的实现依据、平台限制的核对结论、真机证据，以及
`top.zztweb.zshield.health.ProtectionHealth` 的契约。对应 `docs/DESIGN.md` 固定决策 9 与第 7 节的 7 个
回归场景。

- 设备：Pixel 5（redfin），Android 16 / API 36（序列号经 `SERIAL` 环境变量传入，仓库不记录具体地址）
- 代码：`vpn/RecoveryPolicy.kt`（决策表）、`vpn/ProtectionRecovery.kt`（读取平台状态）、
  `vpn/BootRestoreReceiver.kt`、`vpn/KeepAliveJobService.kt`、`tile/ZShieldTileService.kt`、
  `health/HealthState.kt` + `health/ProtectionHealth.kt`

## 1. 两个不同的概念：用户意图 vs 隧道状态

| 值 | 含义 | 谁写 | 什么时候写 |
|---|---|---|---|
| `AppSettings.protectionWanted` | 用户**想不想**过滤 | 只有用户动作 | UI 开关、通知「暂停」按钮、快捷磁贴 |
| `AppSettings.revokedBySystem` | 系统**收回了** VPN | `ZShieldVpnService.onRevoke` | 被别的 VPN 抢占、用户撤销授权 |
| `ZShieldVpnController.state` | 隧道**当前**是否在跑 | 服务生命周期 | 启动/停止/出错 |

规则（每条都有单元测试，见 `RecoveryPolicyTest` / `AppSettingsTest`）：

- 自动恢复**只读** `protectionWanted`，从不写它。杀进程、重启、升级、系统撤销都不会把「开」变成「关」。
- 用户主动关闭是唯一把 `protectionWanted` 置 `false` 的入口。之后无论重启还是自检都**不**恢复。
- `onRevoke` 不改意图，只记 `revokedBySystem`，让自检页能解释「为什么明明开着却没在过滤」。
- 用户重新打开（含从磁贴）时清掉 `revokedBySystem`：意图已被重新确认，旧的撤销提示已过期。

升级兼容：`version.properties` 之前的设置文档没有这两个字段，读出来是 `false`。这是刻意的安全默认值 ——
升级不会让一个原本关着的隧道自己开起来；代价是升级用户需要打开一次开关才会启用自动恢复。

## 2. 自动恢复的四条路径

全部收敛到同一张决策表 `RecoveryPolicy.decide`，避免四条路径各写一半规则：

| 触发 | 来源 | 说明 |
|---|---|---|
| `USER` | UI / 通知 / 磁贴 | 无条件启动（唯一会写意图的路径） |
| `SERVICE_RESTART` | `START_STICKY` 给服务的**空 intent** | 进程被系统回收后由 AMS 重新拉起 |
| `BOOT` | `BOOT_COMPLETED` | 重启后恢复 |
| `PACKAGE_REPLACED` | `MY_PACKAGE_REPLACED` | 覆盖升级后恢复（升级会杀掉同 uid 的服务） |
| `PERIODIC_CHECK` | `JobScheduler`，15 分钟 | 兜底自检，只在「应开未开」时拉起 |

决策顺序（`RecoveryPolicyTest` 逐条覆盖）：

1. `protectionWanted == false` → `USER_TURNED_OFF`，什么都不做；
2. 已在运行/启动中 → `ALREADY_RUNNING`，不重复 `establish`；
3. 没有 VPN 授权 → `NO_VPN_PERMISSION`，只记日志（授权只能由用户在系统对话框里给）；
4. 本应用是「始终开启的 VPN」→ `MANAGED_BY_SYSTEM`，让系统自己拉起，避免和系统抢同一个 tun；
5. 其余 → `RECOVER`。

`START_STICKY` 的返回值：`ACTION_STOP` / `ACTION_PAUSE` / `ACTION_DEBUG_TOGGLE` 三条停止路径返回
`START_NOT_STICKY`，用户停掉的服务不会被系统复活；其余一律 `START_STICKY`。

> 实现教训（已修复，真机日志见 §5.3）：`RecoveryInput.tunnelRunning` 一开始也把
> `ZShieldVpnService.instance != null` 算进去。由于服务在 `onCreate` 里就设置了 `instance`，空 intent 的
> sticky 重启会看到「自己」，判定成 `ALREADY_RUNNING` 而放弃恢复；实测只有 15 分钟后的周期自检才把隧道
> 拉回来。现在只看控制器状态。

## 3. Android 14+ / 15 后台启动前台服务的限制：逐条核对

### 3.1 `systemExempted` 这个类型合法吗

官方文档 *Foreground service types* → System exempted：该类型「Reserved for system applications and
specific system integrations」，可用条件之一是 **“VPN apps (configured using Settings > Network & Internet
> VPN)”**；不满足条件时抛 `ForegroundServiceTypeNotAllowedException`。ZShield 的服务正是用户通过系统
VPN 授权建立的隧道的宿主，属文档列出的情形；`specialUse` 需要 Play 审核的自由文本理由，不适用（本应用不上
Play）。真机证据：服务进入前台且无 `SecurityException`（§5.1）。

`./gradlew lintRelease` 的 `ForegroundServicePermission` 检查要求 `systemExempted` 同时声明
`SCHEDULE_EXACT_ALARM` / `USE_EXACT_ALARM`，这是误报：框架校验的是类型对应的
`FOREGROUND_SERVICE_SYSTEM_EXEMPTED` 权限（已声明），而「有精确闹钟权限」是**另一个**并列的可用条件。
为了过检查去声明一个本应用没有的闹钟能力会误导用户，因此该条在 manifest 里定向抑制并用注释说明。

### 3.2 从 `BOOT_COMPLETED` 启动 `systemExempted` 允许吗

- *Exemptions from background start restrictions*（Foreground service restrictions）把
  「在广播接收器里收到 `ACTION_BOOT_COMPLETED` / `ACTION_LOCKED_BOOT_COMPLETED` /
  `ACTION_MY_PACKAGE_REPLACED`」列为**允许后台启动前台服务**的情形。
- Android 15 的 *Restrictions on BOOT_COMPLETED broadcast receivers launching foreground services* 只禁止
  `dataSync`、`camera`、`mediaPlayback`、`phoneCall`、`mediaProjection`、`microphone` 六种类型
  （违规抛 `ForegroundServiceStartNotAllowedException`）。`systemExempted` **不在**禁止列表内。

结论：`BOOT_COMPLETED` / `MY_PACKAGE_REPLACED` 里启动 `systemExempted` 前台服务是被允许的，真机已验证
（§5.4、§5.5）。另外两个佐证：`AM` 日志里这些启动被记为 `Background started FGS: Allowed`，且
`tempAllowListReason` 是 `BOOT_COMPLETED` / `PACKAGE_REPLACED` 的 20 s 临时白名单。

### 3.3 周期自检（JobScheduler）里启动前台服务为什么也算数

决策 9 要求「JobScheduler 周期自检，只在应开未开时拉起」，而自检运行在 `JobService` 里，属于后台。

真机日志给出了直接答案：启动请求被 AMS 记为 **`code:OP_ACTIVATE_VPN`**，而不是靠某个临时白名单：

```
11-09 16:19:39.265 ActivityManager: Background started FGS: Allowed [callingPackage: top.zztweb.zshield;
         ... uidState: TRNB; ... code:OP_ACTIVATE_VPN; tempAllowListReason:<null>; ...]
```

`OP_ACTIVATE_VPN` 是用户在 VPN 授权对话框点「确定」时被置为 allow 的系统 app-op（设备上
`appops get top.zztweb.zshield ACTIVATE_VPN` → `allow`），而它本身就是「允许后台启动前台服务／后台启动
Activity」的一条独立豁免，与调用者当前处于什么状态（`TRNB` / `RCVR` / `FGSL`）无关。上表 §3.2 的两个广播
路径同样带这条 `code`，`tempAllowListReason` 只是额外叠加的 20 s 临时白名单。

也就是说：只要用户完成过一次 VPN 授权，本应用从广播、从 JobScheduler、从任何后台状态启动这个前台服务
都会被允许，不需要也不应该去申请闹钟权限或 `SYSTEM_ALERT_WINDOW` 之类的旁路。**未授权**时则会被拒绝，这
正是决策表把 `vpnPermission` 放在启动之前的另一个理由 —— 没有授权就没有这条豁免，尝试只会产生一条
`ForegroundServiceStartNotAllowedException` 日志。

真机复现：`docs/TESTING.md` §11.2 的 `DEBUG_KEEPALIVE_CHECK` 广播直接跑 `KeepAliveJobService` 用的那份
决策代码；隧道关闭 + 意图为开时，日志出现 `recovery trigger=PERIODIC_CHECK outcome=RECOVER` 与
`am_foreground_service_start`，且无 `ForegroundServiceStartNotAllowedException`。

### 3.4 为什么没有 `LOCKED_BOOT_COMPLETED`

`LOCKED_BOOT_COMPLETED` 在用户解锁前派发，此时凭据加密存储（`/data/user/0/...`）还不可读。本应用的设置
文档就在 `filesDir` 下，这个时刻读到的会是**默认值**，即 `protectionWanted = false`，于是恢复被自己否掉，
还会打一条误导性的「用户关了过滤」日志。等到 `BOOT_COMPLETED`（解锁后，通常只差几秒）再读，拿到的是真实
意图。

要用 direct-boot 需要把意图放进 device-protected storage（`createDeviceProtectedStorageContext()`）并让
服务可在 direct boot 下运行，代价是两套存储和一次迁移；当前 miestone 不做，记在此处备查。

### 3.5 和「始终开启的 VPN」如何共存

用户开启 always-on 后，平台自己负责在开机等时机拉起 VPN 服务（`VpnService` 的绑定与
`SERVICE_INTERFACE` 由系统侧驱动）。此时如果我们**也**去 `establish`，两个 `VpnService.Builder` 会争同一个
tun，最坏情况是用户流量落在被拆掉的那个接口上。因此决策表把 `alwaysOn == true` 判为 `MANAGED_BY_SYSTEM`，
主动让路。

读取方式：`Settings.Secure` 的 `always_on_vpn_app` 存的是 honor 的包名。这不是公开文档化的第三方可读键，
Pixel 5（A16）实测可读（`settings get secure always_on_vpn_app` 返回包名）；读不到（抛异常）时返回
`null`，而 `null` 被当作「未知、不是确认的 always-on」继续恢复 —— 若把「读不到」当成「是」，隐藏该键的
机型上应用会永久不再自恢复，那比多一次被服务串行化掉的 `establish` 更糟。

## 4. 自检（`ProtectionHealth`）

签名由任务卡固定，UI 直接依赖：

```kotlin
val state: StateFlow<HealthState>
data class HealthState(
    val vpnPermission: Boolean,
    val alwaysOn: Boolean?,
    val lockdown: Boolean?,
    val ignoringBatteryOptimizations: Boolean,
    val notificationsAllowed: Boolean,
    val backgroundRestricted: Boolean,
    val standbyBucket: Int?,
    val privateDnsStrict: Boolean,
    val revokedBySystem: Boolean,
)
fun refresh(context: Context)
fun intentFor(item: HealthItem, context: Context): Intent?
```

| 字段 | 读取方式 | 读不到时 |
|---|---|---|
| `vpnPermission` | `VpnService.prepare(context) == null` | `false`（安全下一步就是授权对话框） |
| `alwaysOn` | `Settings.Secure["always_on_vpn_app"] == packageName` | `null` |
| `lockdown` | `Settings.Secure["always_on_vpn_lockdown"] != 0` | `null` |
| `ignoringBatteryOptimizations` | `PowerManager.isIgnoringBatteryOptimizations` | `false` |
| `notificationsAllowed` | `NotificationManager.areNotificationsEnabled` | `true`（不 nag） |
| `backgroundRestricted` | `ActivityManager.isBackgroundRestricted` | `false`（不 nag） |
| `standbyBucket` | `UsageStatsManager.appStandbyBucket` | `null` |
| `privateDnsStrict` | `Settings.Global["private_dns_mode"] == "hostname"` | `false` |
| `revokedBySystem` | `AppSettings.revokedBySystem` | — |

`HealthReader` 为每个探针单独 `runCatching`，一个读失败不影响其余项，也绝不抛出 —— 自检页是用来帮用户把
保护修好的，它自己不能是崩的那个（`HealthStateTest` 覆盖「全部探针都抛异常」）。

`refresh` 只在两处调用：UI 打开自检页时、以及服务启动/被撤销后。**没有**定时刷新、没有轮询、没有额外广播：
定时自检会直接违反 `docs/DESIGN.md` 决策 10。

### 4.1 忽略电池优化

用 `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` 直接弹系统的「允许后台运行？」对话框，而不是把用户丢进
一长串应用列表里找自己。这需要 manifest 声明 `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`。

- 理由：Play 对该权限的限制是「核心功能确需豁免」；本应用不上 Play（决策 3），而一个被 Doze 挂起的 VPN
  等于没在防护。
- 边界：应用既不能自己给自己豁免，也不能绕过对话框 —— 只是把系统对话框直接调出来。v1 只在这个自检项被
  用户点击时发起，不会在启动流程里自动弹。
- lint 的 `BatteryLife` 警告是 Play 政策的提示，已在 `intentFor` 上定向抑制并写明理由。

### 4.2 `intentFor` 是尽力而为

返回 `null` 表示「本机没有这个设置页」，调用方应退回 `settingsRoot()`。每个返回值都过
`resolveActivity` 检查，并带上 `FLAG_ACTIVITY_NEW_TASK`（调用方可能不是 Activity）。
`PRIVATE_DNS` 没有公开常量，先用 `android.settings.PRIVATE_DNS_SETTINGS`，不存在时退回无线设置页。

「始终开启」/「屏蔽未使用 VPN 的连接」没有公开的直达 Action，统一指向
`Settings.ACTION_VPN_SETTINGS`，用户在那里既能开 always-on，也能把抢占接口的其它 VPN 应用移除。
VPN 授权对话框无法用 Intent 触发，必须由调用方执行 `VpnService.prepare` 并启动返回的 Intent。

## 5. 真机证据（Pixel 5 / Android 16）

命令与判定方式见 `docs/TESTING.md` §11；可重复执行的驱动脚本是 `scripts/device-test-m4a.sh`，
每个场景在 `/tmp/m4a-evidence/` 下留一份带命令与输出的证据文件。下面只摘关键行。

### 5.1 前台服务以 `systemExempted` 进入前台（无 SecurityException）

```
$ adb shell am broadcast -a top.zztweb.zshield.action.DEBUG_TOGGLE_VPN -n top.zztweb.zshield/.filters.DebugCommandReceiver
19:40:13.971 ActivityManager: Background started FGS: Allowed [callingPackage: top.zztweb.zshield;
             ... code:OP_ACTIVATE_VPN; tempAllowListReason:<null>; ... uidState: TRNB ...]
19:40:13.9xx am_foreground_service_start: [0,top.zztweb.zshield/.vpn.ZShieldVpnService,0,OP_ACTIVATE_VPN,36,36,...]
19:40:14.0xx Vpn     : Established by top.zztweb.zshield on tun0
```

全程没有 `SecurityException` 或 `ForegroundServiceTypeNotAllowedException`。

### 5.2 重启后恢复：always-on **关**（靠 `BOOT_COMPLETED`）

```
$ settings get secure always_on_vpn_app   ->  null
$ adb reboot
19:35:25.095 ActivityManager: Start proc 5832:top.zztweb.zshield/u0a249 for broadcast {.../vpn.BootRestoreReceiver}
19:35:25.916 ZShield : restore after android.intent.action.BOOT_COMPLETED
19:35:25.928 ZShield : recovery trigger=BOOT outcome=RECOVER (wanted=true)
19:35:25.964 am_foreground_service_start: [0,.../.vpn.ZShieldVpnService,0,BOOT_COMPLETED,36,36,...]
19:35:26.014 Vpn     : Established by top.zztweb.zshield on tun0

$ ping -c 1 -W 2 doubleclick.net
PING doubleclick.net (127.0.0.1) ...        # 拦截生效
```

### 5.3 重启后恢复：always-on **开**（系统负责，应用让路）

```
$ settings put secure always_on_vpn_app top.zztweb.zshield
$ adb reboot
19:37:36.237 am_proc_start: [0,3780,10249,top.zztweb.zshield,service,{.../.vpn.ZShieldVpnService}]
19:37:37.323 Background started FGS: Allowed [callingPackage: android; callingUid: 1000; uidState: PER;
             code:PROC_STATE_PERSISTENT; tempAllowListReason:<... BOOT_COMPLETED ...>]
19:37:37.330 am_foreground_service_start: [0,.../.vpn.ZShieldVpnService,1,PROC_STATE_PERSISTENT,...]
```

调用者是 `android`（uid 1000，`PROC_STATE_PERSISTENT`）而不是我们的广播接收器 —— 平台在拉起，不是我们。
我们的自检随后报 `outcome=ALREADY_RUNNING`，没有第二次 `establish`。这一条同时证实 §3.5 的让路是对的。

### 5.4 进程被杀后恢复（`START_STICKY`）

```
$ adb shell am broadcast -a top.zztweb.zshield.action.DEBUG_SUICIDE -n top.zztweb.zshield/.vpn.RecoveryTestReceiver
18:39:15.959 am_proc_died: [0,22850,top.zztweb.zshield,200,4]
18:39:15.961 ActivityManager: Scheduling restart of crashed service ...ZShieldVpnService in 1000ms for start-requested
18:39:16.981 ActivityManager: Start proc 22979:top.zztweb.zshield/u0a249 for service {...ZShieldVpnService}
18:39:17.202 ZShield : sticky restart: re-establishing the tunnel
18:39:17.215 Vpn     : Established by top.zztweb.zshield on tun0
```

死亡 → 隧道重建 **1.26 s**。这一条同时验证了 §2 里记录的 `ALREADY_RUNNING` 缺陷已修好（旧代码在这里会
打印 `not recovering (ALREADY_RUNNING)` 并放弃）。

**这条路径不是 100% 必现**：连续快速杀进程时，5 次里有 2 次 AMS 没有安排重启（`dumpsys activity services`
里 `startRequested=true` 但 `nextRestartTime` 已过期、无 `Scheduling restart` 日志）。原因是 AMS 对短时间内
反复死亡的服务有退避（`service_restart_duration=1000`、`service_restart_duration_factor=4`、
`service_min_restart_time_between=10000`、`service_crash_restart_duration=1800000`），生产环境里进程被杀
不会以几秒的间隔重复发生。这也是 §2 保留 15 分钟周期自检作为兜底的理由：同一份决策代码在 sticky 重启被
退避时仍能把隧道拉回来（实测自检触发后 1 s 内恢复）。

### 5.5 覆盖升级后恢复（`MY_PACKAGE_REPLACED`）

```
$ adb install -r dist/zshield-0.0.9-release.apk
Success
19:42:34.683 am_foreground_service_start: [0,.../.vpn.ZShieldVpnService,1,PROC_STATE_PERSISTENT,...]
19:42:34.721 Vpn     : Established by top.zztweb.zshield on tun0
19:42:35.265 ZShield : restore after android.intent.action.MY_PACKAGE_REPLACED
19:42:35.265 ZShield : recovery trigger=PACKAGE_REPLACED outcome=ALREADY_RUNNING (wanted=true)

$ ping -c 1 -W 2 doubleclick.net
PING doubleclick.net (127.0.0.1) ...
```

安装完成到重新过滤 **约 1 s**。（这里 `ALREADY_RUNNING` 是正确的：平台在安装完成时已经把隧道拉起来了，
接收器的检查只是确认。）

### 5.6 Doze 强制空闲 32 分钟

```
$ dumpsys battery unplug; dumpsys deviceidle force-idle
Now forced in to deep idle mode
# 每分钟采样一次，32 次全部为：
dumpsys deviceidle get deep  ->  IDLE
ping -c 1 -W 2 doubleclick.net -> PING doubleclick.net (127.0.0.1)
dumpsys connectivity | grep -c IS_VPN -> 1

$ ping -c 1 -W 3 www.baidu.com   # 未拦截的名字仍能通过隧道解析
PING www.a.shifen.com (220.181.x.x) ...
```

32 分钟深空闲期间隧道一直在跑、拦截一直生效、普通域名照常解析。

### 5.7 受限待机桶

```
$ am set-standby-bucket top.zztweb.zshield restricted
$ am get-standby-bucket top.zztweb.zshield   ->  45
$ dumpsys activity services top.zztweb.zshield | grep isForeground
    isForeground=true foregroundId=1001 types=0x00000400 ...
$ ping -c 1 -W 2 doubleclick.net -> PING doubleclick.net (127.0.0.1)
```

### 5.8 熄屏浸泡 1 小时

60 分钟熄屏，每分钟采样 `dumpsys connectivity | grep -c IS_VPN` 全部为 1。`dumpsys batterystats` 里本应用
（uid `u0a249`）：

| 指标 | 值 |
|---|---|
| 整段 1 h 的估计耗电 | 0.0316 mAh |
| 其中熄屏/Doze 段 | 0.0008 mAh |
| 本应用持有的 wake lock | 只有 JobScheduler 自检的记账条目，标注 `(not used)` |
| 本应用注册的 alarm 唤醒 | 无 |

**口径说明**：这一小时设备接着 USB（`dumpsys battery` → `USB powered: true`、`status: 2`），所以 Android 报
`Time on battery: 0ms`，上面 mAh 是它的模型估算而不是实测放电；设备无法远程拔线，因此"真·离线浸泡"记为
已知未测项。可比的是同一模型下的 per-UID 数值，v0.0.9 基线按同样方式采集。

### 5.9 磁贴

```
$ cmd statusbar add-tile top.zztweb.zshield/.tile.ZShieldTileService
$ settings get secure sysui_qs_tiles
custom(top.zztweb.zshield/.tile.ZShieldTileService),internet,bt,dnd,...
$ dumpsys activity services top.zztweb.zshield
  * ServiceRecord{... u0 top.zztweb.zshield/.tile.ZShieldTileService c:com.android.systemui}
```

展开快捷设置后磁贴渲染为「ZShield 净盾」（`uiautomator dump` 里 `[44,599][276,797]`）。点击：

```
$ input tap 160 698
21:20:17.808 ZShield : tile: paused protection
$ dumpsys connectivity | grep -c IS_VPN -> 0

$ input tap 160 698     # 再点一次
21:20:34.491 ZShield : https filtering: true (...)
$ dumpsys connectivity | grep -c IS_VPN -> 1
$ ping -c 1 -W 2 doubleclick.net -> PING doubleclick.net (127.0.0.1)
```

### 5.10 用户主动关闭后重启不恢复

```
$ input tap 160 698        # 从磁贴关闭
21:20:55.513 ZShield : tile: paused protection
$ dumpsys connectivity | grep -c IS_VPN -> 0

$ adb reboot
$ dumpsys activity services top.zztweb.zshield -> (nothing)
$ dumpsys connectivity | grep -c IS_VPN -> 0
$ dumpsys activity broadcasts | grep -A6 BootRestoreReceiver
      DELIVERED scheduled +4s268ms terminal +55ms (-1) #127: (manifest)
          name=top.zztweb.zshield.vpn.BootRestoreReceiver
          enabled=true exported=true directBootAware=false
```

广播确实投递到了接收器（`DELIVERED`），它按 `protectionWanted=false` 做了「什么都不做」的决定：没有隧道、
没有常驻通知。对照组是 §5.2 —— 同一个触发器、同一个接收器，意图为真时打出
`recovery trigger=BOOT outcome=RECOVER`。

### 5.11 网络切换（部分）

`cmd wifi reassociate` 对 shell uid 被拒（`SecurityException: Uid 2000 does not have access to reassociate
wifi command`），设备无 SIM（`getprop gsm.sim.state` → `ABSENT`），飞行模式会切断 Wi-Fi 上的 adb。因此
「Wi-Fi ↔ 移动数据 ↔ 飞行模式」三态切换未测，记为已知未测项。已验证的部分：重启本身重建了整条网络栈，
隧道在新栈上恢复并继续拦截（§5.2/§5.3）。

## 6. 故障时的行为（fail-safe）

| 情况 | 行为 |
|---|---|
| 读设置失败 | 当作「用户没要求」，不自动拉起（宁可少开，不背着用户开） |
| 读 always-on 失败 | 当作未知，继续尝试恢复（否则隐藏该键的机型永久失效） |
| `establish` 失败 | `VpnState.Error` + 停止服务，不无限重试 |
| 周期自检自身异常 | 捕获并记日志，`jobFinished` 照常调用，不影响下次调度 |
| 用户已关闭 | 任何路径都不恢复，包括 sticky 重启 |

## 7. 参考文档

- Foreground service types（`systemExempted` 的可用条件）：https://developer.android.com/develop/background-work/services/fgs/service-types
- Restrictions on background start + exemptions（`BOOT_COMPLETED` / `MY_PACKAGE_REPLACED`）：
  https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start
- Android 15 行为变更：Restrictions on BOOT_COMPLETED broadcast receivers launching foreground services：
  https://developer.android.com/about/versions/15/behavior-changes-15#fgs-boot-completed
- Android 14 前台服务类型要求：https://developer.android.com/about/versions/14/changes/fgs-types-required
- Doze 与电池优化白名单（`ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`）：
  https://developer.android.com/training/monitoring-device-state/doze-standby
- `JobScheduler` 周期最小值 15 分钟：https://developer.android.com/reference/android/app/job/JobInfo#setPeriodic(long)
