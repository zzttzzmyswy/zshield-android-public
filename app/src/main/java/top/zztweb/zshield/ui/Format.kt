package top.zztweb.zshield.ui

import java.util.Locale

/**
 * Pure formatting helpers shared by the screens. Kept free of Android types so they are unit-tested
 * on the JVM (`FormatTest`).
 */
object Format {

    /** `1234567` → `1,234,567`. */
    fun grouped(value: Long): String = String.format(Locale.ROOT, "%,d", value)

    /**
     * Compact count for hero numbers, in the units a Chinese reader expects:
     * below 10 000 the full grouped number, then `万` (10⁴) and `亿` (10⁸) with one decimal that is
     * dropped when it is zero (`3.0万` → `3万`).
     */
    fun compact(value: Long): String {
        val abs = kotlin.math.abs(value)
        return when {
            abs < 10_000 -> grouped(value)
            abs < 100_000_000 -> scaled(value, 10_000.0) + "万"
            else -> scaled(value, 100_000_000.0) + "亿"
        }
    }

    private fun scaled(value: Long, unit: Double): String {
        // Truncate instead of rounding so a counter never displays a value it has not reached.
        val tenths = kotlin.math.floor(value / unit * 10).toLong()
        return if (tenths % 10 == 0L) (tenths / 10).toString() else "${tenths / 10}.${kotlin.math.abs(tenths % 10)}"
    }

    /** Binary byte size with one decimal: `0 B`, `512 B`, `1.5 KB`, `23.4 MB`, `1.2 GB`. */
    fun bytes(value: Long): String {
        if (value < 1024) return "$value B"
        val units = arrayOf("KB", "MB", "GB", "TB")
        var size = value / 1024.0
        var index = 0
        while (size >= 1024 && index < units.lastIndex) {
            size /= 1024
            index++
        }
        return String.format(Locale.ROOT, "%.1f %s", size, units[index])
    }

    /** Share of [part] in [total] as `12.3%`, or `null` when there is nothing to divide. */
    fun percent(part: Long, total: Long): String? {
        if (total <= 0) return null
        val ratio = part.coerceIn(0, total).toDouble() / total * 100
        return String.format(Locale.ROOT, "%.1f%%", ratio)
    }

    /**
     * How long ago [thenMs] was, relative to [nowMs]. `0` means "never". Clock skew (a time in the
     * future) is shown as "just now" rather than a negative duration.
     */
    fun ago(nowMs: Long, thenMs: Long): String {
        if (thenMs <= 0) return "从未"
        val seconds = ((nowMs - thenMs) / 1000).coerceAtLeast(0)
        return when {
            seconds < 60 -> "刚刚"
            seconds < 3_600 -> "${seconds / 60} 分钟前"
            seconds < 86_400 -> "${seconds / 3_600} 小时前"
            seconds < 86_400 * 30 -> "${seconds / 86_400} 天前"
            else -> "${seconds / (86_400 * 30)} 个月前"
        }
    }

    /** Offset from tunnel start, `+mm:ss` or `+h:mm:ss`, for log rows whose wall time is unknown. */
    fun sinceStart(offsetMs: Long): String {
        val total = (offsetMs / 1000).coerceAtLeast(0)
        val h = total / 3600
        val m = (total % 3600) / 60
        val s = total % 60
        return if (h > 0) String.format(Locale.ROOT, "+%d:%02d:%02d", h, m, s)
        else String.format(Locale.ROOT, "+%02d:%02d", m, s)
    }

    /** Wall-clock `HH:mm:ss` in the device time zone. */
    fun clock(epochMs: Long, zone: java.util.TimeZone = java.util.TimeZone.getDefault()): String {
        val calendar = java.util.Calendar.getInstance(zone).apply { timeInMillis = epochMs }
        return String.format(
            Locale.ROOT, "%02d:%02d:%02d",
            calendar.get(java.util.Calendar.HOUR_OF_DAY),
            calendar.get(java.util.Calendar.MINUTE),
            calendar.get(java.util.Calendar.SECOND),
        )
    }

    /** Elapsed time: `850 ms`, `20.4 s`. */
    fun duration(ms: Long): String =
        if (ms < 1000) "$ms ms" else String.format(Locale.ROOT, "%.1f s", ms / 1000.0)

    /** Human label for an auto-update interval in hours: `6 小时`, `1 天`, `7 天`. */
    fun interval(hours: Int): String =
        if (hours >= 24 && hours % 24 == 0) "${hours / 24} 天" else "$hours 小时"

    /** Chinese label for a request kind from the core (`document`, `script`, ...); unknown kinds pass through. */
    fun requestKind(kind: String): String = when (kind) {
        "document" -> "页面"
        "subdocument" -> "子页面"
        "script" -> "脚本"
        "stylesheet" -> "样式"
        "image" -> "图片"
        "font" -> "字体"
        "media" -> "媒体"
        "xhr", "xmlhttprequest", "fetch" -> "XHR"
        "websocket" -> "WebSocket"
        "ping", "beacon" -> "Ping"
        "other" -> "其他"
        else -> kind
    }

    /** Number of non-empty, non-comment lines in a rules text (what the editor shows as a count). */
    fun ruleLines(text: String): Int =
        text.lineSequence().map { it.trim() }.count { it.isNotEmpty() && !it.startsWith("!") && !it.startsWith("#") }
}
