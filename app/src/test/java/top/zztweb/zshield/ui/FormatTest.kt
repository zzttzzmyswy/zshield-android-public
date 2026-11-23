package top.zztweb.zshield.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.TimeZone

class FormatTest {

    @Test
    fun groupedUsesCommas() {
        assertEquals("0", Format.grouped(0))
        assertEquals("376,661", Format.grouped(376_661))
    }

    @Test
    fun compactSwitchesToChineseUnits() {
        assertEquals("9,999", Format.compact(9_999))
        assertEquals("1万", Format.compact(10_000))
        assertEquals("3.7万", Format.compact(37_999))
        assertEquals("37.6万", Format.compact(376_661))
        assertEquals("9999.9万", Format.compact(99_999_999))
        assertEquals("1.2亿", Format.compact(123_456_789))
    }

    @Test
    fun bytesUsesBinaryUnits() {
        assertEquals("0 B", Format.bytes(0))
        assertEquals("1023 B", Format.bytes(1023))
        assertEquals("1.0 KB", Format.bytes(1024))
        assertEquals("1.5 MB", Format.bytes(1_572_864))
        assertEquals("2.0 GB", Format.bytes(2L * 1024 * 1024 * 1024))
    }

    @Test
    fun percentHandlesZeroAndOverflow() {
        assertNull(Format.percent(1, 0))
        assertEquals("12.5%", Format.percent(1, 8))
        assertEquals("100.0%", Format.percent(9, 8))
    }

    @Test
    fun agoBuckets() {
        val now = 1_000_000_000_000L
        assertEquals("从未", Format.ago(now, 0))
        assertEquals("刚刚", Format.ago(now, now + 5_000))
        assertEquals("刚刚", Format.ago(now, now - 59_000))
        assertEquals("5 分钟前", Format.ago(now, now - 5 * 60_000))
        assertEquals("3 小时前", Format.ago(now, now - 3 * 3_600_000))
        assertEquals("2 天前", Format.ago(now, now - 2 * 86_400_000L))
        assertEquals("2 个月前", Format.ago(now, now - 61 * 86_400_000L))
    }

    @Test
    fun sinceStartAndClock() {
        assertEquals("+00:00", Format.sinceStart(-5))
        assertEquals("+01:05", Format.sinceStart(65_000))
        assertEquals("+1:00:01", Format.sinceStart(3_601_000))
        assertEquals("08:00:01", Format.clock(1_000, TimeZone.getTimeZone("GMT+8")))
    }

    @Test
    fun intervalAndRuleLines() {
        assertEquals("6 小时", Format.interval(6))
        assertEquals("1 天", Format.interval(24))
        assertEquals("36 小时", Format.interval(36))
        assertEquals("850 ms", Format.duration(850))
        assertEquals("20.4 s", Format.duration(20_356))
        assertEquals("脚本", Format.requestKind("script"))
        assertEquals("其他", Format.requestKind("other"))
        assertEquals("csp_report", Format.requestKind("csp_report"))
        assertEquals(2, Format.ruleLines("! comment\n||ads.example^\n\n  # hosts comment\n@@||ok.example^\n"))
    }
}
