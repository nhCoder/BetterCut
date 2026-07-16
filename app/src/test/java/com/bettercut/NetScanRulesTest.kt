package com.bettercut

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the pure netfilter-rule and poison-mode logic — the throttle
 * correctness the user cares about — with no device or root involved.
 */
class NetScanRulesTest {

    // --- kBytesPerSec: UI kbit/s -> hashlimit kByte/s ---

    @Test fun kBytesPerSec_convertsBitsToBytes() {
        assertEquals(500, NetScan.kBytesPerSec(4000))  // 500 KB/s preset
        assertEquals(50, NetScan.kBytesPerSec(400))    // 50 KB/s preset (smallest)
        assertEquals(1000, NetScan.kBytesPerSec(8000)) // 1 MB/s preset
        assertEquals(5000, NetScan.kBytesPerSec(40000))// 5 MB/s preset
    }

    @Test fun kBytesPerSec_neverBelowOne() {
        assertEquals(1, NetScan.kBytesPerSec(0))
        assertEquals(1, NetScan.kBytesPerSec(4))
        assertEquals(1, NetScan.kBytesPerSec(-100))
    }

    // --- poisonMode: cut = victim-only, throttle = both ---

    @Test fun poisonMode_cutIsVictimOnly() {
        assertEquals("v", NetScan.poisonMode(0))
        assertEquals("v", NetScan.poisonMode(-1))
    }

    @Test fun poisonMode_throttleIsBoth() {
        assertEquals("b", NetScan.poisonMode(4000))
        assertEquals("b", NetScan.poisonMode(1))
    }

    // --- bettercutRules: cut ---

    @Test fun cut_isTwoDropsNoAccept() {
        val rules = NetScan.bettercutRules(listOf("192.168.1.10" to 0))
        assertEquals(
            listOf(
                "iptables -A BETTERCUT -s 192.168.1.10 -j DROP",
                "iptables -A BETTERCUT -d 192.168.1.10 -j DROP",
            ),
            rules,
        )
        assertTrue(rules.none { "ACCEPT" in it })
        assertTrue(rules.none { "hashlimit" in it })
    }

    // --- bettercutRules: throttle ---

    @Test fun throttle_hasHashlimitDropAndBothAccepts() {
        val rules = NetScan.bettercutRules(listOf("192.168.1.20" to 4000))
        assertEquals(3, rules.size)
        assertTrue(rules[0].contains("-d 192.168.1.20 -m hashlimit"))
        assertTrue(rules[0].contains("--hashlimit-above 500kb/s"))
        assertTrue(rules[0].contains("--hashlimit-burst 500kb"))
        assertTrue(rules[0].contains("--hashlimit-name bcd1"))
        assertTrue(rules[0].endsWith("-j DROP"))
        // The two ACCEPTs that bypass Android's OEM forward chains must be present.
        assertEquals("iptables -A BETTERCUT -d 192.168.1.20 -j ACCEPT", rules[1])
        assertEquals("iptables -A BETTERCUT -s 192.168.1.20 -j ACCEPT", rules[2])
    }

    @Test fun throttle_burstNeverBelowRate_forEveryPreset() {
        // Every real preset must satisfy iptables' rule: burst >= rate, and
        // burst >= the 12288-byte (12kb) floor. rate==burst==kBps here.
        for (kbps in listOf(400, 800, 2000, 4000, 8000, 16000, 40000)) {
            val kBps = NetScan.kBytesPerSec(kbps)
            assertTrue("burst below 12kb floor for $kbps", kBps >= 12)
            val rule = NetScan.bettercutRules(listOf("10.0.0.1" to kbps))[0]
            assertTrue(rule.contains("--hashlimit-above ${kBps}kb/s"))
            assertTrue(rule.contains("--hashlimit-burst ${kBps}kb"))
        }
    }

    @Test fun multipleThrottles_getUniqueHashlimitNames() {
        val rules = NetScan.bettercutRules(
            listOf("10.0.0.1" to 4000, "10.0.0.2" to 8000),
        )
        val names = rules.filter { "hashlimit-name" in it }
            .map { Regex("--hashlimit-name (bcd\\d+)").find(it)!!.groupValues[1] }
        assertEquals(listOf("bcd1", "bcd2"), names)
        assertEquals(names.size, names.toSet().size)  // all unique
    }

    @Test fun mixedSet_cutsAndThrottles_idCountsOnlyThrottles() {
        // cut, throttle, cut, throttle — hashlimit ids must be bcd1, bcd2 (cuts
        // don't consume an id).
        val rules = NetScan.bettercutRules(
            listOf(
                "10.0.0.1" to 0,
                "10.0.0.2" to 4000,
                "10.0.0.3" to 0,
                "10.0.0.4" to 8000,
            ),
        )
        val names = rules.filter { "hashlimit-name" in it }
            .map { Regex("--hashlimit-name (bcd\\d+)").find(it)!!.groupValues[1] }
        assertEquals(listOf("bcd1", "bcd2"), names)
        // 2 cuts * 2 lines + 2 throttles * 3 lines = 10 lines
        assertEquals(10, rules.size)
    }

    @Test fun emptySet_yieldsNoRules() {
        assertTrue(NetScan.bettercutRules(emptyList()).isEmpty())
    }

    // --- Vendor.isRandomized: locally-administered bit ---

    @Test fun isRandomized_detectsLocallyAdministeredBit() {
        assertTrue(Vendor.isRandomized("02:00:00:00:00:00"))   // Android anon MAC
        assertTrue(Vendor.isRandomized("06:11:22:33:44:55"))   // bit 0x02 set
        assertFalse(Vendor.isRandomized("3c:5a:b4:11:22:33"))  // real OUI, bit clear
        assertFalse(Vendor.isRandomized("fc:00:00:00:00:00"))  // bit clear
    }

    @Test fun isRandomized_handlesGarbageSafely() {
        assertFalse(Vendor.isRandomized("not-a-mac"))
        assertFalse(Vendor.isRandomized(""))
    }

    // --- Nbns.parse: NetBIOS node-status name extraction ---

    @Test fun nbns_parsePrefersWorkstationName() {
        // Craft a node-status response: 56-byte prefix, then numNames + 18-byte
        // entries. Entry names are 15 ASCII chars + suffix + 2 flag bytes.
        val entry1 = nbnsEntry("FILESERVER", suffix = 0x20, group = false) // service
        val entry2 = nbnsEntry("MY-LAPTOP", suffix = 0x00, group = false)  // workstation
        val buf = ByteArray(56) + byteArrayOf(2) + entry1 + entry2
        assertEquals("MY-LAPTOP", Nbns.parse(buf, buf.size))
    }

    @Test fun nbns_ignoresGroupNamesAndFallsBack() {
        val group = nbnsEntry("WORKGROUP", suffix = 0x00, group = true)     // group → skip
        val svc = nbnsEntry("PRINTER01", suffix = 0x20, group = false)      // fallback
        val buf = ByteArray(56) + byteArrayOf(2) + group + svc
        assertEquals("PRINTER01", Nbns.parse(buf, buf.size))
    }

    @Test fun nbns_emptyOnTruncated() {
        assertEquals("", Nbns.parse(ByteArray(40), 40))
    }

    /** One 18-byte NBNS node-status entry: 15-char name, suffix, flags(2). */
    private fun nbnsEntry(name: String, suffix: Int, group: Boolean): ByteArray {
        val n = name.padEnd(15).substring(0, 15).toByteArray(Charsets.US_ASCII)
        val flags = if (group) 0x80 else 0x00
        return n + byteArrayOf(suffix.toByte(), flags.toByte(), 0)
    }
}
