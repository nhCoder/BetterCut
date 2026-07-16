package com.bettercut

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Safety-guard tests: the core must NEVER cut the router, this phone, or a
 * whitelisted device — no matter what it is handed. These exercise
 * NetScan.eligibleTargets, the single choke point every cut/throttle passes
 * through.
 */
class GuardsTest {

    private fun host(ip: String, mac: String, kind: Device.Kind = Device.Kind.HOST) =
        Device(ip = ip, mac = mac, hostname = "", vendor = "", kind = kind)

    private fun eligible(
        limits: List<Pair<Device, Int>>,
        gw: String? = "192.168.1.1",
        me: String? = "192.168.1.50",
        whitelist: Set<String> = emptySet(),
    ) = NetScan.eligibleTargets(limits, gw, me, whitelist)

    // --- whitelist ---

    @Test fun whitelistedDevice_isNeverCut() {
        val d = host("192.168.1.10", "aa:bb:cc:dd:ee:10")
        val out = eligible(listOf(d to 0), whitelist = setOf("aa:bb:cc:dd:ee:10"))
        assertTrue("whitelisted device must be excluded", out.isEmpty())
    }

    @Test fun whitelist_isCaseInsensitive() {
        // Device MAC uppercase, whitelist lowercase — must still match & exclude.
        val d = host("192.168.1.10", "AA:BB:CC:DD:EE:10")
        val out = eligible(listOf(d to 0), whitelist = setOf("aa:bb:cc:dd:ee:10"))
        assertTrue(out.isEmpty())
    }

    @Test fun nonWhitelistedDevice_passesWhenOthersWhitelisted() {
        val safe = host("192.168.1.10", "aa:bb:cc:dd:ee:10")
        val target = host("192.168.1.11", "aa:bb:cc:dd:ee:11")
        val out = eligible(listOf(safe to 0, target to 0), whitelist = setOf("aa:bb:cc:dd:ee:10"))
        assertEquals(listOf(target to 0), out)
    }

    // --- router / gateway ---

    @Test fun gatewayByIp_isNeverCut_evenIfMisclassifiedAsHost() {
        // Simulate a scan that failed to tag the gateway (kind==HOST). The IP
        // exclusion must still protect it — this is the router-safety case.
        val router = host("192.168.1.1", "aa:bb:cc:dd:ee:01", kind = Device.Kind.HOST)
        val out = eligible(listOf(router to 0), gw = "192.168.1.1")
        assertTrue("router must never be cut", out.isEmpty())
    }

    @Test fun gatewayByKind_isNeverCut() {
        val router = host("192.168.9.9", "aa:bb:cc:dd:ee:01", kind = Device.Kind.GATEWAY)
        val out = eligible(listOf(router to 0), gw = null) // even with gw IP unknown
        assertTrue(out.isEmpty())
    }

    // --- this phone ---

    @Test fun ownPhoneByIp_isNeverCut() {
        val phone = host("192.168.1.50", "02:00:00:00:00:00", kind = Device.Kind.HOST)
        val out = eligible(listOf(phone to 0), me = "192.168.1.50")
        assertTrue("this phone must never be cut", out.isEmpty())
    }

    @Test fun ownPhoneByKind_isNeverCut() {
        val phone = host("192.168.1.50", "", kind = Device.Kind.SELF)
        val out = eligible(listOf(phone to 0))
        assertTrue(out.isEmpty())
    }

    // --- malformed / degenerate ---

    @Test fun blankMac_isExcluded() {
        assertTrue(eligible(listOf(host("192.168.1.10", "") to 0)).isEmpty())
    }

    @Test fun nonIpv4_isExcluded() {
        assertTrue(eligible(listOf(host("fe80::1", "aa:bb:cc:dd:ee:10") to 0)).isEmpty())
    }

    @Test fun nullGatewayAndSelf_stillFiltersByKindAndWhitelist() {
        // Even with both gateway and self IP unknown, kind + whitelist still guard.
        val gw = host("10.0.0.1", "aa:bb:cc:dd:ee:01", kind = Device.Kind.GATEWAY)
        val self = host("10.0.0.2", "aa:bb:cc:dd:ee:02", kind = Device.Kind.SELF)
        val wl = host("10.0.0.3", "aa:bb:cc:dd:ee:03")
        val ok = host("10.0.0.4", "aa:bb:cc:dd:ee:04")
        val out = eligible(
            listOf(gw to 0, self to 0, wl to 0, ok to 0),
            gw = null, me = null, whitelist = setOf("aa:bb:cc:dd:ee:03"),
        )
        assertEquals(listOf(ok to 0), out)
    }

    // --- realistic "Cut all" over a whole subnet ---

    @Test fun cutAll_keepsOnlyRealHosts() {
        val devices = listOf(
            host("192.168.1.1", "aa:bb:cc:dd:ee:01", kind = Device.Kind.GATEWAY) to 0,
            host("192.168.1.50", "02:00:00:00:00:00", kind = Device.Kind.SELF) to 0,
            host("192.168.1.20", "aa:bb:cc:dd:ee:20") to 0,     // eligible
            host("192.168.1.21", "aa:bb:cc:dd:ee:21") to 0,     // whitelisted
            host("192.168.1.22", "aa:bb:cc:dd:ee:22") to 0,     // eligible
        )
        val out = eligible(devices, whitelist = setOf("aa:bb:cc:dd:ee:21"))
        assertEquals(
            setOf("192.168.1.20", "192.168.1.22"),
            out.map { it.first.ip }.toSet(),
        )
    }

    @Test fun throttleValuesArePreserved() {
        val d = host("192.168.1.20", "aa:bb:cc:dd:ee:20")
        val out = eligible(listOf(d to 4000))
        assertEquals(4000, out.single().second)
    }
}
