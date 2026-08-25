package com.bettercut

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Tests the iptables byte-counter parsing behind the live traffic meter, using
 * real `iptables -vnxL` output shapes.
 */
class MeterTest {

    private val sample = """
        Chain BETTERCUT (1 references)
            pkts      bytes target     prot opt in     out     source               destination
             120  1500000 ACCEPT     all  --  *      *       0.0.0.0/0            192.168.1.20
              80    64000 ACCEPT     all  --  *      *       192.168.1.20         0.0.0.0/0
    """.trimIndent()

    @Test fun parsesDownloadAndUploadForDevice() {
        val (down, up) = NetScan.parseMeter(sample, "192.168.1.20").toList()
        assertEquals(1_500_000L, down)  // destination == device
        assertEquals(64_000L, up)       // source == device
    }

    @Test fun ignoresOtherDevicesRules() {
        val multi = """
            Chain BETTERCUT (1 references)
                pkts      bytes target     prot opt in     out     source               destination
                  1      100 ACCEPT     all  --  *      *       0.0.0.0/0            192.168.1.99
                 10  2000000 ACCEPT     all  --  *      *       0.0.0.0/0            192.168.1.20
                  5    50000 ACCEPT     all  --  *      *       192.168.1.20         0.0.0.0/0
        """.trimIndent()
        val (down, up) = NetScan.parseMeter(multi, "192.168.1.20").toList()
        assertEquals(2_000_000L, down)
        assertEquals(50_000L, up)
    }

    @Test fun zeroWhenDeviceAbsentOrEmptyChain() {
        assertEquals(listOf(0L, 0L), NetScan.parseMeter(sample, "10.0.0.1").toList())
        assertEquals(listOf(0L, 0L), NetScan.parseMeter("", "192.168.1.20").toList())
    }

    @Test fun ignoresDropRulesFromAConcurrentCut() {
        // A cut adds DROP rules; the meter must count only ACCEPT (forwarded) bytes.
        val withDrop = """
            Chain BETTERCUT (1 references)
                pkts      bytes target     prot opt in     out     source               destination
                  9      900 DROP       all  --  *      *       0.0.0.0/0            192.168.1.20
                 10  3000000 ACCEPT     all  --  *      *       0.0.0.0/0            192.168.1.20
                  5    50000 ACCEPT     all  --  *      *       192.168.1.20         0.0.0.0/0
        """.trimIndent()
        val (down, up) = NetScan.parseMeter(withDrop, "192.168.1.20").toList()
        assertEquals(3_000_000L, down)
        assertEquals(50_000L, up)
    }
}
