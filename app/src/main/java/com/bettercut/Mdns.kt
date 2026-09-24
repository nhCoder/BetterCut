package com.bettercut

import java.net.DatagramPacket
import java.net.InetAddress
import java.net.MulticastSocket

/**
 * Dependency-free mDNS discovery. Queries common service types and reads the
 * A records in the responses, which map "hostname.local" -> IPv4 directly.
 * This is how device names (e.g. "Alis-iPhone.local") are learned, since most
 * devices ignore reverse-PTR queries but announce A records for their services.
 */
object Mdns {

    private const val MDNS_ADDR = "224.0.0.251"
    private const val MDNS_PORT = 5353

    private val SERVICES = listOf(
        "_services._dns-sd._udp.local",
        "_companion-link._tcp.local",
        "_rdlink._tcp.local",
        "_googlecast._tcp.local",
        "_airplay._tcp.local",
        "_raop._tcp.local",
        "_spotify-connect._tcp.local",
        "_workstation._tcp.local",
        "_device-info._tcp.local",
        "_smb._tcp.local",
    )

    /** Runs one discovery pass (~[listenMs]) and returns ip -> friendly name. */
    fun discover(listenMs: Int = 2500): Map<String, String> {
        val result = HashMap<String, String>()
        runCatching {
            MulticastSocket(MDNS_PORT).use { sock ->
                sock.reuseAddress = true
                sock.soTimeout = 400
                val group = InetAddress.getByName(MDNS_ADDR)
                runCatching { sock.joinGroup(group) }
                for (svc in SERVICES) {
                    val q = query(svc)
                    runCatching { sock.send(DatagramPacket(q, q.size, group, MDNS_PORT)) }
                }
                val buf = ByteArray(4096)
                val deadline = System.currentTimeMillis() + listenMs
                while (System.currentTimeMillis() < deadline) {
                    val pkt = DatagramPacket(buf, buf.size)
                    if (runCatching { sock.receive(pkt); true }.getOrDefault(false)) {
                        parseARecords(buf, pkt.length, result)
                    }
                }
                runCatching { sock.leaveGroup(group) }
            }
        }
        return result
    }

    private fun query(name: String): ByteArray {
        val out = ArrayList<Byte>()
        out.addAll(listOf(0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0).map { it.toByte() })
        for (label in name.split(".")) {
            out.add(label.length.toByte())
            out.addAll(label.toByteArray(Charsets.US_ASCII).toList())
        }
        out.add(0)
        out.addAll(listOf(0, 12).map { it.toByte() }) // QTYPE PTR
        out.addAll(listOf(0, 1).map { it.toByte() })  // QCLASS IN
        return out.toByteArray()
    }

    /** Walks every record; for each A record (type 1) records ip -> hostname. */
    private fun parseARecords(buf: ByteArray, len: Int, out: MutableMap<String, String>) {
        if (len < 12) return
        fun u16(i: Int) = ((buf[i].toInt() and 0xff) shl 8) or (buf[i + 1].toInt() and 0xff)
        val qd = u16(4)
        val total = u16(6) + u16(8) + u16(10) // an + ns + ar
        var p = 12
        repeat(qd) { p = skipName(buf, p, len) + 4 }
        var rec = 0
        while (rec < total && p + 10 <= len) {
            val (name, after) = readName(buf, p, len)
            p = after
            if (p + 10 > len) break
            val type = u16(p)
            val rdlen = u16(p + 8)
            val rdStart = p + 10
            if (type == 1 && rdlen == 4 && rdStart + 4 <= len) { // A record
                val ip = "${buf[rdStart].toInt() and 0xff}.${buf[rdStart + 1].toInt() and 0xff}." +
                    "${buf[rdStart + 2].toInt() and 0xff}.${buf[rdStart + 3].toInt() and 0xff}"
                val friendly = clean(name)
                if (friendly.isNotBlank() && out[ip].isNullOrBlank()) out[ip] = friendly
            }
            p = rdStart + rdlen
            rec++
        }
    }

    private fun clean(name: String): String =
        name.removeSuffix(".").removeSuffix(".local").trim()

    private fun skipName(buf: ByteArray, start: Int, len: Int): Int {
        var p = start
        while (p < len) {
            val b = buf[p].toInt() and 0xff
            if (b == 0) return p + 1
            if (b and 0xc0 == 0xc0) return p + 2
            p += 1 + b
        }
        return p
    }

    /** Returns (name, indexAfterName), following compression pointers for reading. */
    private fun readName(buf: ByteArray, start: Int, len: Int): Pair<String, Int> {
        val sb = StringBuilder()
        var p = start
        var after = -1
        var hops = 0
        while (p < len && hops < 30) {
            val b = buf[p].toInt() and 0xff
            if (b == 0) { if (after < 0) after = p + 1; break }
            if (b and 0xc0 == 0xc0) {
                if (after < 0) after = p + 2
                p = ((b and 0x3f) shl 8) or (buf[p + 1].toInt() and 0xff)
                hops++
                continue
            }
            if (p + 1 + b > len) break
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(buf, p + 1, b, Charsets.US_ASCII))
            p += 1 + b
        }
        if (after < 0) after = p
        return sb.toString() to after
    }
}
