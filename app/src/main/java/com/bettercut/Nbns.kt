package com.bettercut

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * NetBIOS Name Service (NBNS) node-status resolver. Many devices that don't do
 * mDNS — Windows PCs, Android phones, printers, NAS boxes — still answer a
 * NetBIOS node-status query (UDP 137) with their machine name. This fills in
 * names mDNS/DNS miss.
 */
object Nbns {

    /** Returns the device's NetBIOS name for [ip], or "" if it doesn't answer. */
    fun resolve(ip: String): String = runCatching {
        DatagramSocket().use { sock ->
            sock.soTimeout = 500
            val q = query()
            sock.send(DatagramPacket(q, q.size, InetAddress.getByName(ip), 137))
            val buf = ByteArray(1024)
            val resp = DatagramPacket(buf, buf.size)
            sock.receive(resp)
            parse(buf, resp.length)
        }
    }.getOrDefault("")

    /** NBSTAT query for the wildcard name "*". */
    private fun query(): ByteArray {
        val out = ArrayList<Byte>()
        out.addAll(listOf(0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0).map { it.toByte() }) // header, 1 question
        out.add(0x20)                                   // encoded name length (32)
        // First-level encode of "*" padded with 15 nulls.
        val name = ByteArray(16).also { it[0] = '*'.code.toByte() }
        for (b in name) {
            out.add(('A'.code + ((b.toInt() and 0xF0) ushr 4)).toByte())
            out.add(('A'.code + (b.toInt() and 0x0F)).toByte())
        }
        out.add(0)                                      // name terminator
        out.addAll(listOf(0, 0x21).map { it.toByte() }) // QTYPE NBSTAT
        out.addAll(listOf(0, 1).map { it.toByte() })    // QCLASS IN
        return out.toByteArray()
    }

    internal fun parse(buf: ByteArray, len: Int): String {
        // header(12) + qname(34) + type(2)+class(2)+ttl(4)+rdlen(2) = 56, then rdata.
        val rdata = 56
        if (len <= rdata) return ""
        val numNames = buf[rdata].toInt() and 0xff
        var p = rdata + 1
        var fallback = ""
        repeat(numNames) {
            if (p + 18 > len) return fallback
            val name = String(buf, p, 15, Charsets.US_ASCII).trim()
            val suffix = buf[p + 15].toInt() and 0xff
            val group = (buf[p + 16].toInt() and 0x80) != 0
            p += 18
            if (name.isNotEmpty() && !group) {
                if (suffix == 0x00) return name          // workstation name — best
                if (fallback.isEmpty()) fallback = name
            }
        }
        return fallback
    }
}
