package com.bettercut

import java.net.DatagramPacket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.MulticastSocket
import java.net.URL

/**
 * SSDP / UPnP discovery. Smart TVs, printers, routers, consoles, speakers and
 * media boxes answer an SSDP M-SEARCH and point to a description XML that
 * carries a human "friendlyName" — names mDNS/NBNS/DNS usually can't get.
 */
object Ssdp {

    private const val ADDR = "239.255.255.250"
    private const val PORT = 1900

    private val MSEARCH = (
        "M-SEARCH * HTTP/1.1\r\n" +
            "HOST: $ADDR:$PORT\r\n" +
            "MAN: \"ssdp:discover\"\r\n" +
            "MX: 2\r\n" +
            "ST: ssdp:all\r\n\r\n"
        ).toByteArray()

    /** One discovery pass; returns ip -> friendly device name. */
    fun discover(listenMs: Int = 2500): Map<String, String> {
        val locations = HashMap<String, String>() // ip -> description URL
        runCatching {
            MulticastSocket().use { sock ->
                sock.soTimeout = 400
                val group = InetAddress.getByName(ADDR)
                sock.send(DatagramPacket(MSEARCH, MSEARCH.size, group, PORT))
                val buf = ByteArray(2048)
                val deadline = System.currentTimeMillis() + listenMs
                while (System.currentTimeMillis() < deadline) {
                    val pkt = DatagramPacket(buf, buf.size)
                    if (!runCatching { sock.receive(pkt); true }.getOrDefault(false)) continue
                    val text = String(buf, 0, pkt.length, Charsets.US_ASCII)
                    val loc = header(text, "LOCATION")
                    val ip = pkt.address?.hostAddress
                    if (loc != null && ip != null && ip !in locations) locations[ip] = loc
                }
            }
        }
        val out = HashMap<String, String>()
        for ((ip, loc) in locations) {
            val name = friendlyName(loc)
            if (name.isNotBlank()) out[ip] = name
        }
        return out
    }

    private fun header(resp: String, name: String): String? =
        resp.lineSequence().firstOrNull { it.startsWith("$name:", ignoreCase = true) }
            ?.substringAfter(':')?.trim()

    private fun friendlyName(location: String): String = runCatching {
        val conn = (URL(location).openConnection() as HttpURLConnection).apply {
            connectTimeout = 1500; readTimeout = 1500; requestMethod = "GET"
        }
        try {
            if (conn.responseCode != 200) return ""
            val xml = conn.inputStream.bufferedReader().readText()
            Regex("<friendlyName>(.*?)</friendlyName>", RegexOption.DOT_MATCHES_ALL)
                .find(xml)?.groupValues?.get(1)?.trim().orEmpty()
        } finally {
            conn.disconnect()
        }
    }.getOrDefault("")
}
