package com.bettercut

import android.content.Context

/**
 * MAC -> vendor lookup. Most modern phones use per-network randomized MACs
 * (the locally-administered bit is set); those have no real vendor, so we label
 * them "Private" instead of a bogus lookup. Real MACs use a bundled OUI list.
 */
object Vendor {

    private var oui: Map<String, String>? = null

    private fun load(context: Context): Map<String, String> {
        oui?.let { return it }
        val map = runCatching {
            context.assets.open("oui.txt").bufferedReader().useLines { lines ->
                lines.mapNotNull { line ->
                    val parts = line.trim().split(Regex("\\s+"), limit = 2)
                    if (parts.size == 2 && parts[0].length >= 6)
                        parts[0].uppercase().take(6) to parts[1] else null
                }.toMap()
            }
        }.getOrDefault(emptyMap())
        oui = map
        return map
    }

    /** True if the MAC is locally-administered (bit 1 of first octet) → randomized. */
    fun isRandomized(mac: String): Boolean {
        val first = mac.split(":").firstOrNull()?.toIntOrNull(16) ?: return false
        return first and 0x02 != 0
    }

    fun lookup(context: Context, mac: String): String {
        if (isRandomized(mac)) return "Private"
        val prefix = mac.replace(":", "").uppercase().take(6)
        return load(context)[prefix] ?: ""
    }
}
