package com.bettercut

import android.content.Context
import android.net.wifi.WifiManager
import org.json.JSONArray
import java.io.File
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

/** A host on the LAN. */
data class Device(
    val ip: String,
    val mac: String,
    val hostname: String,
    val vendor: String,
    val kind: Kind = Kind.HOST,
) {
    enum class Kind { HOST, GATEWAY, SELF }

    val displayName: String
        get() = hostname.ifBlank { if (ip.isNotBlank()) ip else mac }
}

/**
 * Native LAN scanner + ARP cutter. Replaces bettercap entirely:
 *  - discovery/MACs: libarpcut.so `scan` (raw ARP sweep, needs root)
 *  - gateway: routing table
 *  - hostnames: mDNS + reverse DNS (Kotlin)
 *  - vendor: bundled OUI + randomized-MAC detection (Kotlin)
 *  - cut: libarpcut.so `cut`
 */
object NetScan {

    private val cutProc = AtomicReference<Process?>(null)
    private val names = ConcurrentHashMap<String, String>()   // ip -> hostname
    private val accumulated = ConcurrentHashMap<String, Device>() // mac -> device
    private val resolvers = Executors.newFixedThreadPool(2)
    @Volatile private var discovering = false

    @Volatile var lastGateway: String? = null
        private set
    @Volatile private var lastGatewayMac: String? = null
    @Volatile private var lastIface = "wlan0"
    @Volatile private var logFile: java.io.File? = null

    /** Presence of this file = "a cut should be running". Deleting it signals the
     *  root watchdog to kill the poisoner, so the cut never outlives the app. */
    @Volatile private var flagFile: java.io.File? = null

    /** Absolute path to libarpcut.so, cached so heal/stop paths that have no
     *  Context can still invoke the tool. */
    @Volatile private var toolPathCached: String? = null

    /** The victims currently ARP-poisoned, as (ip, mac). We keep this so that
     *  when a cut is lifted — fully, or by dropping a device from the set — we
     *  can send corrective ARP ("heal") to exactly those hosts and the gateway,
     *  making the restore immediate instead of waiting for cache timeout. */
    @Volatile private var lastTargets: List<Pair<String, String>> = emptyList()

    /** Gateway that the ACTIVE cut was built against, cached independently of
     *  scan state. A rescan calls reset(), which nulls lastGateway/lastGatewayMac
     *  and clears the accumulated table — so without this, healing or modifying a
     *  cut during/just-after a rescan would find no gateway and silently fail to
     *  heal (the classic "restore didn't work" symptom). Set when a cut is
     *  applied; used as the source of truth for heal and as an apply-time
     *  fallback. */
    @Volatile private var cutGwIp: String? = null
    @Volatile private var cutGwMac: String? = null

    /** The value of /proc/sys/net/ipv4/ip_forward BEFORE we first touched it this
     *  session, so a full teardown restores exactly what was there (bettercap does
     *  this — issue #1261 — so e.g. an active hotspot's forwarding isn't left
     *  broken). Null = we haven't changed it yet. */
    @Volatile private var savedIpForward: String? = null

    /** Kills every running poisoner, however it was orphaned. Matches on BOTH
     *  /proc/<pid>/exe (the real binary path) AND /proc/<pid>/comm (the process
     *  name, "libarpcut.so") — never on the cmdline, because the issuing shell's
     *  own command line contains "libarpcut" and `pkill -f` would kill it before
     *  it reaches the poisoners. The shell's exe/comm is mksh, so it's safe. */
    private val KILL_POISONERS =
        "for p in /proc/[0-9]*; do " +
            "e=\$(readlink \$p/exe 2>/dev/null); c=\$(cat \$p/comm 2>/dev/null); " +
            "case \"\$e\$c\" in *libarpcut*) kill -9 \${p##*/} 2>/dev/null;; esac; done"

    // Permanent name cache (mac -> name), so a once-resolved name always shows.
    private val persistNames = ConcurrentHashMap<String, String>()
    private var namePrefs: android.content.SharedPreferences? = null

    /** Flight recorder + persistent name cache init. */
    fun initLog(context: Context) {
        val f = java.io.File(context.filesDir, "rootlog.txt")
        runCatching { if (f.length() > 200_000) f.writeText("") }
        logFile = f
        toolPathCached = toolPath(context)
        flagFile = java.io.File(context.filesDir, "cut.active")
        runCatching { flagFile?.delete() } // stale flag from a previous run
        val p = context.getSharedPreferences("bettercut_names", Context.MODE_PRIVATE)
        namePrefs = p
        runCatching { p.all.forEach { (k, v) -> if (v is String && v.isNotBlank()) persistNames[k] = v } }
    }

    private fun rememberName(mac: String, name: String) {
        // Only persist a genuine name — never blank, an IP, or a UUID blob.
        if (name.isBlank() || isUgly(name) ||
            name.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))
        ) return
        val m = mac.lowercase()
        if (persistNames[m] == name) return
        persistNames[m] = name
        runCatching { namePrefs?.edit()?.putString(m, name)?.apply() }
    }

    private fun rlog(msg: String) {
        runCatching { logFile?.appendText("${System.currentTimeMillis()} $msg\n") }
    }
    private var mcastLock: WifiManager.MulticastLock? = null

    /** Android drops inbound multicast (mDNS replies) unless a lock is held. */
    private fun ensureMulticast(context: Context) {
        if (mcastLock?.isHeld == true) return
        runCatching {
            val wifi = context.applicationContext
                .getSystemService(Context.WIFI_SERVICE) as WifiManager
            mcastLock = wifi.createMulticastLock("bettercut-mdns").apply {
                setReferenceCounted(false); acquire()
            }
        }
    }

    fun toolPath(context: Context): String =
        File(context.applicationInfo.nativeLibraryDir, "libarpcut.so").absolutePath

    fun isPresent(context: Context): Boolean = File(toolPath(context)).exists()

    /** Clears accumulated state; call when starting a fresh scan session. */
    fun reset() {
        accumulated.clear()
        names.clear()
        nameAttempts.clear()
        // persistNames is intentionally kept — remembered names survive across scans.
        lastGateway = null
        lastGatewayMac = null
    }

    /**
     * Runs one native ARP sweep, merges results into the accumulated set, and
     * returns the current device list. Hostnames resolve in the background and
     * appear on subsequent sweeps. Requires root; returns the last-known list on
     * failure.
     */
    fun scan(context: Context, iface: String): List<Device> {
        ensureMulticast(context)
        lastIface = iface.ifBlank { "wlan0" }
        // Cache the gateway — it rarely changes, so avoid an `su ip route` every sweep.
        val gwIp = lastGateway ?: detectGateway(iface).also { lastGateway = it }
        val myIp = myIpv4(iface)
        val myMac = myMac(iface)

        val hosts = kernelScan(lastIface).toMutableList()
        if (myIp != null && myMac != null) hosts.add(myIp to myMac) // add ourselves
        for ((ip, mac) in hosts) {
            if (mac.isBlank()) continue
            val kind = when (ip) {
                gwIp -> Device.Kind.GATEWAY
                myIp -> Device.Kind.SELF
                else -> Device.Kind.HOST
            }
            if (kind == Device.Kind.GATEWAY) lastGatewayMac = mac
            val macL = mac.lowercase()
            val fresh = names[ip]?.takeIf { it.isNotBlank() && !isUgly(it) }
            if (fresh != null) rememberName(macL, fresh)
            accumulated[macL] = Device(
                ip = ip,
                mac = mac,
                hostname = fresh ?: persistNames[macL].orEmpty(), // remembered name persists
                vendor = Vendor.lookup(context, mac),
                kind = kind,
            )
        }
        // Android hides an app's own WiFi MAC (privacy), so the sweep above often
        // can't include this phone. Add it explicitly as SELF so the user sees
        // their device in the list — it's kind==SELF, so it's never a Cut all /
        // Throttle all target and can't be cut individually either.
        if (myIp != null && accumulated.values.none { it.kind == Device.Kind.SELF }) {
            accumulated[myMac?.lowercase() ?: "self"] = Device(
                ip = myIp,
                mac = myMac.orEmpty(),
                hostname = "This device",
                vendor = "",
                kind = Device.Kind.SELF,
            )
        }
        triggerDiscovery()

        return accumulated.values.sortedWith(
            compareBy({ kindRank(it.kind) }, { ipSortKey(it.ip) })
        )
    }

    private fun kindRank(k: Device.Kind): Int = when (k) {
        Device.Kind.GATEWAY -> 0
        Device.Kind.SELF -> 1
        Device.Kind.HOST -> 2
    }

    private val nameAttempts = ConcurrentHashMap<String, Int>()

    /** True for UUID/hex-blob "names" so a friendlier source can replace them. */
    private fun isUgly(name: String): Boolean =
        name.matches(Regex("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-.*")) ||
            (name.length >= 24 && name.count { it == '-' } >= 3)

    private fun hasGoodName(ip: String): Boolean {
        val n = names[ip]
        return !n.isNullOrBlank() && !isUgly(n)
    }

    private fun triggerDiscovery() {
        if (discovering) return
        discovering = true
        resolvers.execute {
            // mDNS (.local) + SSDP/UPnP (friendlyName) batch discovery.
            runCatching { Mdns.discover().forEach { (ip, n) -> if (!hasGoodName(ip)) names[ip] = n } }
            runCatching { Ssdp.discover().forEach { (ip, n) -> if (!hasGoodName(ip)) names[ip] = n } }

            for (d in accumulated.values) {
                val ip = d.ip
                if ("." !in ip || hasGoodName(ip)) continue
                // Already have a remembered name for this device? no need to hammer it.
                if (persistNames[d.mac.lowercase()]?.let { !isUgly(it) } == true) continue
                // Keep retrying (unlike before, which gave up after one miss) — a
                // device may answer NetBIOS/DNS on a later attempt. Cap so truly
                // silent devices don't get probed forever.
                val tries = nameAttempts.getOrDefault(ip, 0)
                if (tries >= 8) continue
                nameAttempts[ip] = tries + 1
                val nb = runCatching { Nbns.resolve(ip) }.getOrDefault("")
                if (nb.isNotBlank()) { names[ip] = nb; continue }
                runCatching {
                    val n = java.net.InetAddress.getByName(ip).canonicalHostName
                    if (n != ip && n.isNotBlank()) names[ip] = n.removeSuffix(".").removeSuffix(".local")
                }
            }
            discovering = false
        }
    }

    /**
     * Applies per-device limits. Each entry is (device, kbps): kbps == 0 blocks
     * the device entirely (cut); kbps > 0 throttles it to that rate; devices not
     * listed are left unlimited (untouched). All listed devices are ARP-poisoned
     * so their traffic reaches us; the kernel then forwards it, and our FORWARD
     * sub-chain either drops it (block) or drop-polices it to the target rate
     * (throttle). Empty list = clear all.
     *
     * IMPORTANT: we never attach a `tc` qdisc/filter to the wifi interface.
     * Shaping forwarded packets on wlan0's qdisc hard-crashes this Qualcomm WiFi
     * firmware (watchdog reboot). Plain forwarding + netfilter policing was
     * measured safe under sustained load, so all rate-limiting is done that way.
     */
    @Volatile private var shapingActive = false

    /** Undo our forwarding/iptables setup. Runs UNCONDITIONALLY — a no-op
     *  teardown is cheap, but skipping it because `shapingActive` drifted out of
     *  sync would leave the phone forwarding/hairpinning the LAN after a stop,
     *  which is exactly the "network still slow after exit" failure. Safe anytime;
     *  touches only our own chain, routing rules, and ip_forward. */
    private fun teardownNetworking() {
        // Wipe our rules/routes, then restore ip_forward to its pre-session value
        // (default 0 if we never recorded one) — never leave forwarding stuck on.
        val restore = "echo ${savedIpForward ?: "0"} > /proc/sys/net/ipv4/ip_forward 2>/dev/null"
        runRoot(wipeRulesScript() + "\n" + restore)
        savedIpForward = null
        shapingActive = false
    }

    /** Reads and remembers the original ip_forward value the first time we're
     *  about to change it, so teardown can put it back exactly. */
    private fun saveIpForwardOnce() {
        if (savedIpForward != null) return
        val v = runRoot("cat /proc/sys/net/ipv4/ip_forward 2>/dev/null").trim().firstOrNull()?.toString()
        savedIpForward = if (v == "0" || v == "1") v else "0"
    }

    @Synchronized
    fun applyLimits(context: Context, limits: List<Pair<Device, Int>>) {
        val previous = lastTargets

        // Resolve the gateway UP FRONT (best effort) so it can be excluded by IP
        // even if the scan misclassified it as a HOST — which happens whenever
        // gateway detection failed at scan time. This is independent of the
        // kind==HOST check, so the router is protected by two separate mechanisms.
        val gwIpForGuard = lastGateway ?: cutGwIp ?: detectGateway(lastIface)
        val myIp = myIpv4(lastIface)
        val whitelist = readWhitelist(context)

        // The ONE choke point every cut/throttle passes through. Defense in depth:
        // the UI already filters, but the core itself NEVER touches the gateway,
        // this phone, a non-HOST, or a whitelisted device. See eligibleTargets.
        val usable = eligibleTargets(limits, gwIpForGuard, myIp, whitelist)

        // FULL RECONCILE — this is the fix for the sync/restore drift. Every change
        // first returns the network to a CLEAN baseline: stop all poisoning,
        // actively HEAL everyone we were poisoning (so anything removed from the
        // set — a lifted cut OR throttle — genuinely recovers), and strip ALL our
        // iptables/routing state. Only THEN do we re-establish exactly the desired
        // set from scratch. Result: a device is never left half-cut, the desired
        // set is always what's actually enforced, and the notification always
        // matches. Devices that stay cut get a ~1 s heal-then-recut blip — a fair
        // price for state that can't drift. This mirrors how bettercap fully
        // un-spoofs on every stop rather than tracking partial diffs.
        killPoisoners()
        if (previous.isNotEmpty()) healTargets(previous)
        lastTargets = emptyList()
        teardownNetworking()

        if (usable.isEmpty()) {
            CutService.stop(context)
            return
        }

        // Re-establish from scratch. If the gateway is unknown we can't proceed —
        // but everything is already healed/torn down, so the failure just leaves
        // every device WORKING rather than stuck (a safe failure).
        val gwIp = gwIpForGuard ?: run {
            CutService.stop(context); throw RuntimeException("gateway unknown")
        }
        val gwMac = lastGatewayMac
            ?: accumulated.values.firstOrNull { it.ip == gwIp }?.mac
            ?: cutGwMac
            ?: run { CutService.stop(context); throw RuntimeException("gateway MAC unknown — let the scan run first") }
        cutGwIp = gwIp
        cutGwMac = gwMac

        // ARP-poison the desired set (full-duplex "@b" — poison victim AND gateway
        // so the cut lands even on devices that ignore unsolicited ARP), then
        // install its forwarding/netfilter rules.
        rlog("CUT ${usable.size} targets rates=${usable.map { it.second }}")
        launchPoisoner(context, gwIp, gwMac,
            usable.map { (d, kbps) -> "${d.ip}@${d.mac}@${poisonMode(kbps)}" })
        saveIpForwardOnce()
        runRoot(policeScript(usable, gwIp))
        shapingActive = true
        lastTargets = usable.map { it.first.ip to it.first.mac }
        CutService.update(context, usable.size)
    }

    /** Reads the whitelisted MACs (lowercased) straight from prefs, so the core
     *  guard uses the authoritative set even if an in-memory copy is stale. */
    private fun readWhitelist(context: Context): Set<String> = runCatching {
        context.getSharedPreferences("bettercut", Context.MODE_PRIVATE)
            .getStringSet("whitelist", emptySet()).orEmpty()
            .map { it.lowercase() }.toSet()
    }.getOrDefault(emptySet())

    /**
     * The single safety filter every cut/throttle passes through. A device is
     * eligible ONLY if all of these hold — so the router, this phone, and any
     * whitelisted device can never be cut, regardless of UI state or a scan
     * misclassification:
     *  - it has a real MAC and an IPv4 address,
     *  - it is a HOST (never GATEWAY or SELF),
     *  - its IP is not the gateway's and not this phone's,
     *  - its MAC is not whitelisted.
     * Pure and unit-tested; [whitelist] must be lowercased.
     */
    internal fun eligibleTargets(
        limits: List<Pair<Device, Int>>,
        gatewayIp: String?,
        myIp: String?,
        whitelist: Set<String>,
    ): List<Pair<Device, Int>> = limits.filter { (d, _) ->
        d.mac.isNotBlank() &&
            "." in d.ip &&
            d.kind == Device.Kind.HOST &&
            d.ip != gatewayIp &&
            d.ip != myIp &&
            d.mac.lowercase() !in whitelist
    }

    /** Launches the root poisoner for the given "ip@mac@mode" specs, wrapped in a
     *  watchdog that kills it the instant our app process dies (force-stop, crash,
     *  task-killer), the flag file is removed (a clean stop), or it exits itself —
     *  so a poisoner can never outlive the app. Shared by cut/throttle and the
     *  traffic meter. */
    private fun launchPoisoner(context: Context, gwIp: String, gwMac: String, specs: List<String>) {
        val args = buildList {
            add(toolPath(context)); add("cut"); add(lastIface)
            add(gwIp); add(gwMac); add("0")
            addAll(specs)
        }
        val shellLine = args.joinToString(" ") { "'" + it.replace("'", "'\\''") + "'" }
        val appPid = android.os.Process.myPid()
        val flag = (flagFile ?: java.io.File(context.filesDir, "cut.active")).also {
            flagFile = it; runCatching { it.writeText("1") }
        }.absolutePath
        val guarded =
            "$shellLine & CP=\$!; " +
                "while kill -0 $appPid 2>/dev/null && [ -f '$flag' ] && kill -0 \$CP 2>/dev/null; do sleep 1; done; " +
                "kill -9 \$CP 2>/dev/null"
        cutProc.set(ProcessBuilder("su", "-c", guarded).redirectErrorStream(true).start())
    }

    /** IP of the device currently being metered, or null. */
    @Volatile private var monitoredIp: String? = null

    /**
     * Starts a per-device traffic meter: ARP-poisons [device] both directions,
     * FORWARDS its traffic (so it keeps working — nothing is dropped) and counts
     * up/down bytes via iptables. Mutually exclusive with a cut (it re-flushes the
     * chain); the caller resumes cuts on stop. Returns false if the device isn't a
     * real, non-self, non-gateway host or the gateway is unknown.
     */
    @Synchronized
    fun startMonitor(context: Context, device: Device): Boolean {
        val gwIp = lastGateway ?: cutGwIp ?: detectGateway(lastIface) ?: return false
        val gwMac = lastGatewayMac
            ?: accumulated.values.firstOrNull { it.ip == gwIp }?.mac
            ?: cutGwMac ?: return false
        if (device.kind != Device.Kind.HOST || device.mac.isBlank() || "." !in device.ip ||
            device.ip == gwIp || device.ip == myIpv4(lastIface)
        ) return false
        cutGwIp = gwIp
        cutGwMac = gwMac
        // Full reconcile first (same as applyLimits): stop + HEAL whatever was
        // poisoned (so paused cuts don't strand devices), wipe our rules, and drop
        // the stale cut notification. Then stand up the meter cleanly.
        val previous = lastTargets
        killPoisoners()
        if (previous.isNotEmpty()) healTargets(previous)
        lastTargets = emptyList()
        teardownNetworking()
        CutService.stop(context)
        // Poison both directions so we observe up AND down.
        launchPoisoner(context, gwIp, gwMac, listOf("${device.ip}@${device.mac}@b"))
        saveIpForwardOnce()
        runRoot(monitorScript(device.ip, gwIp))
        shapingActive = true
        monitoredIp = device.ip
        lastTargets = listOf(device.ip to device.mac)
        rlog("MONITOR ${device.ip}")
        return true
    }

    /** Forward the metered device's traffic (so it stays online) and count it. No
     *  drops: `-d ip ACCEPT` tallies download bytes, `-s ip ACCEPT` upload bytes;
     *  ACCEPT also bypasses Android's OEM forward chains. */
    private fun monitorScript(ip: String, gwIp: String): String {
        val sb = StringBuilder()
        sb.append(forwardingSetup(gwIp))
        sb.appendLine("iptables -N BETTERCUT 2>/dev/null")
        sb.appendLine("iptables -F BETTERCUT")
        sb.appendLine("iptables -C FORWARD -j BETTERCUT 2>/dev/null || iptables -I FORWARD -j BETTERCUT")
        sb.appendLine("iptables -A BETTERCUT -d $ip -j ACCEPT")
        sb.appendLine("iptables -A BETTERCUT -s $ip -j ACCEPT")
        return sb.toString()
    }

    /** Cumulative [downBytes, upBytes] for the metered device from iptables byte
     *  counters, or null if nothing is being metered. Poll and diff for a rate. */
    fun readMeter(): LongArray? {
        val ip = monitoredIp ?: return null
        return parseMeter(runRoot("iptables -vnxL BETTERCUT 2>/dev/null"), ip)
    }

    /** Parses `iptables -vnxL BETTERCUT` output into [downBytes, upBytes] for [ip]:
     *  the ACCEPT rule whose destination is the device counts download, whose
     *  source is the device counts upload. Pure, so it's unit-tested. */
    internal fun parseMeter(output: String, ip: String): LongArray {
        var down = 0L
        var up = 0L
        for (line in output.lineSequence()) {
            val f = line.trim().split(Regex("\\s+"))
            // pkts bytes target prot opt in out source destination
            if (f.size < 9 || f[2] != "ACCEPT") continue
            val bytes = f[1].toLongOrNull() ?: continue
            when (ip) {
                f[8] -> down = bytes   // destination == device → download to it
                f[7] -> up = bytes     // source == device → upload from it
            }
        }
        return longArrayOf(down, up)
    }

    /** Stops the meter: kills the poisoner, heals ARP, tears down forwarding. */
    @Synchronized
    fun stopMonitor(context: Context) {
        monitoredIp = null
        killPoisoners()
        healTargets(lastTargets)
        lastTargets = emptyList()
        teardownNetworking()
        CutService.stop(context)
    }

    /** Kills every running poisoner and clears the run flag, WITHOUT healing —
     *  used internally when we're about to immediately re-poison a new set. */
    private fun killPoisoners() {
        runCatching { flagFile?.delete() } // signals the watchdog to stop
        runCatching {
            ProcessBuilder("su", "-c", KILL_POISONERS)
                .redirectErrorStream(true).start().waitFor()
        }
        cutProc.getAndSet(null)?.destroy()
    }

    /** Sends corrective ARP so victims AND the whole segment relearn the real
     *  MACs at once. Even with no known targets it still broadcasts the real
     *  gateway mapping — which un-poisons every device's gateway entry — so a
     *  stop always clears poison, including from orphan poisoners we no longer
     *  track. Needs a known gateway; blocks ~1.5s (a short corrective burst). */
    private fun healTargets(targets: List<Pair<String, String>>) {
        val tool = toolPathCached ?: return
        // Use the cut's own cached gateway (falling back to live scan state), so
        // healing works even mid-rescan when lastGateway has been nulled.
        val gwIp = cutGwIp ?: lastGateway ?: return
        val gwMac = cutGwMac ?: lastGatewayMac ?: return
        val args = buildList {
            add(tool); add("heal"); add(lastIface); add(gwIp); add(gwMac)
            targets.forEach { add("${it.first}@${it.second}") }
        }
        val line = args.joinToString(" ") { "'" + it.replace("'", "'\\''") + "'" }
        runRoot(line)
    }

    /** Launch-time hygiene: reap any orphan poisoner left by a previous run
     *  (e.g. after a crash/force-stop) and clear its stale FORWARD rules. Safe to
     *  run anytime — it touches no `tc`, only our own poisoner and iptables chain. */
    fun cleanupNetworking() {
        runCatching { flagFile?.delete() }
        runCatching {
            ProcessBuilder("su", "-c", "$KILL_POISONERS ; ${wipeRulesScript()} ; echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null")
                .redirectErrorStream(true).start().waitFor()
        }
        shapingActive = false
    }

    /** Removes ALL of our netfilter/routing footprint — the BETTERCUT chain, any
     *  tc qdisc, our policy rules, and our route table — WITHOUT touching
     *  ip_forward (callers decide that). */
    private fun wipeRulesScript(): String =
        """
        iptables -F BETTERCUT 2>/dev/null
        iptables -D FORWARD -j BETTERCUT 2>/dev/null
        iptables -X BETTERCUT 2>/dev/null
        tc qdisc del dev $lastIface ingress 2>/dev/null
        tc qdisc del dev ifb0 root 2>/dev/null
        while ip rule del pref 17000 2>/dev/null; do : ; done
        while ip rule del pref 17001 2>/dev/null; do : ; done
        ip route flush table 17000 2>/dev/null
        """.trimIndent()

    /**
     * Shell to make this phone actually FORWARD poisoned traffic to the internet.
     *
     * We do NOT try to detect Android's per-network route table (the old
     * `ip route get 8.8.8.8 | grep table` trick returned empty on this device, so
     * the routing rule was never added and every forwarded packet was dropped —
     * that's why the meter read 0 and throttle behaved like a cut). Instead we
     * BUILD our own table 17000 from facts we already know for certain: a default
     * route via the real gateway, plus the local /24, and send everything arriving
     * on wlan0 through it. No parsing, no guessing.
     */
    private fun forwardingSetup(gwIp: String): String {
        val subnet = myIpv4(lastIface)?.substringBeforeLast('.')?.let { "$it.0/24" }
        val sb = StringBuilder()
        sb.appendLine("echo 1 > /proc/sys/net/ipv4/ip_forward")
        sb.appendLine("ip route flush table 17000 2>/dev/null")
        if (subnet != null) sb.appendLine("ip route add $subnet dev $lastIface table 17000 2>/dev/null")
        sb.appendLine("ip route add default via $gwIp dev $lastIface table 17000 2>/dev/null")
        sb.appendLine("while ip rule del pref 17000 2>/dev/null; do : ; done")
        sb.appendLine("ip rule add iif $lastIface lookup 17000 pref 17000 2>/dev/null")
        // rp_filter would drop the victim traffic we forward (its source doesn't
        // match our route back); relax it on the iface and globally.
        sb.appendLine("echo 0 > /proc/sys/net/ipv4/conf/$lastIface/rp_filter 2>/dev/null")
        sb.appendLine("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null")
        return sb.toString()
    }

    /**
     * Builds the root shell that forwards poisoned traffic and enforces limits,
     * entirely in netfilter. Blocks become FORWARD DROPs; throttles become
     * hashlimit drop-policing on the download direction.
     *
     * Why not smooth `tc` shaping? On this Qualcomm chipset every shaping option
     * fails: an htb qdisc on wlan0's egress/root CRASHES the WiFi firmware, and
     * shaping on a virtual IFB device (via a wlan0 ingress redirect) DROPS all
     * forwarded transit packets — the redirect doesn't re-forward on this kernel,
     * so the target gets cut instead of throttled (routing is fine; the redirect
     * mechanism itself doesn't forward). Drop-policing needs no qdisc/redirect on
     * wlan0, so forwarding keeps working — the rate is jumpy (TCP reacts to drops)
     * but it actually throttles.
     */
    private fun policeScript(targets: List<Pair<Device, Int>>, gwIp: String): String {
        val hasThrottle = targets.any { it.second > 0 }

        // PURE CUT (no throttles) — bettercap "ban" model: the ARP spoof ALONE
        // blocks the victim (its traffic comes to this phone and dies because
        // forwarding is off). So we install NOTHING — no iptables chain, no policy
        // route, no custom table. We only run teardownScript to (a) turn ip_forward
        // OFF and (b) wipe any leftover chain/route/table from a previous
        // throttle/meter session, so a cut leaves ZERO netfilter/routing state
        // behind. This is the fix for "network still slow after restore": a cut no
        // longer touches forwarding or iptables at all.
        if (!hasThrottle) return wipeRulesScript() + "\necho 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null"

        // THROTTLE / MIXED — needs the phone to forward under-limit packets, so it
        // genuinely requires ip_forward + our routing table + the netfilter chain
        // (cut victims in a mixed set get an explicit DROP since forwarding is on).
        val sb = StringBuilder()
        sb.append(forwardingSetup(gwIp))
        sb.appendLine("iptables -N BETTERCUT 2>/dev/null")
        sb.appendLine("iptables -F BETTERCUT")
        sb.appendLine("iptables -C FORWARD -j BETTERCUT 2>/dev/null || iptables -I FORWARD -j BETTERCUT")
        bettercutRules(targets.map { it.first.ip to it.second }).forEach { sb.appendLine(it) }
        return sb.toString()
    }

    /** Byte-rate the netfilter throttle enforces for a UI kbit/s value. hashlimit
     *  is byte-mode, so kbit/s / 8 = kByte/s; never below 1. */
    internal fun kBytesPerSec(kbps: Int): Int = maxOf(1, kbps / 8)

    /** Poison direction — ALWAYS full-duplex ("b"): poison BOTH the victim and the
     *  gateway. Victim-only ("v") was unreliable — many stacks (Windows, hardened
     *  phones/IoT) ignore an unsolicited ARP reply, so a victim-only cut worked on
     *  some devices and not others. Poisoning the gateway too means the victim's
     *  INBOUND traffic is redirected to us regardless of whether the victim itself
     *  accepts the poison, so the cut lands on both directions. (For a pure cut,
     *  forwarding stays off, so both directions are simply dropped — no hairpin.) */
    internal fun poisonMode(kbps: Int): String = "b"

    /** The per-target BETTERCUT rule lines for a set of (ip, kbps). Pure string
     *  building, split out so throttle/cut correctness is unit-testable without a
     *  device: a cut is two DROPs; a throttle is a download hashlimit DROP plus
     *  the two ACCEPTs that bypass Android's OEM forward chains, each with a
     *  unique hashlimit name and burst >= rate. */
    internal fun bettercutRules(targets: List<Pair<String, Int>>): List<String> {
        val out = ArrayList<String>()
        var id = 0
        for ((ip, kbps) in targets) {
            if (kbps <= 0) {
                // Block: drop the victim's forwarded traffic both directions.
                out += "iptables -A BETTERCUT -s $ip -j DROP"
                out += "iptables -A BETTERCUT -d $ip -j DROP"
            } else {
                id++
                // Drop-police the DOWNLOAD (to the victim) — the direction users
                // set a limit for. We deliberately don't police the upload, so the
                // victim's TCP ACKs flow freely and the download holds nearer the
                // cap instead of collapsing. burst must be >= the rate (~1 s bucket).
                val kBps = kBytesPerSec(kbps)
                out += "iptables -A BETTERCUT -d $ip -m hashlimit --hashlimit-name bcd$id " +
                    "--hashlimit-mode dstip --hashlimit-above ${kBps}kb/s --hashlimit-burst ${kBps}kb -j DROP"
                // ESSENTIAL: explicitly ACCEPT the victim's remaining traffic (both
                // directions). ACCEPT is a terminating verdict, so these packets
                // skip Android's OEM forward chains (tetherctrl_FORWARD, bw_FORWARD)
                // which DROP un-tethered forwarded traffic. Without this the victim
                // is cut entirely instead of throttled — under-limit packets fall
                // through into those chains and die.
                out += "iptables -A BETTERCUT -d $ip -j ACCEPT"
                out += "iptables -A BETTERCUT -s $ip -j ACCEPT"
            }
        }
        return out
    }

    fun stopCut() {
        // Stop poisoning first, THEN heal — otherwise a still-running poisoner
        // would immediately overwrite the corrective ARP we send.
        killPoisoners()
        healTargets(lastTargets)
        lastTargets = emptyList()
    }

    /** Stops discovery only; any active cut keeps running. */
    fun stopScan() {
        runCatching { mcastLock?.takeIf { it.isHeld }?.release() }
        mcastLock = null
    }

    /** Full teardown: stop the cut, undo shaping (only if set), service, scan. */
    fun exit(context: Context) {
        stopCut()
        teardownNetworking()
        CutService.stop(context)
        stopScan()
    }

    /** A complete restore, as if the user hit "Restore all" in-app. Used by the
     *  notification action so it doesn't leave a half-restored state: heals ARP,
     *  kills the poisoner, tears down the iptables/forwarding rules, AND clears
     *  the persisted limits so the next launch won't re-apply the cut. The
     *  ViewModel re-reads limits from prefs on resume, so the in-app UI clears
     *  too. Only the "limits" key is touched — the whitelist is left intact. */
    fun fullRestore(context: Context) {
        stopCut()
        teardownNetworking()
        cutGwIp = null
        cutGwMac = null
        runCatching {
            context.getSharedPreferences("bettercut", Context.MODE_PRIVATE)
                .edit().remove("limits").apply()
        }
        CutService.stop(context)
    }

    // --- helpers ---

    /** True if a cut is genuinely running in THIS process. After the process is
     *  killed and recreated, the poisoner is gone and this is false — used to
     *  suppress a phantom "cut active" notification on a sticky service restart. */
    fun hasActiveCut(): Boolean = cutProc.get() != null || lastTargets.isNotEmpty()

    /** Blanket un-poison of the whole segment: broadcasts the real gateway
     *  mapping so every device relearns gwIP->gwMAC, undoing poison left by a
     *  previous crash or an orphan poisoner we no longer track. Needs the gateway
     *  IP+MAC (resolved by a scan). Safe no-op if the gateway isn't known yet.
     *  Call when starting up with NO active cut — never while a cut is intended. */
    fun repairSegment() {
        val tool = toolPathCached ?: return
        val gwIp = lastGateway ?: return
        val gwMac = lastGatewayMac ?: return
        runRoot("'$tool' heal '$lastIface' '$gwIp' '$gwMac'")
    }

    /** A live dump of the networking state behind cut/throttle/meter, so problems
     *  can be diagnosed without ADB: forwarding flag, running poisoners, our route
     *  table + rule, the BETTERCUT chain with byte counters, and the neighbour
     *  (ARP) table showing whether targets are actually poisoned to this phone. */
    fun diagnostics(): String {
        val me = runCatching { myIpv4(lastIface) }.getOrNull() ?: "?"
        val script = listOf(
            "echo '=== iface $lastIface  self $me  gw ${lastGateway ?: cutGwIp ?: "?"} ==='",
            "echo '--- ip_forward ---'; cat /proc/sys/net/ipv4/ip_forward 2>&1",
            "echo '--- poisoners running ---'; " +
                "for p in /proc/[0-9]*; do e=\$(readlink \$p/exe 2>/dev/null); " +
                "case \"\$e\" in *libarpcut*) echo \"pid \${p##*/}: \$(cat \$p/cmdline 2>/dev/null | tr '\\0' ' ')\";; esac; done",
            "echo '--- ip rule (pref 17000) ---'; ip rule show 2>&1 | grep -E '17000|lookup' ",
            "echo '--- route table 17000 ---'; ip route show table 17000 2>&1",
            "echo '--- BETTERCUT chain (bytes) ---'; iptables -vnxL BETTERCUT 2>&1",
            "echo '--- ARP neigh ---'; ip neigh show dev $lastIface 2>&1",
        ).joinToString(" ; ")
        return runRoot(script).ifBlank { "(no output — is root granted?)" }
    }

    /** True if the app actually has working root (su granted). */
    fun hasRoot(): Boolean = runCatching {
        val p = ProcessBuilder("su", "-c", "id -u").redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText().trim()
        p.waitFor()
        out.startsWith("0")
    }.getOrDefault(false)

    private fun runRoot(cmd: String): String = runCatching {
        rlog("RUN ${cmd.replace("\n", " ; ").take(200)}")
        val p = ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        p.waitFor()
        out
    }.getOrDefault("")

    private fun myIpv4(iface: String): String? = runCatching {
        NetworkInterface.getByName(iface)?.inetAddresses?.toList()
            ?.firstOrNull { it is Inet4Address }?.hostAddress
    }.getOrNull()

    private fun myMac(iface: String): String? = runCatching {
        NetworkInterface.getByName(iface)?.hardwareAddress?.joinToString(":") { "%02x".format(it) }
    }.getOrNull()

    /**
     * Host discovery WITHOUT raw packet injection. Nudges every IP with a UDP
     * datagram so the kernel resolves each MAC via its normal ARP path (what any
     * app does), then reads the neighbour table. This is safe for the WiFi
     * firmware — unlike broadcasting raw ARP frames, which crashes it.
     */
    private fun kernelScan(iface: String): List<Pair<String, String>> {
        val myIp = myIpv4(iface) ?: return emptyList()
        val prefix = myIp.substringBeforeLast('.')
        runCatching {
            java.net.DatagramSocket().use { s ->
                val payload = ByteArray(1)
                for (i in 1..254) runCatching {
                    s.send(
                        java.net.DatagramPacket(
                            payload, 1, java.net.InetAddress.getByName("$prefix.$i"), 40000
                        )
                    )
                }
            }
        }
        Thread.sleep(1200) // let ARP replies land in the neighbour table
        val out = runRoot("ip neigh show dev $iface")
        val re = Regex("""(\d{1,3}(?:\.\d{1,3}){3})\s+lladdr\s+([0-9a-fA-F:]{17})""")
        return out.lineSequence()
            .mapNotNull { line -> re.find(line)?.let { it.groupValues[1] to it.groupValues[2].lowercase() } }
            .distinctBy { it.first }
            .toList()
    }

    private fun detectGateway(iface: String?): String? {
        val ifacePart = if (iface.isNullOrBlank()) """\w+""" else Regex.escape(iface)
        val re = Regex("""default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})\s+dev\s+$ifacePart\b""")
        val out = runRoot("ip route show table all")
        return out.lineSequence()
            .filter { "rmnet" !in it && "tun" !in it && "dummy" !in it }
            .firstNotNullOfOrNull { re.find(it)?.groupValues?.get(1) }
    }

    private fun ipSortKey(ip: String): Long =
        ip.split(".").takeIf { it.size == 4 }
            ?.fold(0L) { acc, p -> (acc shl 8) or (p.toLongOrNull() ?: 0L) } ?: Long.MAX_VALUE
}
