package com.bettercut

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Holds all screen state. A ViewModel survives configuration changes, returning
 * from the notification, and screen on/off — so devices, active cuts, and the
 * selected action never get lost. Scroll position and tab live in the UI via
 * saveable state.
 */
class ScanViewModel(app: Application) : AndroidViewModel(app) {

    var devices by mutableStateOf<List<Device>>(emptyList()); private set
    var scanning by mutableStateOf(false); private set
    var status by mutableStateOf("Starting…"); private set
    var limits by mutableStateOf<Map<String, Int>>(emptyMap()); private set   // ip -> kbps
    var whitelist by mutableStateOf<Set<String>>(emptySet()); private set     // macs

    private val prefs = app.getSharedPreferences("bettercut", Application.MODE_PRIVATE)
    private var scanJob: Job? = null
    private var started = false
    // IPs whose persisted limit is currently enforced by an active cut. Compared
    // against the visible-limited set after each scan so a limited device that was
    // offline at the first settle gets re-cut when it later appears — instead of a
    // one-shot "restore once" that silently misses late/offline devices.
    private var appliedLimitIps: Set<String> = emptySet()

    // Serializes limit applies (they touch root/iptables) so concurrent taps can't
    // interleave, and records the last set actually pushed to NetScan so identical
    // repeats collapse. Both are only touched on the Main dispatcher.
    private val applyMutex = Mutex()
    private var enforced: Map<String, Int> = emptyMap()
    private var repairedOnLaunch = false   // blanket un-poison once, if nothing to restore

    init {
        NetScan.initLog(app)
        whitelist = prefs.getStringSet("whitelist", emptySet())!!.map { it.lowercase() }.toSet()
        // Restore the cut/throttle set from a previous run so the UI shows it and
        // the first scan can re-establish it (the poisoner dies with the process).
        limits = loadLimits()
        Thread { NetScan.cleanupNetworking() }.start()
    }

    // limits persist as a set of "ip=kbps" strings so cuts survive process death.
    private fun loadLimits(): Map<String, Int> =
        prefs.getStringSet("limits", emptySet()).orEmpty().mapNotNull { s ->
            val p = s.split("=")
            val kbps = p.getOrNull(1)?.toIntOrNull()
            if (p.size == 2 && kbps != null) p[0] to kbps else null
        }.toMap()

    private fun persistLimits(m: Map<String, Int>) {
        prefs.edit().putStringSet("limits", m.map { "${it.key}=${it.value}" }.toSet()).apply()
    }

    /** Re-sync in-memory limits from prefs. Called on resume so an external
     *  change — the notification's "Restore all", which clears persisted limits —
     *  is reflected in the UI instead of showing a stale cut. Prefs is the single
     *  source of truth; every in-app mutation already writes it, so a reload can
     *  only pull in a genuinely external change. */
    fun reloadFromPrefs() {
        val fresh = loadLimits()
        if (fresh != limits) {
            limits = fresh
            // An external clear (notification Restore all) means nothing is
            // enforced anymore; let the next scan re-establish whatever remains.
            appliedLimitIps = appliedLimitIps intersect fresh.keys
            // NetScan's actual state was changed out from under us, so forget what
            // we think is enforced — the next apply must not collapse as a no-op.
            enforced = emptyMap()
            status = if (fresh.isEmpty()) "Restored" else "${fresh.size} limited"
        }
    }

    /** Auto-start one scan the first time the screen appears. */
    fun startOnce() {
        if (started) return
        started = true
        startScan()
    }

    /** Runs a scan that stops itself once the device list settles. */
    fun startScan() {
        if (scanning) return
        scanning = true
        val app = getApplication<Application>()
        scanJob = viewModelScope.launch {
            status = "Checking root…"
            if (!withContext(Dispatchers.IO) { NetScan.hasRoot() }) {
                status = "No root — grant BetterCut in KernelSU Next, then rescan"
                scanning = false
                return@launch
            }
            withContext(Dispatchers.IO) { NetScan.reset() }
            status = "Scanning…"
            var last = -1
            var stable = 0
            var sweeps = 0
            while (scanning && sweeps < 12) {
                val r = withContext(Dispatchers.IO) { runCatching { NetScan.scan(app, "wlan0") } }
                r.onSuccess {
                    devices = it
                    val hosts = it.count { d -> d.kind == Device.Kind.HOST }
                    status = "Scanning… $hosts hosts"
                    // Only treat the list as "settled" once it's non-empty — never
                    // stop at zero just because ARP hasn't populated yet.
                    if (it.isNotEmpty() && it.size == last) stable++ else stable = 0
                    last = it.size
                }.onFailure { status = "Waiting for root…" }
                sweeps++
                if (stable >= 2 && sweeps >= 4) break   // found devices & settled → done
                delay(2500)
            }
            if (scanning) {                          // finished naturally (not user-stopped)
                scanning = false
                NetScan.stopScan()
                val gw = NetScan.lastGateway ?: "—"
                val done = "Done · ${devices.count { it.kind == Device.Kind.HOST }} hosts · gw $gw"
                // Re-establish persisted limits for every limited device that's now
                // visible. Re-apply whenever that visible-limited set differs from
                // what's already enforced — so a device that was offline at the
                // first settle gets re-cut when it later appears, and we don't
                // needlessly re-poison an unchanged set.
                val visibleLimited = devices.filter { it.ip in limits }
                val wantIps = visibleLimited.map { it.ip }.toSet()
                if (wantIps.isNotEmpty() && wantIps != appliedLimitIps) {
                    appliedLimitIps = wantIps
                    val pending = visibleLimited.map { it to limits.getValue(it.ip) }
                    withContext(Dispatchers.IO) {
                        runCatching { NetScan.applyLimits(getApplication(), pending) }
                    }
                    status = "Restored ${pending.size} limit(s) · gw $gw"
                } else {
                    // Nothing to restore → if this is the first settle, blanket
                    // un-poison the segment once, in case a previous crash/orphan
                    // left devices stuck pointing at this phone.
                    if (!repairedOnLaunch) {
                        repairedOnLaunch = true
                        withContext(Dispatchers.IO) { runCatching { NetScan.repairSegment() } }
                    }
                    status = done
                }
            }
        }
    }

    fun stopScan() {
        scanning = false
        scanJob?.cancel()
        NetScan.stopScan()
        status = if (limits.isEmpty()) "Stopped"
        else "Idle · ${limits.size} limited"
    }

    fun applyLimits(next: Map<String, Int>) {
        limits = next
        persistLimits(next)
        appliedLimitIps = devices.filter { it.ip in next }.map { it.ip }.toSet() // restore-sync
        viewModelScope.launch {
            applyMutex.withLock {
                // Read the LATEST intended state at execution time (not the map
                // captured when this coroutine was queued), so a burst of taps
                // can't let a stale set win. Collapse no-op repeats so we don't
                // needlessly kill+repoison — a visible blip — for no change.
                val current = limits
                if (current == enforced) return@withLock
                enforced = current
                val victims = devices.filter { it.ip in current }.map { it to current.getValue(it.ip) }
                withContext(Dispatchers.IO) { runCatching { NetScan.applyLimits(getApplication(), victims) } }
                    .onFailure { status = "Limit error: ${it.message}" }
            }
        }
    }

    fun toggleWhitelist(mac: String) {
        val m = mac.lowercase()
        val next = if (m in whitelist) whitelist - m else whitelist + m
        whitelist = next
        prefs.edit().putStringSet("whitelist", next).apply()
        if (m !in (whitelist)) return
        // just-whitelisted: also lift any limit on it
        devices.firstOrNull { it.mac.lowercase() == m }?.ip?.let { ip ->
            if (ip in limits) applyLimits(limits - ip)
        }
    }

    fun fullExit() {
        scanning = false
        scanJob?.cancel()
        limits = emptyMap()
        appliedLimitIps = emptySet()
        enforced = emptyMap()
        persistLimits(emptyMap())   // a full exit should not restore limits next launch
        NetScan.exit(getApplication())
    }
}
