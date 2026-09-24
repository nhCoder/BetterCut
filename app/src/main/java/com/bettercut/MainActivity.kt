package com.bettercut

import android.content.Context
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Bolt
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.DevicesOther
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Radar
import androidx.compose.material.icons.rounded.RestartAlt
import androidx.compose.material.icons.rounded.Router
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Smartphone
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.Stop
import androidx.compose.material.icons.rounded.SwapVert
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material.icons.rounded.Wifi
import androidx.compose.material.icons.rounded.WifiOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.bettercut.ui.theme.BetterCutTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.roundToInt

private fun Context.findActivity(): android.app.Activity? {
    var c: Context? = this
    while (c is android.content.ContextWrapper) {
        if (c is android.app.Activity) return c
        c = c.baseContext
    }
    return null
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        // NetScan.initLog + cleanupNetworking (reaping any orphan poisoner and
        // stale rules from a previous run) are done once by ScanViewModel.init,
        // which is created moments later when the UI composes — no need to also do
        // them here and race two root teardowns.
        enableEdgeToEdge()
        setContent { BetterCutTheme { ScannerScreen() } }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScannerScreen(vm: ScanViewModel = viewModel()) {
    val context = LocalContext.current
    LaunchedEffect(Unit) { vm.startOnce() }   // auto-scan on first launch

    // Re-sync limits from prefs whenever the screen resumes, so a restore done
    // from the notification (which clears persisted limits) clears the UI too.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val obs = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_RESUME -> vm.reloadFromPrefs()
                // Don't keep MITM-ing a device while backgrounded — stop the meter
                // so it can't hairpin traffic through the phone unattended.
                Lifecycle.Event.ON_PAUSE -> vm.stopMeter()
                else -> {}
            }
        }
        lifecycleOwner.lifecycle.addObserver(obs)
        onDispose { lifecycleOwner.lifecycle.removeObserver(obs) }
    }

    var tab by rememberSaveable { mutableIntStateOf(0) }
    val netListState = rememberLazyListState()   // scroll position survives config changes
    val wlListState = rememberLazyListState()
    var menuOpen by remember { mutableStateOf(false) }
    var confirmCutAll by remember { mutableStateOf(false) }
    var throttleAllOpen by remember { mutableStateOf(false) }
    var diagText by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    val devices = vm.devices
    val limits = vm.limits
    val whitelist = vm.whitelist
    val cuttable = devices.filter { it.kind == Device.Kind.HOST && "." in it.ip }
    val networkList = devices.filter { it.mac.lowercase() !in whitelist }
    val whitelistList = devices.filter { it.mac.lowercase() in whitelist }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer,
                ),
                title = {
                    Column {
                        Text("BetterCut", fontWeight = FontWeight.Bold)
                        Text(
                            vm.status,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                actions = {
                    if (vm.scanning) CircularProgressIndicator(Modifier.size(18.dp))
                    IconButton(onClick = { if (vm.scanning) vm.stopScan() else vm.startScan() }) {
                        Icon(
                            if (vm.scanning) Icons.Rounded.Stop else Icons.Rounded.Radar,
                            contentDescription = if (vm.scanning) "Stop scan" else "Scan",
                        )
                    }
                    IconButton(onClick = { menuOpen = true }) {
                        Icon(Icons.Rounded.MoreVert, "More")
                    }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        DropdownMenuItem(
                            text = { Text("Cut all") },
                            leadingIcon = { Icon(Icons.Rounded.Bolt, null) },
                            enabled = cuttable.isNotEmpty(),
                            onClick = { menuOpen = false; confirmCutAll = true },
                        )
                        DropdownMenuItem(
                            text = { Text("Throttle all") },
                            leadingIcon = { Icon(Icons.Rounded.Speed, null) },
                            enabled = cuttable.isNotEmpty(),
                            onClick = { menuOpen = false; throttleAllOpen = true },
                        )
                        DropdownMenuItem(
                            text = { Text("Restore all") },
                            leadingIcon = { Icon(Icons.Rounded.RestartAlt, null) },
                            enabled = limits.isNotEmpty(),
                            onClick = { menuOpen = false; vm.applyLimits(emptyMap()) },
                        )
                        DropdownMenuItem(
                            text = { Text("Diagnostics") },
                            leadingIcon = { Icon(Icons.Rounded.BugReport, null) },
                            onClick = {
                                menuOpen = false
                                diagText = "Running…"
                                scope.launch {
                                    val t = withContext(Dispatchers.IO) { NetScan.diagnostics() }
                                    diagText = t
                                }
                            },
                        )
                        HorizontalDivider()
                        DropdownMenuItem(
                            text = { Text("Full exit") },
                            leadingIcon = { Icon(Icons.Rounded.PowerSettingsNew, null) },
                            onClick = {
                                menuOpen = false
                                vm.fullExit()
                                context.findActivity()?.finishAndRemoveTask()
                            },
                        )
                    }
                },
            )
        },
    ) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            PrimaryTabRow(selectedTabIndex = tab) {
                Tab(selected = tab == 0, onClick = { tab = 0 },
                    text = { Text("Devices · ${networkList.size}") })
                Tab(selected = tab == 1, onClick = { tab = 1 },
                    text = { Text("Whitelist · ${whitelistList.size}") })
            }

            val list = if (tab == 0) networkList else whitelistList
            if (list.isEmpty()) {
                EmptyState(if (tab == 0) "Scanning for devices…" else "No whitelisted devices")
            } else {
                LazyColumn(
                    Modifier.fillMaxSize(),
                    state = if (tab == 0) netListState else wlListState,
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    items(list, key = { it.mac.ifBlank { it.ip } }) { d ->
                        DeviceCard(
                            d = d,
                            limitKbps = limits[d.ip],
                            isWhitelisted = d.mac.lowercase() in whitelist,
                            onCutToggle = {
                                vm.applyLimits(
                                    if (d.ip in limits) limits - d.ip else limits + (d.ip to 0)
                                )
                            },
                            onSetLimit = { kbps ->
                                vm.applyLimits(
                                    if (kbps == null) limits - d.ip else limits + (d.ip to kbps)
                                )
                            },
                            onWhitelistToggle = { vm.toggleWhitelist(d.mac) },
                            onMeter = { vm.startMeter(d) },
                        )
                    }
                }
            }
        }
    }

    val cutTargets = cuttable.filter { it.mac.lowercase() !in whitelist }

    // Cutting the whole network at once is disruptive — confirm first.
    if (confirmCutAll) {
        AlertDialog(
            onDismissRequest = { confirmCutAll = false },
            icon = { Icon(Icons.Rounded.Warning, null) },
            title = { Text("Cut all devices?") },
            text = {
                Text(
                    "This blocks internet for all ${cutTargets.size} device(s) on the network " +
                        "at once. Whitelisted devices are left alone. Continue?"
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmCutAll = false
                    vm.applyLimits(cutTargets.associate { it.ip to 0 })
                }) { Text("Cut all") }
            },
            dismissButton = { TextButton(onClick = { confirmCutAll = false }) { Text("Cancel") } },
        )
    }

    // Throttle every device to one chosen speed (Full clears all limits).
    if (throttleAllOpen) {
        SpeedDialog(
            name = "All ${cutTargets.size} device(s)",
            current = 4000, // default 500 KB/s
            onDismiss = { throttleAllOpen = false },
            onApply = { kbps ->
                throttleAllOpen = false
                vm.applyLimits(
                    if (kbps == null) emptyMap() else cutTargets.associate { it.ip to kbps }
                )
            },
        )
    }

    // Live per-device traffic meter.
    vm.monitoring?.let { dev ->
        MeterDialog(
            device = dev,
            downRate = vm.meterDownRate,
            upRate = vm.meterUpRate,
            downTotal = vm.meterDownTotal,
            upTotal = vm.meterUpTotal,
            onStop = { vm.stopMeter() },
        )
    }

    diagText?.let { text ->
        AlertDialog(
            onDismissRequest = { diagText = null },
            icon = { Icon(Icons.Rounded.BugReport, null) },
            title = { Text("Diagnostics") },
            text = {
                Text(
                    text,
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier
                        .heightIn(max = 420.dp)
                        .verticalScroll(rememberScrollState()),
                )
            },
            confirmButton = { TextButton(onClick = { diagText = null }) { Text("Close") } },
        )
    }
}

@Composable
private fun MeterDialog(
    device: Device,
    downRate: Long,
    upRate: Long,
    downTotal: Long,
    upTotal: Long,
    onStop: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onStop,
        icon = { Icon(Icons.Rounded.SwapVert, null) },
        title = { Text("Live traffic") },
        text = {
            Column {
                Text(
                    device.displayName,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    device.ip,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(16.dp))
                MeterRow("Download", downRate, downTotal, MaterialTheme.colorScheme.primary)
                Spacer(Modifier.height(10.dp))
                MeterRow("Upload", upRate, upTotal, MaterialTheme.colorScheme.secondary)
                Spacer(Modifier.height(12.dp))
                Text(
                    "This routes the device's traffic through your phone to measure " +
                        "it. Stop when you're done.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = { TextButton(onClick = onStop) { Text("Stop") } },
    )
}

@Composable
private fun MeterRow(label: String, rate: Long, total: Long, color: Color) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f),
        )
        Text(
            fmtRate(rate),
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            color = color,
        )
    }
    Text(
        "Total ${fmtBytes(total)}",
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

private fun fmtRate(bytesPerSec: Long): String = fmtBytes(bytesPerSec) + "/s"

private fun fmtBytes(b: Long): String = when {
    b >= 1_000_000_000 -> "%.2f GB".format(b / 1_000_000_000.0)
    b >= 1_000_000 -> "%.1f MB".format(b / 1_000_000.0)
    b >= 1_000 -> "%.0f KB".format(b / 1_000.0)
    else -> "$b B"
}

@Composable
private fun EmptyState(msg: String) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Text(msg, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

// Speed presets. Value is kbit/s for tc (= KB/s × 8). null → unlimited; 0 → cut.
private val RATES: List<Pair<String, Int?>> = listOf(
    "Blocked" to 0,
    "50 KB/s" to 400,
    "100 KB/s" to 800,
    "250 KB/s" to 2000,
    "500 KB/s" to 4000,
    "1 MB/s" to 8000,
    "2 MB/s" to 16000,
    "5 MB/s" to 40000,
    "Full (no limit)" to null,
)

// kbit → the KB/s the user sees.
private fun rateShort(kbit: Int?): String = when {
    kbit == null -> "Full"
    kbit == 0 -> "CUT"
    kbit >= 8000 -> "${kbit / 8000}M"
    else -> "${kbit / 8}K"
}

private fun rateIndex(kbps: Int?): Int =
    RATES.indexOfFirst { it.second == kbps }.let { if (it < 0) RATES.lastIndex else it }

@Composable
private fun DeviceCard(
    d: Device,
    limitKbps: Int?,          // null = unlimited, 0 = blocked, >0 = throttled
    isWhitelisted: Boolean,
    onCutToggle: () -> Unit,
    onSetLimit: (Int?) -> Unit,
    onWhitelistToggle: () -> Unit,
    onMeter: () -> Unit,
) {
    val scheme = MaterialTheme.colorScheme
    val isCut = limitKbps == 0
    val isThrottled = limitKbps != null && limitKbps > 0
    val container by animateColorAsState(
        when {
            isCut -> scheme.errorContainer
            isThrottled -> scheme.secondaryContainer
            isWhitelisted -> scheme.tertiaryContainer
            else -> scheme.surfaceContainerHigh
        }, label = "card",
    )
    // Only real, non-whitelisted hosts can be cut/throttled. The gateway, this
    // phone, and whitelisted devices never get a Cut button or speed option — so
    // the UI can't even offer an action the core (NetScan.eligibleTargets) would
    // refuse, which would otherwise show a misleading "CUT" state.
    val canAct = d.kind == Device.Kind.HOST && "." in d.ip && !isWhitelisted
    var showSpeed by remember { mutableStateOf(false) }

    Surface(shape = RoundedCornerShape(24.dp), color = container) {
        Row(
            Modifier.fillMaxWidth().padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.size(44.dp), contentAlignment = Alignment.Center) {
                Surface(shape = CircleShape, color = scheme.surface, modifier = Modifier.size(44.dp)) {}
                Icon(
                    deviceIcon(d.kind, isWhitelisted),
                    contentDescription = null,
                    tint = when {
                        isCut -> scheme.error
                        isThrottled -> scheme.secondary
                        isWhitelisted -> scheme.tertiary
                        else -> scheme.primary
                    },
                )
            }
            Spacer(Modifier.width(14.dp))

            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        d.displayName,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    Spacer(Modifier.width(6.dp))
                    StatusBadge(d.kind, limitKbps, isWhitelisted)
                }
                val sub = buildList {
                    if (d.hostname.isNotBlank()) add(d.ip)
                    if (d.vendor.isNotBlank()) add(d.vendor)
                }.joinToString("  ·  ")
                if (sub.isNotBlank()) {
                    Text(
                        sub, style = MaterialTheme.typography.bodySmall,
                        color = scheme.onSurfaceVariant, maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Text(
                    d.mac, style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = scheme.onSurfaceVariant, maxLines = 1,
                )
            }

            if (canAct) {
                Spacer(Modifier.width(6.dp))
                FilledTonalIconButton(
                    onClick = onCutToggle,
                    colors = if (isCut)
                        IconButtonDefaults.filledTonalIconButtonColors(
                            containerColor = scheme.error, contentColor = scheme.onError,
                        )
                    else IconButtonDefaults.filledTonalIconButtonColors(),
                ) {
                    Icon(
                        if (isCut) Icons.Rounded.Wifi else Icons.Rounded.WifiOff,
                        contentDescription = if (isCut) "Restore" else "Cut",
                    )
                }
            }
            DeviceMenu(
                // Whitelisted hosts still get a menu — to *remove* them from the
                // whitelist — but no throttle/meter option. Gateway/self get nothing.
                isWhitelisted = isWhitelisted,
                showActions = canAct || (isWhitelisted && "." in d.ip),
                canThrottle = canAct,
                onSpeed = { showSpeed = true },
                onMeter = onMeter,
                onWhitelistToggle = onWhitelistToggle,
            )
        }
    }

    if (showSpeed) {
        SpeedDialog(
            name = d.displayName,
            current = limitKbps,
            onDismiss = { showSpeed = false },
            onApply = { onSetLimit(it); showSpeed = false },
        )
    }
}

@Composable
private fun SpeedDialog(name: String, current: Int?, onDismiss: () -> Unit, onApply: (Int?) -> Unit) {
    var idx by remember { mutableFloatStateOf(rateIndex(current).toFloat()) }
    val sel = RATES[idx.roundToInt().coerceIn(0, RATES.lastIndex)]
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Speed limit") },
        text = {
            Column {
                Text(name, style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(12.dp))
                Text(
                    sel.first,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                    color = when (sel.second) {
                        0 -> MaterialTheme.colorScheme.error
                        null -> MaterialTheme.colorScheme.primary
                        else -> MaterialTheme.colorScheme.secondary
                    },
                )
                Slider(
                    value = idx,
                    onValueChange = { idx = it },
                    valueRange = 0f..RATES.lastIndex.toFloat(),
                    steps = RATES.size - 2,
                )
                Text(
                    "Slide to Full for no limit, or Blocked to cut it off entirely.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = { TextButton(onClick = { onApply(sel.second) }) { Text("Apply") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun DeviceMenu(
    isWhitelisted: Boolean,
    showActions: Boolean,
    canThrottle: Boolean,
    onSpeed: () -> Unit,
    onMeter: () -> Unit,
    onWhitelistToggle: () -> Unit,
) {
    if (!showActions) { Spacer(Modifier.width(4.dp)); return }
    var open by remember { mutableStateOf(false) }
    Box {
        IconButton(onClick = { open = true }) { Icon(Icons.Rounded.MoreVert, "Options") }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            if (canThrottle) {
                DropdownMenuItem(
                    text = { Text("Live traffic…") },
                    leadingIcon = { Icon(Icons.Rounded.SwapVert, null) },
                    onClick = { open = false; onMeter() },
                )
                DropdownMenuItem(
                    text = { Text("Speed limit…") },
                    leadingIcon = { Icon(Icons.Rounded.Speed, null) },
                    onClick = { open = false; onSpeed() },
                )
            }
            DropdownMenuItem(
                text = { Text(if (isWhitelisted) "Remove from whitelist" else "Add to whitelist") },
                leadingIcon = { Icon(Icons.Rounded.Shield, null) },
                onClick = { open = false; onWhitelistToggle() },
            )
        }
    }
}

@Composable
private fun StatusBadge(kind: Device.Kind, limitKbps: Int?, isWhitelisted: Boolean) {
    val (label, color) = when {
        limitKbps == 0 -> "CUT" to MaterialTheme.colorScheme.error
        limitKbps != null -> rateShort(limitKbps) to MaterialTheme.colorScheme.secondary
        kind == Device.Kind.GATEWAY -> "GATEWAY" to MaterialTheme.colorScheme.primary
        kind == Device.Kind.SELF -> "YOU" to MaterialTheme.colorScheme.primary
        isWhitelisted -> "SAFE" to MaterialTheme.colorScheme.tertiary
        else -> return
    }
    Surface(shape = RoundedCornerShape(8.dp), color = color.copy(alpha = 0.15f)) {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            color = color,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
        )
    }
}

private fun deviceIcon(kind: Device.Kind, whitelisted: Boolean) = when {
    whitelisted -> Icons.Rounded.Shield
    kind == Device.Kind.GATEWAY -> Icons.Rounded.Router
    kind == Device.Kind.SELF -> Icons.Rounded.Smartphone
    else -> Icons.Rounded.DevicesOther
}
