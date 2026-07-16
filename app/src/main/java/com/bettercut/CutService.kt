package com.bettercut

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

/**
 * Foreground service that keeps an active ARP cut alive when the scan is stopped
 * or the app is backgrounded (otherwise Android / task-killers reap the process
 * and the cut dies). It doesn't run the cut itself — libarpcut.so does, as a root
 * process — this just holds foreground priority and shows a persistent notice.
 */
class CutService : Service() {

    companion object {
        private const val CHANNEL = "cut"
        private const val NOTIF_ID = 42
        const val ACTION_STOP = "com.bettercut.action.STOP_CUT"
        private const val EXTRA_COUNT = "count"

        /** Start or update the service to reflect [count] cut devices. */
        fun update(context: Context, count: Int) {
            val i = Intent(context, CutService::class.java).putExtra(EXTRA_COUNT, count)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                context.startForegroundService(i)
            else context.startService(i)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, CutService::class.java))
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /** Best-effort reaper for a clean service teardown. Hard kills (force-stop,
     *  task-killer, crash) don't call this — the poisoner's app-PID watchdog
     *  handles those — but this makes an orderly stop tear the cut down promptly. */
    override fun onDestroy() {
        Thread { NetScan.stopCut() }.start()
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            // Notification "Restore all" — a FULL restore (heal + teardown +
            // clear persisted limits), so it matches the in-app Restore all and
            // the cut can't silently come back on next launch.
            val ctx = applicationContext
            Thread { NetScan.fullRestore(ctx) }.start()
            stopSelf()
            return START_NOT_STICKY
        }
        // A null intent = the system restarted this sticky service. If that
        // happened because the process was killed, the cut died with it — don't
        // show a phantom "cut active" notification. Still satisfy the foreground
        // contract (startForeground) before self-removing to avoid a crash.
        if (intent == null && !NetScan.hasActiveCut()) {
            startForegroundCompat(0)
            stopSelf()
            return START_NOT_STICKY
        }
        val count = intent?.getIntExtra(EXTRA_COUNT, 0) ?: 0
        startForegroundCompat(count)
        return START_STICKY
    }

    private fun startForegroundCompat(count: Int) {
        createChannel()
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, CutService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notif: Notification = NotificationCompat.Builder(this, CHANNEL)
            .setContentTitle("BetterCut — cut active")
            .setContentText("$count device(s) blocked from the network")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Restore all", stopIntent)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(CHANNEL) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(CHANNEL, "Active cut", NotificationManager.IMPORTANCE_LOW)
                )
            }
        }
    }
}
