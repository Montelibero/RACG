package app.racg.approver

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
import androidx.core.app.NotificationManagerCompat
import java.net.URI
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ApproverPollService : Service() {
    private val store by lazy { DataStoreApproverStore(this) }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val running = AtomicBoolean(false)
    private val visibleRequests = mutableSetOf<String>()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannels()
        startForeground()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        if (running.compareAndSet(false, true)) {
            scope.launch { pollLoop() }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        running.set(false)
        scope.cancel()
        super.onDestroy()
    }

    private suspend fun pollLoop() {
        while (running.get() && scope.isActive) {
            try {
                pollOnce()
            } catch (_: Exception) {
                updateForeground("Approval watching paused. Retrying.")
            }
            delay(60_000)
        }
    }

    private suspend fun pollOnce() {
        val setups = store.loadAll()
        val requests = withContext(Dispatchers.IO) {
            coroutineScope {
                setups.map { setup ->
                    async {
                        try {
                            val uri = URI(setup.payload.endpoint)
                            val transport = ApproverTransport(setup, BrokerClient(uri.host, uri.port))
                            transport.pendingRequests(DeviceKeyManager.pollSigner(setup.pollKeyMaterial.publicKey))
                                .map { PendingRequestItem(setup, it) }
                        } catch (_: Exception) {
                            emptyList()
                        }
                    }
                }.awaitAll().flatten()
            }
        }

        notify(requests)
        val status = if (requests.isEmpty()) "Connected. No pending approvals." else "${requests.size} approval(s) waiting."
        updateForeground(status)
    }

    private fun notify(requests: List<PendingRequestItem>) {
        val manager = NotificationManagerCompat.from(this)
        if (!manager.areNotificationsEnabled()) return

        requests.forEach { item ->
            val notification = NotificationCompat.Builder(this, CHANNEL_APPROVALS)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("Approval needed")
                .setContentText("${item.setup.payload.serverId} • ${item.request.request.clientId}")
                .setStyle(NotificationCompat.BigTextStyle()
                    .bigText("${item.setup.payload.serverId}\n${item.request.request.clientId}\n${item.request.request.requestId}"))
                .setGroup(GROUP_APPROVALS)
                .setAutoCancel(true)
                .setContentIntent(mainIntent())
                .build()
            manager.notify(notificationId(item), notification)
        }

        val dismissed = visibleRequests - requests.map { it.key }.toSet()
        dismissed.forEach { manager.cancel(notificationId(it)) }
        if (requests.isNotEmpty()) {
            val summary = NotificationCompat.Builder(this, CHANNEL_APPROVALS)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("RACG approvals waiting")
                .setContentText("${requests.size} verified request(s)")
                .setGroup(GROUP_APPROVALS)
                .setGroupSummary(true)
                .setAutoCancel(true)
                .setContentIntent(mainIntent())
                .build()
            manager.notify(SUMMARY_ID, summary)
        } else {
            manager.cancel(SUMMARY_ID)
        }
        visibleRequests.clear()
        visibleRequests.addAll(requests.map { it.key })
    }

    private fun notificationId(item: PendingRequestItem): Int =
        notificationId(item.setup.payload.serverId + ":" + item.request.request.requestId)

    private fun notificationId(key: String): Int = key.hashCode()

    private fun mainIntent(): PendingIntent = PendingIntent.getActivity(
        this,
        0,
        Intent(this, MainActivity::class.java),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )

    private fun startForeground() {
        val notification = NotificationCompat.Builder(this, CHANNEL_SERVICE)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("RACG approver watching")
            .setContentText("Connected servers are checked for approvals.")
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(FOREGROUND_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(FOREGROUND_ID, notification)
        }
    }

    private fun updateForeground(text: String) {
        val notification = NotificationCompat.Builder(this, CHANNEL_SERVICE)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("RACG approver watching")
            .setContentText(text)
            .setOngoing(true)
            .build()
        val manager = NotificationManagerCompat.from(this)
        manager.notify(FOREGROUND_ID, notification)
    }

    private fun createChannels() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL_SERVICE, "Approval watcher", NotificationManager.IMPORTANCE_MIN))
        manager.createNotificationChannel(NotificationChannel(CHANNEL_APPROVALS, "Pending approvals", NotificationManager.IMPORTANCE_HIGH))
    }

    companion object {
        private const val ACTION_STOP = "app.racg.approver.STOP"
        private const val CHANNEL_SERVICE = "racg_service"
        private const val CHANNEL_APPROVALS = "racg_approvals"
        private const val GROUP_APPROVALS = "racg_pending_approvals"
        private const val FOREGROUND_ID = 1
        private const val SUMMARY_ID = 2

        fun start(context: Context) {
            context.startForegroundService(Intent(context, ApproverPollService::class.java))
        }

        fun stop(context: Context) {
            context.startService(Intent(context, ApproverPollService::class.java).setAction(ACTION_STOP))
        }
    }
}
