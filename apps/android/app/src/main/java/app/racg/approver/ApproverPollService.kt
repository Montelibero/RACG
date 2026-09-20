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
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withContext

class ApproverPollService : Service() {
    private val store by lazy { DataStoreApproverStore(this) }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val running = AtomicBoolean(false)
    private val visibleRequests = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
    private val wakeups = kotlinx.coroutines.channels.Channel<Unit>(kotlinx.coroutines.channels.Channel.CONFLATED)
    private val eventWatchers = mutableMapOf<String, kotlinx.coroutines.Job>()

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
        eventWatchers.values.forEach { it.cancel() }
        eventWatchers.clear()
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
            // Instant wakeups arrive from the WebSocket event watchers (9.3);
            // the 60-second sweep stays as the fallback.
            select<Unit> {
                wakeups.onReceive { }
                onTimeout(60_000) { }
            }
        }
    }

    /** Keeps one signed WebSocket per cleartext/facade server alive; each
     * event just pulls the trigger for an immediate poll. Failures fall back
     * to the 60s sweep silently. */
    private fun syncEventWatchers(setups: List<StoredSetup>) {
        val wanted = setups.filter { usesCompatibilityApi(it.payload.endpoint) }
            .associateBy { it.payload.serverId }
        eventWatchers.keys.filterNot { wanted.containsKey(it) }.forEach { id ->
            eventWatchers.remove(id)?.cancel()
        }
        wanted.forEach { (serverId, setup) ->
            if (eventWatchers.containsKey(serverId)) return@forEach
            eventWatchers[serverId] = scope.launch {
                var backoffSeconds = 5L
                while (running.get() && scope.isActive) {
                    try {
                        ApproverSocket(
                            endpoint = setup.payload.endpoint,
                            serverId = serverId,
                            deviceId = setup.payload.approverId,
                            pollKeyPublic = setup.pollKeyMaterial.publicKey,
                        ).run(object : ApproverSocket.Listener {
                            override fun onWakeup() {
                                wakeups.trySend(Unit)
                            }

                            override fun onClosed() {
                                wakeups.trySend(Unit)
                            }
                        })
                        backoffSeconds = 5L
                    } catch (e: Exception) {
                        AppLog.log("events $serverId: ${e.message ?: e.javaClass.simpleName}")
                    }
                    delay(backoffSeconds * 1000)
                    if (backoffSeconds < 60L) backoffSeconds = (backoffSeconds * 2).coerceAtMost(60L)
                }
            }
        }
    }

    private suspend fun pollOnce() {
        val setups = store.loadAll()
        syncEventWatchers(setups)
        val requests = withContext(Dispatchers.IO) {
            coroutineScope {
                setups.map { setup ->
                    async {
                        try {
                            if (usesCompatibilityApi(setup.payload.endpoint)) {
                                pendingCompatibilityRequests(setup).map {
                                    PendingRequestItem(setup, it.id, it.clientId, it.operation, it.operationSha256)
                                }
                            } else {
                                val uri = URI(setup.payload.endpoint)
                                val transport = ApproverTransport(setup, BrokerClient(uri.host, uri.port))
                                transport.pendingRequests(DeviceKeyManager.pollSigner(setup.pollKeyMaterial.publicKey)).map {
                                    PendingRequestItem(
                                        setup = setup,
                                        requestId = it.request.requestId,
                                        clientId = it.request.clientId,
                                        operation = String(it.request.operation),
                                        operationSha256 = ApprovalProtocol.requestDigest(it.request),
                                    )
                                }
                            }
                        } catch (e: Exception) {
                            AppLog.log("poll ${setup.payload.serverId} failed: ${e.message}")
                            emptyList()
                        }
                    }
                }.awaitAll().flatten()
            }
        }

        notify(requests)
        pendingCount.value = requests.size
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
                .setContentText("${item.setup.payload.serverId} • ${item.clientId}")
                .setStyle(NotificationCompat.BigTextStyle()
                    .bigText("${item.setup.payload.serverId}\n${item.clientId}\n${item.requestId}"))
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
        notificationId(item.setup.payload.serverId + ":" + item.requestId)

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

        /** Live pending-request count for the home screen indicator (item 9.2). */
        val pendingCount = MutableStateFlow(0)

        fun start(context: Context) {
            context.startForegroundService(Intent(context, ApproverPollService::class.java))
        }

        fun stop(context: Context) {
            pendingCount.value = 0
            context.startService(Intent(context, ApproverPollService::class.java).setAction(ACTION_STOP))
        }
    }
}
