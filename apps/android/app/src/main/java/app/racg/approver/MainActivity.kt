package app.racg.approver

import android.Manifest
import android.os.Build
import android.os.Bundle
import android.content.Context
import android.content.pm.PackageManager
import androidx.activity.compose.setContent
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.app.ActivityCompat
import kotlinx.coroutines.launch
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URI
import java.time.Instant
import java.util.Base64
import java.security.SecureRandom
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters

private enum class Screen {
    Home,
    ScanSetup,
    Approvals,
    RequestDetail,
    Raw,
    History,
    Servers,
    TransferQr,
    Logs,
    Admin,
}

class MainActivity : FragmentActivity() {
    private val permissionCallbacks = mutableMapOf<Int, (Boolean) -> Unit>()
    private var nextPermissionCode = 7001

    /** Direct permission request with a 16-bit-safe request code: the
     * rememberLauncherForActivityResult generator produced request codes
     * beyond the lower 16 bits and crashed on this device. */
    fun requestPermission(permission: String, onResult: (Boolean) -> Unit) {
        val code = nextPermissionCode++
        permissionCallbacks[code] = onResult
        ActivityCompat.requestPermissions(this, arrayOf(permission), code)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        permissionCallbacks.remove(requestCode)?.invoke(
            grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED,
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AppLog.init(filesDir)
        AppLog.installCrashHandler()
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AppContent()
                }
            }
        }
    }
}

@Composable
private fun AppContent() {
    val context = LocalContext.current
    val store = remember { DataStoreApproverStore(context) }
    val scope = rememberCoroutineScope()
    var screen by remember { mutableStateOf(Screen.Home) }
    var setups by remember { mutableStateOf<List<StoredSetup>>(emptyList()) }
    var status by remember { mutableStateOf<String?>(null) }
    var transferQr by remember { mutableStateOf<String?>(null) }
    var transferServerId by remember { mutableStateOf<String?>(null) }
    var selectedRequest by remember { mutableStateOf<PendingRequestItem?>(null) }
    val pendingCount by ApproverPollService.pendingCount.collectAsState()

    fun startWatching() {
        val granted = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
        if (granted || Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            ApproverPollService.start(context)
            status = "Background watching started"
        } else {
            val act = context as? MainActivity
            if (act == null) {
                status = "Notification permission is unavailable"
            } else {
                act.requestPermission(Manifest.permission.POST_NOTIFICATIONS) { granted ->
                    if (granted) ApproverPollService.start(context) else status = "Notifications are disabled"
                }
            }
        }
    }

    LaunchedEffect(store) {
        setups = store.loadAll()
    }

    // Auto-start the watcher (item 9.1): with at least one configured server
    // the foreground service comes up on every app launch without a button.
    LaunchedEffect(setups) {
        if (setups.isNotEmpty()) startWatching()
    }

    // System back navigates in-app (item 10): every screen pops to its
    // parent instead of finishing the activity.
    BackHandler(enabled = screen != Screen.Home) {
        screen = when (screen) {
            Screen.Raw -> Screen.RequestDetail
            Screen.RequestDetail -> Screen.Approvals
            else -> Screen.Home
        }
    }

    fun transferServer(target: StoredSetup) {
        val activity = context as? FragmentActivity
        if (activity == null) {
            status = "Approver key authentication is unavailable"
            return
        }
        requestDeviceAuthentication(activity) {
            scope.launch {
                try {
                    val qr = withContext(Dispatchers.IO) {
                        val token = ByteArray(32).also { SecureRandom().nextBytes(it) }
                        val suffix = ByteArray(6).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
                        val newDeviceId = target.payload.approverId + "-transfer-" + suffix
                        val grant = ApprovalProtocol.newDeviceTransferGrant(
                            serverId = target.payload.serverId,
                            currentDeviceId = target.payload.approverId,
                            keyType = target.approvalKeyMaterial.keyType,
                            newDeviceId = newDeviceId,
                            token = token,
                            now = Instant.now(),
                        )
                        val signedGrant = ApprovalProtocol.signDeviceTransferGrant(
                            grant,
                            DeviceKeyManager.approvalSigner(target.approvalKeyMaterial.publicKey),
                        )
                        val uri = URI(target.payload.endpoint)
                        BrokerClient(uri.host, uri.port).createTransfer(signedGrant)
                        org.json.JSONObject().apply {
                            put("v", 3)
                            put("kind", SetupQrParser.KIND)
                            put("server_id", target.payload.serverId)
                            put("server_public_key", java.util.Base64.getEncoder().encodeToString(target.payload.serverPublicKey))
                            put("endpoint", target.payload.endpoint)
                            put("new_device_id", newDeviceId)
                            put("grant_challenge", java.util.Base64.getEncoder().encodeToString(grant.challenge))
                            put("transfer_token", java.util.Base64.getEncoder().encodeToString(token))
                        }.toString()
                    }
                    transferQr = qr
                    transferServerId = target.payload.serverId
                    screen = Screen.TransferQr
                } catch (_: Exception) {
                    status = "Transfer could not be created"
                }
            }
        }
    }

    when (screen) {
        Screen.Home -> HomeScreen(
            setups = setups,
            status = status,
            pendingCount = pendingCount,
            onShowApprovals = { screen = Screen.Approvals },
            onManageServers = { screen = Screen.Servers },
            onScanSetup = { screen = Screen.ScanSetup },
            onStartWatching = { startWatching() },
            onStopWatching = {
                ApproverPollService.stop(context)
                status = "Background watching stopped"
            },
            onOpenLogs = { screen = Screen.Logs },
            onOpenAdmin = { screen = Screen.Admin },
        )

        Screen.Logs -> DiagnosticsLogScreen(onBack = { screen = Screen.Home })

        Screen.Admin -> if (setups.isNotEmpty()) {
            AdminScreen(
                setups = setups,
                onBack = { screen = Screen.Home },
            )
        }

        Screen.ScanSetup -> BarcodeScannerView(
            onScanned = { raw ->
                scope.launch {
                    try {
                        AppLog.log("QR scanned (${raw.length} chars)")
                        val payload = SetupQrParser.parse(raw)
                        if (payload.transferToken != null && setups.any { it.payload.serverId == payload.serverId }) {
                            status = "That server is already configured"
                            screen = Screen.Home
                            return@launch
                        }
                        val newSetup = withContext(Dispatchers.IO) {
                            // Fresh install: regenerate keys so current key
                            // settings (auth window) apply. Existing servers
                            // share these keys, so only safe when none left.
                            if (setups.isEmpty()) {
                                DeviceKeyManager.deleteAll()
                                AppLog.log("device keys regenerated for fresh enrollment")
                            }
                            val keys = DeviceKeyManager.createOrLoadPair()
                            AppLog.log("device key pair ready")
                            StoredSetup(payload, keys.approval, keys.poll)
                        }
                        val activity = context as? FragmentActivity
                        if (activity == null) {
                            status = "Approver key authentication is unavailable"
                            return@launch
                        }
                        requestDeviceAuthentication(activity) {
                            scope.launch {
                                try {
                                    val completed = withContext(Dispatchers.IO) {
                                        val endpoint = URI(payload.endpoint)
                                        if (endpoint.scheme == "http" || endpoint.scheme == "https") {
                                            val token = payload.enrollmentToken
                                                ?: throw IllegalArgumentException("Enrollment token is missing")
                                            val client = PhoneClient(payload.endpoint)
                                            val challenge = client.challenge()
                                            val tokenSha256Hex = CompatProtocol.sha256Hex(token)
                                            val publicKeySha256Hex =
                                                CompatProtocol.sha256Hex(newSetup.approvalKeyMaterial.publicKey)
                                            val pollKeySha256Hex =
                                                CompatProtocol.sha256Hex(newSetup.pollKeyMaterial.publicKey)
                                            val message = CompatProtocol.pairingMessage(
                                                serverId = payload.serverId,
                                                deviceId = payload.approverId,
                                                publicKeySha256Hex = publicKeySha256Hex,
                                                pollKeySha256Hex = pollKeySha256Hex,
                                                challenge = challenge,
                                                tokenSha256Hex = tokenSha256Hex,
                                            )
                                            val signature = Base64.getEncoder().encodeToString(
                                                DeviceKeyManager.approvalSigner(newSetup.approvalKeyMaterial.publicKey)
                                                    .sign(message),
                                            )
                                            client.pair(
                                                deviceId = payload.approverId,
                                                publicKey = newSetup.approvalKeyMaterial.publicKey,
                                                pollPublicKey = newSetup.pollKeyMaterial.publicKey,
                                                tokenSha256Hex = tokenSha256Hex,
                                                challenge = challenge,
                                                signature = signature,
                                            )
                                        } else {
                                            payload.transferToken?.let { transferToken ->
                                                val serverKey = Ed25519PublicKeyParameters(payload.serverPublicKey, 0)
                                                val enrollment = ApprovalProtocol.newDeviceTransferEnrollment(
                                                    serverId = payload.serverId,
                                                    newDeviceId = payload.transferDeviceId
                                                        ?: throw IllegalArgumentException("Transfer identity is missing"),
                                                    signer = DeviceKeyManager.approvalSigner(newSetup.approvalKeyMaterial.publicKey),
                                                    pollKey = newSetup.pollKeyMaterial.publicKey,
                                                    grantChallenge = payload.transferGrantChallenge
                                                        ?: throw IllegalArgumentException("Transfer grant is missing"),
                                                    token = transferToken,
                                                    now = Instant.now(),
                                                )
                                                val signed = ApprovalProtocol.signDeviceTransferEnrollment(
                                                    enrollment,
                                                    DeviceKeyManager.approvalSigner(newSetup.approvalKeyMaterial.publicKey),
                                                )
                                                val uri = URI(payload.endpoint)
                                                val receipt = BrokerClient(uri.host, uri.port).enrollTransfer(
                                                    DeviceTransferSubmission(
                                                        enrollment = signed,
                                                        token = transferToken,
                                                    ),
                                                )
                                                ApprovalProtocol.verifyTransferReceipt(
                                                    signed,
                                                    receipt,
                                                    serverKey,
                                                    Instant.now(),
                                                )
                                            }
                                        }
                                        newSetup.copy(
                                            payload = payload.copy(
                                                enrollmentToken = null,
                                                transferToken = null,
                                                transferGrantChallenge = null,
                                            ),
                                        )
                                    }
                                    setups = store.save(completed)
                                    AppLog.log("setup saved for ${payload.serverId}")
                                    status = "Setup saved for ${payload.serverId}"
                                    screen = Screen.Home
                                } catch (e: Exception) {
                                    AppLog.error(e, "setup network step")
                                    status = "Setup failed: ${e.message}"
                                    screen = Screen.Home
                                }
                            }
                        }
                    } catch (e: Exception) {
                        AppLog.error(e, "setup scan step")
                        status = "Setup failed: ${e.message}"
                        screen = Screen.Home
                    }
                }
            },
            modifier = Modifier.fillMaxSize(),
        )

        Screen.Approvals -> if (setups.isNotEmpty()) {
            ApprovalsScreen(
                setups = setups,
                onBack = { screen = Screen.Home },
                onOpen = { request ->
                    selectedRequest = request
                    screen = Screen.RequestDetail
                },
                onOpenHistory = { screen = Screen.History },
            )
        }

        Screen.RequestDetail -> selectedRequest?.let { request ->
            RequestDetailsScreen(
                request = request,
                onBack = { screen = Screen.Approvals },
                onShowRaw = { screen = Screen.Raw },
            )
        } ?: run { screen = Screen.Approvals }

        Screen.Raw -> selectedRequest?.let { request ->
            RawRequestScreen(
                request = request,
                onBack = { screen = Screen.RequestDetail },
            )
        } ?: run { screen = Screen.Approvals }

        Screen.History -> if (setups.isNotEmpty()) {
            HistoryScreen(
                setups = setups,
                onBack = { screen = Screen.Approvals },
            )
        }

        Screen.Servers -> ServersScreen(
            setups = setups,
            statusText = status,
            onBack = { screen = Screen.Home },
            onAddServer = { screen = Screen.ScanSetup },
            onTransfer = { target -> transferServer(target) },
            onForget = { target ->
                scope.launch {
                    setups = store.forget(target.payload.serverId)
                    status = "Removed ${target.payload.serverId} from this phone"
                    if (setups.isEmpty()) {
                        ApproverPollService.stop(context)
                    }
                    screen = Screen.Servers
                }
            },
        )

        Screen.TransferQr -> transferQr?.let { qr ->
            transferServerId?.let { serverId ->
                TransferQrScreen(
                    serverId = serverId,
                    qr = qr,
                    onDone = { screen = Screen.Servers },
                )
            }
        }
    }
}

@Composable
private fun HomeScreen(
    setups: List<StoredSetup>,
    status: String?,
    pendingCount: Int,
    onShowApprovals: () -> Unit,
    onManageServers: () -> Unit,
    onScanSetup: () -> Unit,
    onStartWatching: () -> Unit,
    onStopWatching: () -> Unit,
    onOpenLogs: () -> Unit,
    onOpenAdmin: () -> Unit,
) {
    AppFrame(title = "RACG Approver", onBack = null) {
        Text(
            "v${BuildConfig.VERSION_NAME} build ${BuildConfig.SOURCE_REVISION.take(12)}",
            style = MaterialTheme.typography.bodySmall,
        )
        Text(
            when {
                setups.isNotEmpty() -> "${setups.size} server(s) configured"
                else -> "Set up this device with a QR code."
            },
            style = MaterialTheme.typography.bodyLarge,
        )
        status?.let {
            Text(it, style = MaterialTheme.typography.bodyMedium)
        }
        if (setups.isNotEmpty()) {
            if (pendingCount > 0) {
                AppButton(
                    text = "$pendingCount approval(s) waiting — review now",
                    onClick = onShowApprovals,
                )
            } else {
                AppButton(text = "Show approvals", onClick = onShowApprovals)
            }
        } else {
            AppButton(text = "Show approvals", onClick = onShowApprovals, enabled = false)
        }
        AppButton(text = "Manage servers", onClick = onManageServers, outlined = true, enabled = setups.isNotEmpty())
        AppButton(text = "Scan setup QR", onClick = onScanSetup, outlined = true)
        AppButton(text = "Start watching", onClick = onStartWatching, outlined = true)
        AppButton(text = "Stop watching", onClick = onStopWatching, outlined = true)
        AppButton(text = "Diagnostics log", onClick = onOpenLogs, outlined = true)
        if (setups.isNotEmpty()) {
            AppButton(text = "Manage sessions & devices", onClick = onOpenAdmin, outlined = true)
        }
        Text(
            "Reads (pending list) are signed with the device poll key and never ask for biometrics. Decisions require one biometric unlock per five minutes.",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

@Composable
private fun DiagnosticsLogScreen(onBack: () -> Unit) {
    var showAll by remember { mutableStateOf(false) }
    val clipboard = LocalClipboardManager.current
    val text = remember(showAll) { AppLog.text(if (showAll) null else 1.0) }

    AppFrame(title = "Diagnostics log", onBack = onBack) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(onClick = { showAll = !showAll }) {
                Text(if (showAll) "Last hour" else "Show all")
            }
            OutlinedButton(onClick = { clipboard.setText(AnnotatedString(text)) }) {
                Text("Copy")
            }
        }
        Text(
            if (showAll) "Full buffer incl. persisted history (newest last)" else "Last hour (newest last)",
            style = MaterialTheme.typography.titleSmall,
        )
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(text.lines()) { line ->
                Text(
                    line,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
    }
}
