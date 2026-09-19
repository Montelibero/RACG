package app.racg.approver

import android.Manifest
import android.os.Build
import android.os.Bundle
import android.content.Context
import android.content.pm.PackageManager
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.launch
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URI
import java.time.Instant
import java.security.SecureRandom
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters

private enum class Screen {
    Home,
    ScanSetup,
    Approvals,
    Servers,
    TransferQr,
}

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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
    val notificationPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) ApproverPollService.start(context) else status = "Notifications are disabled"
    }

    fun startWatching() {
        val granted = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
        if (granted || Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            ApproverPollService.start(context)
            status = "Background watching started"
        } else {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    LaunchedEffect(store) {
        setups = store.loadAll()
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
            onShowApprovals = { screen = Screen.Approvals },
            onManageServers = { screen = Screen.Servers },
            onScanSetup = { screen = Screen.ScanSetup },
            onStartWatching = { startWatching() },
            onStopWatching = {
                ApproverPollService.stop(context)
                status = "Background watching stopped"
            },
        )

        Screen.ScanSetup -> BarcodeScannerView(
            onScanned = { raw ->
                scope.launch {
                    try {
                        val payload = SetupQrParser.parse(raw)
                        if (payload.transferToken != null && setups.any { it.payload.serverId == payload.serverId }) {
                            status = "That server is already configured"
                            screen = Screen.Home
                            return@launch
                        }
                        val newSetup = withContext(Dispatchers.IO) {
                            val keys = DeviceKeyManager.createOrLoadPair()
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
                                        payload.transferToken?.let { transferToken ->
                                            val transferDeviceId = payload.transferDeviceId
                                                ?: throw IllegalArgumentException("Transfer identity is missing")
                                            val serverKey = Ed25519PublicKeyParameters(payload.serverPublicKey, 0)
                                            val enrollment = ApprovalProtocol.newDeviceTransferEnrollment(
                                                serverId = payload.serverId,
                                                newDeviceId = transferDeviceId,
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
                                        newSetup.copy(
                                            payload = payload.copy(
                                                transferToken = null,
                                                transferGrantChallenge = null,
                                            ),
                                        )
                                    }
                                    setups = store.save(completed)
                                    status = "Setup saved for ${payload.serverId}"
                                    screen = Screen.Home
                                } catch (_: Exception) {
                                    status = "Setup was not completed"
                                    screen = Screen.Home
                                }
                            }
                        }
                    } catch (_: Exception) {
                        status = "Setup was not completed"
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
            )
        }

        Screen.Servers -> ServersScreen(
            setups = setups,
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
    onShowApprovals: () -> Unit,
    onManageServers: () -> Unit,
    onScanSetup: () -> Unit,
    onStartWatching: () -> Unit,
    onStopWatching: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("RACG Approver", style = MaterialTheme.typography.headlineMedium)
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
        Button(
            onClick = onShowApprovals,
            enabled = setups.isNotEmpty(),
        ) {
            Text("Show approvals")
        }
        OutlinedButton(
            onClick = onManageServers,
            enabled = setups.isNotEmpty(),
        ) {
            Text("Manage servers")
        }
        OutlinedButton(
            onClick = onScanSetup,
            enabled = true,
        ) {
            Text("Scan setup QR")
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(onClick = onStartWatching) { Text("Start watching") }
            OutlinedButton(onClick = onStopWatching) { Text("Stop watching") }
        }
        Text(
            "Approvals use the signed broker protocol. Release packaging is not ready yet.",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Start,
        )
    }
}
