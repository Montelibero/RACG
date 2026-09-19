package app.racg.approver

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import kotlinx.coroutines.launch
import androidx.fragment.app.FragmentActivity

private enum class Screen {
    Home,
    ScanSetup,
    Approvals,
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
    var setup by remember { mutableStateOf<StoredSetup?>(null) }
    var status by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(store) {
        setup = store.load()
    }

    when (screen) {
        Screen.Home -> HomeScreen(
            setup = setup,
            status = status,
            onShowApprovals = { screen = Screen.Approvals },
            onScanSetup = { screen = Screen.ScanSetup },
        )

        Screen.ScanSetup -> BarcodeScannerView(
            onScanned = { raw ->
                scope.launch {
                    try {
                        val payload = SetupQrParser.parse(raw)
                        val material = setup?.keyMaterial ?: run {
                            val privateKey = DeviceKeyManager.generate()
                            DeviceKeyMaterial(
                                publicKey = DeviceKeyManager.publicKey(privateKey).encoded,
                                encryptedPrivateKey = DeviceKeyManager.protect(context, privateKey),
                            )
                        }
                        val newSetup = StoredSetup(payload, material)
                        store.save(newSetup)
                        setup = newSetup
                        status = "Connected to ${payload.serverId}"
                        screen = Screen.Home
                    } catch (_: Exception) {
                        status = "Setup QR was not valid"
                        screen = Screen.Home
                    }
                }
            },
            modifier = Modifier.fillMaxSize(),
        )

        Screen.Approvals -> setup?.let { configured ->
            ApprovalsScreen(
                setup = configured,
                onBack = { screen = Screen.Home },
            )
        }
    }
}

@Composable
private fun HomeScreen(
    setup: StoredSetup?,
    status: String?,
    onShowApprovals: () -> Unit,
    onScanSetup: () -> Unit,
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
                setup != null -> "Setup saved for ${setup.payload.serverId}"
                else -> "Set up this device with a QR code."
            },
            style = MaterialTheme.typography.bodyLarge,
        )
        status?.let {
            Text(it, style = MaterialTheme.typography.bodyMedium)
        }
        Button(
            onClick = onShowApprovals,
            enabled = setup != null,
        ) {
            Text("Show approvals")
        }
        OutlinedButton(
            onClick = onScanSetup,
            enabled = setup == null,
        ) {
            Text("Scan setup QR")
        }
        Text(
            "Approvals use the signed broker protocol. Release packaging is not ready yet.",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Start,
        )
    }
}
